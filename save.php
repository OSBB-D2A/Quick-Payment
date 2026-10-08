<?php
declare(strict_types=1);
/**
 * save.php — серверна частина сторінки оплати (усе в одному файлі).
 *
 *   GET  ?action=config          публічна частина config.php (реквізити для сторінки; БЕЗ пароля/хеша)
 *   POST ?action=setup           перше задання пароля (лише коли password_hash у config.php порожній)
 *   POST ?action=login           пароль → ключ (токен) для цього браузера
 *   POST ?action=whoami          перевірка ключа
 *   POST ?action=logout          видалити ключ цього браузера на сервері
 *   POST ?action=save            дописати скорочення в links.json (потрібен ключ, заголовок X-Key)
 *   POST ?action=reset_request   надіслати на пошту ФОП лист із посиланням для повного скидання ключа
 *   GET/POST ?action=reset       сторінка підтвердження скидання (за посиланням із листа)
 *   POST ?action=invoice         створити PDF-рахунок {sum, purpose, note?} → номер із реєстру, рядок у invoices.csv.php (потрібен ключ)
 *   POST ?action=invoices        стан реєстру рахунків: кількість, наступний номер, рахунки за останні 30 днів (потрібен ключ)
 *   POST ?action=invoice_get     повторно завантажити вже згенерований PDF-рахунок {number} з реєстру (потрібен ключ)
 *   POST ?action=invoices_csv    завантажити реєстр рахунків як CSV (потрібен ключ)
 *   POST ?action=visibility      {show_phone?, show_email?} → зберегти в config.php, чи показувати ці поля у звичайному режимі (потрібен ключ)
 *
 * Дані та секрети — у config.php (див. його). Вимоги: PHP 7.4+, права запису на config.php і links.json,
 * працююча функція mail() для листа «Анулювати ключ».
 */

const CONFIG_FILE        = __DIR__ . '/config.php';
const DATA_FILE          = __DIR__ . '/links.json';
const INVOICES_FILE      = __DIR__ . '/invoices.csv.php';   // реєстр рахунків; перший рядок ховає файл від браузера
const INVOICE_HEADER     = ['Дата генерації', 'Номер рахунку', 'Дата рахунку', 'Сума', 'Призначення', 'Примітка', 'Платник'];
const INVOICE_RECENT_DAYS = 30;    // «останні рахунки» у випадному списку — за скільки днів показувати
const INVOICE_RECENT_MAX  = 300;   // запобіжник розміру відповіді, якщо рахунків за ці 30 днів дуже багато
const NOTE_MAX_LEN        = 300;
const PAYER_MAX_LEN       = 140;   // як і призначення — стільки вміщується в один рядок реквізитів PDF без переносу проблем
const PAYERS_SUGGEST_MAX  = 200;   // скільки останніх унікальних платників пропонувати для автопідстановки
const CONFIG_GUARD       = "<?php http_response_code(404); exit; ?>\n";   // перший рядок config.php: у браузері файл «порожній»
const MAX_LINKS          = 5000;
const CODE_LEN           = 6;
const ALPHABET           = '23456789abcdefghjkmnpqrstuvwxyz';
const RESERVED           = ['admin', 'sum', 'amount', 'purpose', 'desc', 'p', 'c'];
const MIN_PASSWORD       = 8;
const MAX_PASSWORD       = 256;
const MAX_SESSIONS       = 20;
const LOGIN_MAX_FAILS    = 5;
const LOGIN_LOCK_SECONDS = 900;
const RESET_TTL          = 3600;      // посилання зі скидання діє 1 годину
const RESET_COOLDOWN     = 300;       // не частіше одного листа на 5 хвилин

// ───────────────────────── відповіді ─────────────────────────
function respond_json(int $status, array $data): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function fail(int $status, string $msg): void { respond_json($status, ['error' => $msg]); }

function respond_html(int $status, string $title, string $inner): void {
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('Referrer-Policy: no-referrer');          // токен у посиланні не має «витікати» через Referer
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    $t = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    echo '<!DOCTYPE html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<meta name="robots" content="noindex,nofollow"><title>' . $t . '</title><style>'
       . 'body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0e1a;color:#e8ecf7;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:20px}'
       . '.c{max-width:460px;background:#141a2d;border:1px solid rgba(255,255,255,.09);border-radius:22px;padding:28px}'
       . 'h1{font-size:20px;margin:0 0 12px}p{color:#8b96b3;margin:0 0 18px}'
       . 'button,a.b{display:inline-block;border:0;border-radius:12px;padding:12px 18px;font:600 15px system-ui,sans-serif;cursor:pointer;text-decoration:none;color:#fff;background:linear-gradient(135deg,#4f46e5,#7c3aed 60%,#06b6d4)}'
       . '</style></head><body><div class="c"><h1>' . $t . '</h1>' . $inner . '</div></body></html>';
    exit;
}

function input_json(): array {
    $body = file_get_contents('php://input', false, null, 0, 8192);
    $in = json_decode($body === false ? '' : $body, true);
    return is_array($in) ? $in : [];
}

// ───────────────────────── config.php ─────────────────────────
function cfg_parse(string $raw): ?array {
    $pos = strpos($raw, '?>');
    if ($pos === false) return null;
    $d = json_decode(trim(substr($raw, $pos + 2)), true);
    return is_array($d) ? $d : null;
}
function cfg_read(): array {
    $raw = @file_get_contents(CONFIG_FILE);
    if ($raw === false) fail(500, 'Не знайдено config.php');
    $cfg = cfg_parse($raw);
    if ($cfg === null) fail(500, 'config.php пошкоджений (невалідний JSON) — виправте його вручну');
    return $cfg;
}
/** Читає config.php, викликає $fn(array $cfg): ?array і записує результат (null = нічого не змінювати). Усе під блокуванням. */
function cfg_update(callable $fn): void {
    $fh = @fopen(CONFIG_FILE, 'c+');
    if (!$fh) fail(500, 'Немає доступу до config.php (потрібні права запису для веб-користувача)');
    if (!flock($fh, LOCK_EX)) { fclose($fh); fail(500, 'Не вдалося заблокувати config.php'); }
    $cfg = cfg_parse((string)stream_get_contents($fh));
    if ($cfg === null) { flock($fh, LOCK_UN); fclose($fh); fail(500, 'config.php пошкоджений (невалідний JSON) — виправте його вручну'); }
    $new = $fn($cfg);
    if (is_array($new)) {
        $new['sessions'] = (object)(is_array($new['sessions'] ?? null) ? $new['sessions'] : []);
        $json = json_encode($new, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) { flock($fh, LOCK_UN); fclose($fh); fail(500, 'Не вдалося сформувати config.php'); }
        rewind($fh); ftruncate($fh, 0);
        $ok = fwrite($fh, CONFIG_GUARD . $json . "\n") !== false;
        fflush($fh);
        if (!$ok) { flock($fh, LOCK_UN); fclose($fh); fail(500, 'Не вдалося записати config.php'); }
    }
    flock($fh, LOCK_UN); fclose($fh);
}
function public_config(array $c): array {
    $accounts = is_array($c['accounts'] ?? null) ? $c['accounts'] : [];
    $first = is_array($accounts[0] ?? null) ? $accounts[0] : (is_array($c['payee'] ?? null) ? $c['payee'] : []);
    return [
        'payee'           => $first,
        'accounts'        => $accounts,
        'default_account' => (string)($c['default_account'] ?? ($first['id'] ?? '')),
        'default_purpose' => (string)($c['default_purpose'] ?? 'Оплата за послуги'),
        'purposes'        => is_array($c['purposes'] ?? null) ? $c['purposes'] : [],
        'profile'         => is_array($c['profile'] ?? null) ? $c['profile'] : [],
        'page'            => is_array($c['page'] ?? null) ? $c['page'] : [],
        'password_set'    => (string)($c['password_hash'] ?? '') !== '',
    ];
}
function action_set_visibility(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $in = input_json();
    $accountId = trim((string)($in['account'] ?? ''));
    $allowed = ['show_phone', 'show_email'];
    $updates = [];
    foreach ($allowed as $k) if (array_key_exists($k, $in)) $updates[$k] = (bool)$in[$k];
    if (!$updates) fail(400, 'Немає що зберігати');
    $saved = [];
    cfg_update(function (array $cfg) use ($accountId, $updates, &$saved) {
        $accounts = is_array($cfg['accounts'] ?? null) ? $cfg['accounts'] : [];
        foreach ($accounts as &$a) {
            if (!is_array($a) || (string)($a['id'] ?? '') !== $accountId) continue;
            foreach ($updates as $k => $v) $a[$k] = $v;
            $saved = $a;
            break;
        }
        unset($a);
        if (!$saved) return null;
        $cfg['accounts'] = $accounts;
        return $cfg;
    });
    if (!$saved) fail(404, 'Рахунок не знайдено');
    respond_json(200, ['ok' => true, 'show_phone' => $saved['show_phone'] ?? true, 'show_email' => $saved['show_email'] ?? true]);
}

function admin_email(array $c): string {
    foreach ([$c['admin_email'] ?? '', is_array($c['payee'] ?? null) ? ($c['payee']['email'] ?? '') : ''] as $e)
        if (is_string($e) && filter_var($e, FILTER_VALIDATE_EMAIL)) return $e;
    return '';
}
function mask_email(string $e): string {
    $p = explode('@', $e, 2);
    return count($p) === 2 ? substr($p[0], 0, 1) . '***@' . $p[1] : '***';
}
function site_url(array $c): string {                      // адреса сторінки; беремо ЛИШЕ з config (Host-заголовку довіряти не можна)
    $u = trim((string)($c['site_url'] ?? ''));
    return preg_match('#^https?://[^\s/]+#i', $u) ? rtrim($u, '/') . '/' : '';
}

// ───────────────────────── паролі та ключі ─────────────────────────
function pw_prehash(string $pw): string { return base64_encode(hash('sha256', $pw, true)); }   // знімає обмеження bcrypt у 72 байти
function pw_valid(string $pw): bool { return strlen($pw) >= MIN_PASSWORD && strlen($pw) <= MAX_PASSWORD; }

function issue_token(array &$cfg): array {
    $now = time(); $days = max(1, (int)($cfg['session_days'] ?? 30));
    $sessions = is_array($cfg['sessions'] ?? null) ? $cfg['sessions'] : [];
    foreach ($sessions as $h => $s) if (!is_array($s) || (int)($s['exp'] ?? 0) <= $now) unset($sessions[$h]);
    uasort($sessions, function ($a, $b) { return ((int)($a['created'] ?? 0)) <=> ((int)($b['created'] ?? 0)); });
    while (count($sessions) >= MAX_SESSIONS) { reset($sessions); unset($sessions[key($sessions)]); }
    $token = bin2hex(random_bytes(32)); $exp = $now + $days * 86400;
    $sessions[hash('sha256', $token)] = ['created' => $now, 'exp' => $exp];
    $cfg['sessions'] = $sessions;
    return [$token, $exp];
}
function current_token(): string { return (string)($_SERVER['HTTP_X_KEY'] ?? ''); }
function session_ok(array $cfg, string $token): bool {
    if ($token === '' || strlen($token) > 200) return false;
    $s = is_array($cfg['sessions'] ?? null) ? ($cfg['sessions'][hash('sha256', $token)] ?? null) : null;
    return is_array($s) && (int)($s['exp'] ?? 0) > time();
}
function require_auth(array $cfg): void {
    if (!session_ok($cfg, current_token())) fail(403, 'Ключ недійсний або прострочений — введіть пароль знову');
}

// ───────────────────────── пошта ─────────────────────────
function send_mail(array $cfg, string $to, string $subject, string $body): bool {
    $host = parse_url(site_url($cfg), PHP_URL_HOST) ?: 'localhost';
    $from = (string)($cfg['mail_from'] ?? '');
    if (!filter_var($from, FILTER_VALIDATE_EMAIL)) $from = 'noreply@' . $host;
    $headers = ['From: ' . $from, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: 8bit', 'X-Mailer: payment-page'];
    return (bool)@mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, implode("\r\n", $headers), '-f' . $from);
}
function client_info(): string {
    return 'IP: ' . ($_SERVER['REMOTE_ADDR'] ?? '?') . "\nБраузер: " . substr((string)($_SERVER['HTTP_USER_AGENT'] ?? '?'), 0, 200);
}
function notify(array $cfg, string $subject, string $text): void {       // сповіщення власнику (без помилок, якщо пошта не працює)
    $to = admin_email($cfg);
    if ($to !== '') send_mail($cfg, $to, $subject, $text . "\n\n" . client_info() . "\nЧас: " . date('Y-m-d H:i:s') . "\n");
}

// ───────────────────────── дії ─────────────────────────
function action_config(): void {
    respond_json(200, public_config(cfg_read()));
}

function action_setup(): void {
    $pw = (string)(input_json()['password'] ?? '');
    if (!pw_valid($pw)) fail(400, 'Пароль: від ' . MIN_PASSWORD . ' символів');
    $res = ['status' => 500, 'error' => 'Внутрішня помилка']; $snapshot = [];
    cfg_update(function (array $cfg) use ($pw, &$res, &$snapshot) {
        if ((string)($cfg['password_hash'] ?? '') !== '') { $res = ['status' => 409, 'error' => 'Пароль уже задано. Щоб змінити його, скористайтеся «Анулювати ключ»']; return null; }
        $cfg['password_hash'] = password_hash(pw_prehash($pw), PASSWORD_DEFAULT);
        $cfg['auth'] = []; $cfg['reset'] = []; $cfg['sessions'] = [];
        [$token, $exp] = issue_token($cfg);
        $res = ['status' => 200, 'token' => $token, 'expires' => $exp]; $snapshot = $cfg;
        return $cfg;
    });
    if ($res['status'] === 200) notify($snapshot, 'Задано пароль автозбереження', "На сторінці оплати задано пароль автозбереження.\nЯкщо це були не ви — натисніть у режимі адміністратора «Анулювати ключ».");
    respond_json((int)$res['status'], array_diff_key($res, ['status' => 1]));
}

function action_login(): void {
    $pw = (string)(input_json()['password'] ?? '');
    $res = ['status' => 500, 'error' => 'Внутрішня помилка'];
    if (strlen($pw) > MAX_PASSWORD) fail(403, 'Невірний пароль');
    cfg_update(function (array $cfg) use ($pw, &$res) {
        $hash = (string)($cfg['password_hash'] ?? '');
        if ($hash === '') { $res = ['status' => 409, 'error' => 'Пароль ще не задано']; return null; }
        $now = time(); $auth = is_array($cfg['auth'] ?? null) ? $cfg['auth'] : [];
        if ((int)($auth['locked_until'] ?? 0) > $now) {
            $res = ['status' => 429, 'error' => 'Забагато невдалих спроб. Спробуйте через ' . (int)ceil(((int)$auth['locked_until'] - $now) / 60) . ' хв']; return null;
        }
        if ($pw !== '' && password_verify(pw_prehash($pw), $hash)) {
            [$token, $exp] = issue_token($cfg);
            $cfg['auth'] = ['fails' => 0, 'locked_until' => 0];
            $res = ['status' => 200, 'token' => $token, 'expires' => $exp];
        } else {
            $fails = (int)($auth['fails'] ?? 0) + 1; $lock = 0;
            if ($fails >= LOGIN_MAX_FAILS) { $fails = 0; $lock = $now + LOGIN_LOCK_SECONDS; }
            $cfg['auth'] = ['fails' => $fails, 'locked_until' => $lock];
            $res = ['status' => 403, 'error' => 'Невірний пароль', 'slow' => true];
        }
        return $cfg;
    });
    if (!empty($res['slow'])) usleep(600000);              // гальмуємо перебір
    respond_json((int)$res['status'], array_diff_key($res, ['status' => 1, 'slow' => 1]));
}

function action_whoami(): void {
    $cfg = cfg_read(); require_auth($cfg);
    respond_json(200, ['ok' => true]);
}

function action_logout(): void {
    $token = current_token();
    if ($token !== '') cfg_update(function (array $cfg) use ($token) {
        $h = hash('sha256', $token);
        if (!is_array($cfg['sessions'] ?? null) || !isset($cfg['sessions'][$h])) return null;
        unset($cfg['sessions'][$h]); return $cfg;
    });
    respond_json(200, ['ok' => true]);
}

function action_reset_request(): void {
    $res = ['status' => 500, 'error' => 'Внутрішня помилка']; $cfgSnap = [];
    cfg_update(function (array $cfg) use (&$res, &$cfgSnap) {
        if ((string)($cfg['password_hash'] ?? '') === '') { $res = ['status' => 409, 'error' => 'Пароль ще не задано — скидати нічого']; return null; }
        if (site_url($cfg) === '') { $res = ['status' => 500, 'error' => 'У config.php не задано site_url — лист не можна сформувати']; return null; }
        $to = admin_email($cfg);
        if ($to === '') { $res = ['status' => 500, 'error' => 'У config.php немає адреси пошти (admin_email або payee.email)']; return null; }
        $now = time(); $r = is_array($cfg['reset'] ?? null) ? $cfg['reset'] : [];
        $wait = (int)($r['last_request'] ?? 0) + RESET_COOLDOWN - $now;
        if ($wait > 0) { $res = ['status' => 429, 'error' => 'Лист уже надсилали. Спробуйте через ' . (int)ceil($wait / 60) . ' хв']; return null; }
        $token = bin2hex(random_bytes(32));
        $cfg['reset'] = ['token_hash' => hash('sha256', $token), 'expires' => $now + RESET_TTL, 'last_request' => $now];
        $cfgSnap = $cfg;
        $res = ['status' => 200, 'token' => $token, 'to' => $to];
        return $cfg;
    });
    if ($res['status'] !== 200) fail((int)$res['status'], (string)$res['error']);
    $link = site_url($cfgSnap) . basename(__FILE__) . '?action=reset&token=' . $res['token'];
    $body = "Хтось (можливо, ви) натиснув «Анулювати ключ» на сторінці оплати.\n\n"
          . "Щоб повністю скинути ключ автозбереження (пароль буде видалено, усі браузери — розлогінено), відкрийте посилання та підтвердіть:\n$link\n\n"
          . "Посилання діє " . (int)(RESET_TTL / 60) . " хв і спрацьовує один раз.\n"
          . "Якщо це були не ви — просто проігноруйте лист: нічого не зміниться.\n\n" . client_info() . "\n";
    if (!send_mail($cfgSnap, $res['to'], 'Скидання ключа автозбереження', $body)) {
        cfg_update(function (array $cfg) { $cfg['reset'] = ['last_request' => 0]; return $cfg; });      // дозволяємо повторити
        fail(500, 'Не вдалося надіслати лист (перевірте налаштування пошти на сервері)');
    }
    respond_json(200, ['ok' => true, 'to' => mask_email($res['to']), 'ttl_minutes' => (int)(RESET_TTL / 60)]);
}

function reset_token_valid(array $cfg, string $token): bool {
    $r = is_array($cfg['reset'] ?? null) ? $cfg['reset'] : [];
    $h = (string)($r['token_hash'] ?? '');
    return preg_match('/^[0-9a-f]{64}$/', $token) === 1 && $h !== '' && (int)($r['expires'] ?? 0) > time() && hash_equals($h, hash('sha256', $token));
}

function action_reset_page(): void {
    $token = (string)($_GET['token'] ?? '');
    if (!reset_token_valid(cfg_read(), $token)) {
        respond_html(400, 'Посилання недійсне', '<p>Посилання застаріло або вже використане. Натисніть «Анулювати ключ» на сторінці ще раз.</p>');
    }
    respond_html(200, 'Скинути ключ автозбереження?',
        '<p>Пароль буде видалено, усі браузери розлогінено. Після цього відкрийте сторінку в режимі адміністратора й задайте новий пароль.</p>'
      . '<form method="post" action="?action=reset"><input type="hidden" name="token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">'
      . '<button type="submit">Так, скинути ключ</button></form>');
}

function action_reset_confirm(): void {
    $token = (string)($_POST['token'] ?? '');
    $ok = false; $snap = [];
    cfg_update(function (array $cfg) use ($token, &$ok, &$snap) {
        if (!reset_token_valid($cfg, $token)) return null;
        $cfg['password_hash'] = ''; $cfg['sessions'] = []; $cfg['auth'] = []; $cfg['reset'] = ['last_request' => 0];
        $ok = true; $snap = $cfg; return $cfg;
    });
    if (!$ok) respond_html(400, 'Посилання недійсне', '<p>Посилання застаріло або вже використане.</p>');
    notify($snap, 'Ключ автозбереження скинуто', "Ключ автозбереження повністю скинуто: пароль видалено, усі браузери розлогінено.\nЗадайте новий пароль у режимі адміністратора сторінки.");
    $site = site_url($snap);
    respond_html(200, 'Ключ скинуто', '<p>Пароль видалено, усі браузери розлогінено. Відкрийте сторінку в режимі адміністратора й задайте новий пароль.</p>'
        . ($site !== '' ? '<a class="b" href="' . htmlspecialchars($site . '?admin', ENT_QUOTES, 'UTF-8') . '">Відкрити сторінку</a>' : ''));
}

// ───────────────────────── збереження скорочення ─────────────────────────
function normalize_purpose(string $s): string {
    $s = preg_replace('/[\x00-\x1F\x7F\x{2028}\x{2029}]+/u', ' ', $s);
    $s = preg_replace('/\s+/u', ' ', (string)$s);
    $s = trim((string)$s);
    if (preg_match('/^.{0,140}/us', $s, $m)) $s = $m[0];      // не більше 140 символів (ліміт стандарту НБУ)
    return trim($s);
}
function normalize_note(string $s): string {
    $s = preg_replace('/[\x00-\x1F\x7F\x{2028}\x{2029}]+/u', ' ', $s);
    $s = trim((string)preg_replace('/\s+/u', ' ', (string)$s));
    return mb_substr($s, 0, NOTE_MAX_LEN, 'UTF-8');
}
function normalize_payer(string $s): string {
    $s = preg_replace('/[\x00-\x1F\x7F\x{2028}\x{2029}]+/u', ' ', $s);
    $s = trim((string)preg_replace('/\s+/u', ' ', (string)$s));
    return mb_substr($s, 0, PAYER_MAX_LEN, 'UTF-8');
}
function gen_code(array $links): string {
    for ($i = 0; $i < 50; $i++) {
        $s = '';
        for ($j = 0; $j < CODE_LEN; $j++) $s .= ALPHABET[random_int(0, strlen(ALPHABET) - 1)];
        if (!isset($links[$s])) return $s;
    }
    fail(500, 'Не вдалося підібрати вільний код');
}

function action_save(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $in = input_json();
    $sum = isset($in['sum']) ? trim((string)$in['sum']) : '';
    if ($sum !== '' && (!preg_match('/^\d{1,9}(\.\d{2})?$/', $sum) || (float)$sum <= 0)) fail(400, 'Некоректна сума');

    $account = trim((string)($in['account'] ?? ''));
    $accounts = is_array($cfg['accounts'] ?? null) ? $cfg['accounts'] : [];
    $accountData = null;
    foreach ($accounts as $a) if (is_array($a) && (string)($a['id'] ?? '') === $account) { $accountData = $a; break; }
    if ($accountData === null && isset($accounts[0]) && is_array($accounts[0])) { $accountData = $accounts[0]; $account = (string)($accountData['id'] ?? ''); }
    if ($account === '' || !is_array($accountData)) fail(400, 'Не вказано коректний рахунок');

    $rawPurpose = (string)($in['purpose'] ?? '');
    if (!preg_match('//u', $rawPurpose)) fail(400, 'Призначення має бути в UTF-8');
    $purpose = normalize_purpose($rawPurpose);
    if ($purpose === '') fail(400, 'Порожнє призначення');

    $code = (string)($in['code'] ?? '');
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]{2,31}$/', $code) || in_array(strtolower($code), RESERVED, true)) $code = '';

    $fh = @fopen(DATA_FILE, 'c+');
    if (!$fh) fail(500, 'Немає доступу до links.json (перевірте права запису)');
    if (!flock($fh, LOCK_EX)) { fclose($fh); fail(500, 'Не вдалося заблокувати links.json'); }
    $raw = stream_get_contents($fh);
    $data = trim((string)$raw) === '' ? [] : json_decode((string)$raw, true);
    if (!is_array($data)) { flock($fh, LOCK_UN); fclose($fh); fail(500, 'links.json пошкоджений — виправте його вручну'); }
    $links = (isset($data['links']) && is_array($data['links'])) ? $data['links'] : [];

    foreach ($links as $c => $e) {
        if (!is_array($e)) continue;
        $es = isset($e['sum']) ? trim((string)$e['sum']) : '';
        $ep = normalize_purpose((string)($e['purpose'] ?? ''));
        $ea = (string)($e['account'] ?? ($cfg['default_account'] ?? ''));
        if ($ea === $account && $es === $sum && $ep === $purpose) {
            flock($fh, LOCK_UN); fclose($fh);
            respond_json(200, ['code' => (string)$c, 'created' => false]);
        }
    }
    if (count($links) >= MAX_LINKS) { flock($fh, LOCK_UN); fclose($fh); fail(507, 'Досягнуто ліміт записів'); }
    if ($code === '' || isset($links[$code])) $code = gen_code($links);
    $links[$code] = $sum !== '' ? ['account' => $account, 'sum' => $sum, 'purpose' => $purpose] : ['account' => $account, 'purpose' => $purpose];
    $data['links'] = (object)$links;

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) { flock($fh, LOCK_UN); fclose($fh); fail(500, 'Не вдалося сформувати JSON'); }
    @copy(DATA_FILE, DATA_FILE . '.bak');
    rewind($fh); ftruncate($fh, 0);
    $ok = fwrite($fh, $json . "\n") !== false;
    fflush($fh); flock($fh, LOCK_UN); fclose($fh);
    if (!$ok) fail(500, 'Не вдалося записати links.json');
    respond_json(200, ['code' => (string)$code, 'created' => true]);
}

// ───────────────────────── рахунки (PDF) і реєстр (CSV) ─────────────────────────
function csv_field(string $s): string {
    if ($s !== '' && strpbrk($s[0], "=+-@\t\r") !== false) $s = "'" . $s;      // захист від формул в Excel
    return preg_match('/[;"\r\n]/', $s) ? '"' . str_replace('"', '""', $s) . '"' : $s;
}
function csv_line(array $f): string { return implode(';', array_map('csv_field', array_map('strval', $f))); }

function registry_rows(string $raw): array {
    $pos = strpos($raw, '?>');
    $body = $pos === false ? $raw : substr($raw, $pos + 2);
    $rows = [];
    foreach (preg_split('/\r\n|\n|\r/', $body) as $line) {
        if (trim($line) === '') continue;
        $f = str_getcsv($line, ';', '"', '');
        if (count($f) < 5 || !ctype_digit(trim((string)$f[1]))) continue;      // заголовок і сміття пропускаємо
        $rows[] = ['generated' => (string)$f[0], 'number' => (int)$f[1], 'date' => (string)$f[2], 'amount' => (string)$f[3], 'purpose' => (string)$f[4], 'note' => isset($f[5]) ? (string)$f[5] : '', 'payer' => isset($f[6]) ? (string)$f[6] : ''];
    }
    return $rows;
}
function registry_next(array $rows, array $cfg): int {                        // наступний номер = найбільший у файлі + 1
    $max = 0;
    foreach ($rows as $r) $max = max($max, $r['number']);
    $start = max(1, (int)(is_array($cfg['invoice'] ?? null) ? ($cfg['invoice']['number_start'] ?? 1) : 1));
    return $max > 0 ? $max + 1 : $start;
}
function registry_read(): string {
    $fh = @fopen(INVOICES_FILE, 'r');
    if (!$fh) return '';
    flock($fh, LOCK_SH); $raw = (string)stream_get_contents($fh); flock($fh, LOCK_UN); fclose($fh);
    return $raw;
}
function cfg_timezone(array $cfg): DateTimeZone {
    try { return new DateTimeZone((string)($cfg['timezone'] ?? 'Europe/Kyiv')); } catch (Exception $e) { return new DateTimeZone('UTC'); }
}

function action_invoice(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $in = input_json();
    $sum = isset($in['sum']) ? trim((string)$in['sum']) : '';
    if (!preg_match('/^\d{1,9}(\.\d{1,2})?$/', $sum) || (float)$sum <= 0) fail(400, 'Для рахунку потрібна сума більша за нуль');
    $parts = explode('.', $sum, 2);
    $amount = (string)((int)$parts[0]) . '.' . str_pad($parts[1] ?? '', 2, '0');
    $rawPurpose = (string)($in['purpose'] ?? '');
    if (!preg_match('//u', $rawPurpose)) fail(400, 'Призначення має бути в UTF-8');
    $purpose = normalize_purpose($rawPurpose);
    if ($purpose === '') fail(400, 'Порожнє призначення');
    $note = normalize_note((string)($in['note'] ?? ''));
    $payer = normalize_payer((string)($in['payer'] ?? ''));
    if (!is_file(__DIR__ . '/invoice.php')) fail(500, 'Не знайдено invoice.php поруч зі save.php');
    require_once __DIR__ . '/invoice.php';
    $now = new DateTimeImmutable('now', cfg_timezone($cfg));

    $fh = @fopen(INVOICES_FILE, 'c+');
    if (!$fh) fail(500, 'Немає доступу до invoices.csv.php (потрібні права запису на файл або теку)');
    if (!flock($fh, LOCK_EX)) { fclose($fh); fail(500, 'Не вдалося заблокувати реєстр рахунків'); }
    $raw = (string)stream_get_contents($fh);
    $number = registry_next(registry_rows($raw), $cfg);
    try {                                                   // спершу PDF: якщо він не вдався — номер не «витрачається»
        $pdf = invoice_build_pdf($cfg, ['number' => $number, 'date' => $now, 'amount' => $amount, 'purpose' => $purpose, 'payer' => $payer]);
    } catch (Throwable $e) {
        flock($fh, LOCK_UN); fclose($fh); fail(500, 'Не вдалося створити PDF: ' . $e->getMessage());
    }
    $purposeFull = inv_qr_purpose($purpose, $number, $now);   // те саме призначення, що показане в PDF і закодоване в QR
    $line = csv_line([$now->format('Y-m-d H:i:s'), (string)$number, $now->format('Y-m-d'), $amount, $purposeFull, $note, $payer]) . "\n";
    if (trim($raw) === '') { rewind($fh); ftruncate($fh, 0); $ok = fwrite($fh, CONFIG_GUARD . csv_line(INVOICE_HEADER) . "\n" . $line) !== false; }
    else {
        // якщо файл лишився від версії без колонки «Примітка» і/або «Платник» — оновлюємо лише рядок заголовка, самі дані не чіпаємо
        $bodyStart = strpos($raw, '?>'); $bodyStart = $bodyStart === false ? 0 : $bodyStart + 2;
        if (substr($raw, $bodyStart, 2) === "\r\n") $bodyStart += 2;           // guard-рядок закінчується власним переносом — пропускаємо його
        elseif (($raw[$bodyStart] ?? '') === "\n") $bodyStart += 1;
        $headerEnd = strpos($raw, "\n", $bodyStart);
        $firstLine = rtrim($headerEnd === false ? substr($raw, $bodyStart) : substr($raw, $bodyStart, $headerEnd - $bodyStart), "\r");
        $oldHeaders = [
            csv_line(['Дата генерації', 'Номер рахунку', 'Дата рахунку', 'Сума', 'Призначення']),
            csv_line(['Дата генерації', 'Номер рахунку', 'Дата рахунку', 'Сума', 'Призначення', 'Примітка']),
        ];
        if (in_array($firstLine, $oldHeaders, true) && $headerEnd !== false) {
            $guard = $bodyStart > 0 ? substr($raw, 0, $bodyStart) : CONFIG_GUARD;
            $rest = substr($raw, $headerEnd + 1);
            rewind($fh); ftruncate($fh, 0);
            $ok = fwrite($fh, $guard . csv_line(INVOICE_HEADER) . "\n" . $rest . (($rest === '' || substr($rest, -1) === "\n") ? '' : "\n") . $line) !== false;
        } else {
            fseek($fh, 0, SEEK_END); $ok = fwrite($fh, (substr($raw, -1) === "\n" ? '' : "\n") . $line) !== false;
        }
    }
    fflush($fh); flock($fh, LOCK_UN); fclose($fh);
    if (!$ok) fail(500, 'Не вдалося записати реєстр рахунків');

    http_response_code(200);
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="Rakhunok-' . $number . '-' . $now->format('Y-m-d') . '.pdf"');
    header('Content-Length: ' . strlen($pdf));
    header('Cache-Control: no-store');
    header('X-Invoice-Number: ' . $number);
    echo $pdf;
    exit;
}

function action_invoices(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $rows = registry_rows(registry_read());
    $since = (new DateTimeImmutable('now', cfg_timezone($cfg)))->modify('-' . INVOICE_RECENT_DAYS . ' days');
    $recent = []; $payers = []; $seenPayers = [];
    foreach (array_reverse($rows) as $r) {                      // найновіші перші
        if ($r['payer'] !== '' && !isset($seenPayers[$r['payer']])) {   // унікальні платники з усього реєстру, не лише за 30 днів
            $seenPayers[$r['payer']] = true;
            if (count($payers) < PAYERS_SUGGEST_MAX) $payers[] = $r['payer'];
        }
        $gen = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $r['generated'], cfg_timezone($cfg));
        if ($gen !== false && $gen < $since) continue;
        if (count($recent) < INVOICE_RECENT_MAX) $recent[] = ['number' => $r['number'], 'date' => $r['date'], 'amount' => $r['amount'], 'purpose' => $r['purpose'], 'note' => $r['note'], 'payer' => $r['payer']];
    }
    respond_json(200, ['count' => count($rows), 'next' => registry_next($rows, $cfg), 'recentDays' => INVOICE_RECENT_DAYS, 'recent' => $recent, 'payers' => $payers]);
}

function action_invoice_get(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $input = input_json();
    $number = (int)($input['number'] ?? 0);
    if ($number <= 0) fail(400, 'Не вказано номер рахунку');
    $found = null;
    foreach (registry_rows(registry_read()) as $r) if ($r['number'] === $number) $found = $r;   // остання поява — найактуальніша
    if ($found === null) fail(404, 'Рахунок № ' . $number . ' не знайдено в реєстрі');
    $gen = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $found['generated'], cfg_timezone($cfg));
    if ($gen === false) fail(500, 'Пошкоджений запис реєстру: не вдалося розпізнати дату генерації');
    if (!is_file(__DIR__ . '/invoice.php')) fail(500, 'Не знайдено invoice.php поруч зі save.php');
    require_once __DIR__ . '/invoice.php';
    try {
        $pdf = invoice_build_pdf($cfg, ['number' => $number, 'date' => $gen, 'amount' => $found['amount'], 'purpose' => $found['purpose'], 'payer' => $found['payer']]);
    } catch (Throwable $e) {
        fail(500, 'Не вдалося відтворити PDF: ' . $e->getMessage());
    }
    http_response_code(200);
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="Rakhunok-' . $number . '-' . $gen->format('Y-m-d') . '.pdf"');
    header('Content-Length: ' . strlen($pdf));
    header('Cache-Control: no-store');
    header('X-Invoice-Number: ' . $number);
    echo $pdf;
    exit;
}

function action_invoices_csv(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $out = "\xEF\xBB\xBF" . csv_line(INVOICE_HEADER) . "\r\n";                   // BOM — щоб Excel правильно читав кирилицю
    foreach (registry_rows(registry_read()) as $r) $out .= csv_line([$r['generated'], (string)$r['number'], $r['date'], $r['amount'], $r['purpose'], $r['note'], $r['payer']]) . "\r\n";
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="invoices.csv"');
    header('Cache-Control: no-store');
    echo $out;
    exit;
}

// ───────────────────────── маршрутизація ─────────────────────────
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = (string)($_GET['action'] ?? ($method === 'POST' ? 'save' : ''));
$routes = [
    'config'        => ['GET',  'action_config'],
    'setup'         => ['POST', 'action_setup'],
    'login'         => ['POST', 'action_login'],
    'whoami'        => ['POST', 'action_whoami'],
    'logout'        => ['POST', 'action_logout'],
    'save'          => ['POST', 'action_save'],
    'reset_request' => ['POST', 'action_reset_request'],
    'invoice'       => ['POST', 'action_invoice'],
    'invoices'      => ['POST', 'action_invoices'],
    'invoice_get'   => ['POST', 'action_invoice_get'],
    'invoices_csv'  => ['POST', 'action_invoices_csv'],
    'visibility'    => ['POST', 'action_set_visibility'],
];
if ($action === 'reset') {
    if ($method === 'GET')  action_reset_page();
    if ($method === 'POST') action_reset_confirm();
}
if (!isset($routes[$action])) fail(404, 'Невідома дія');
if ($method !== $routes[$action][0]) { header('Allow: ' . $routes[$action][0]); fail(405, 'Метод не підтримується'); }
call_user_func($routes[$action][1]);
