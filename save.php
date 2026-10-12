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
 *   POST ?action=reset_request   надіслати на пошту ФОП лист із посиланням для повного скидання ключа
 *   GET/POST ?action=reset       сторінка підтвердження скидання (за посиланням із листа)
 *   POST ?action=visibility      {show_phone?, show_email?} → зберегти в config.php, чи показувати ці поля у звичайному режимі (потрібен ключ)
 *
 * Дані та секрети — у config.php (див. його). Вимоги: PHP 7.4+ та права запису на config.php,
 * працююча функція mail() для листа «Анулювати ключ».
 */

const CONFIG_FILE        = __DIR__ . '/config.php';
const CONFIG_GUARD       = "<?php http_response_code(404); exit; ?>\n";   // перший рядок config.php: у браузері файл «порожній»
const MIN_PASSWORD       = 8;
const MAX_PASSWORD       = 256;
const MAX_SESSIONS       = 20;
const LOGIN_MAX_FAILS    = 5;
const LOGIN_LOCK_SECONDS = 900;
const RESET_TTL          = 3600;      // посилання зі скидання діє 1 годину
const RESET_COOLDOWN     = 300;       // не частіше одного листа на 5 хвилин

// Оновлення коду з GitHub. Конфігурація та робочі дані ніколи не перезаписуються.
const VERSION_FILE       = __DIR__ . '/VERSION';
const UPDATE_REPO_OWNER  = 'OSBB-D2A';
const UPDATE_REPO_NAME   = 'Quick-Payment';
const UPDATE_BRANCH      = 'main';
const UPDATE_CODE_FILES  = ['index.html', 'save.php', 'invoice.php', 'qrcode.php', 'config.example.php', 'apartments.json', 'README.md', 'VERSION', 'natural-green-bg.svg', 'profile-logo.svg', '.gitignore'];

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
        'version'         => local_version(),
    ];
}

// ───────────────────────── версія та оновлення ─────────────────────────
function local_version(): string {
    $v = @file_get_contents(VERSION_FILE);
    return $v === false ? '0.0.0' : trim($v);
}
function update_http_get(string $url, int $timeout = 12): ?string {
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'Quick-Payment-updater',
        ]);
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return ($body !== false && $status >= 200 && $status < 300) ? $body : null;
    }
    if ((string)ini_get('allow_url_fopen') === '1') {
        $ctx = stream_context_create(['http' => ['timeout' => $timeout, 'header' => "User-Agent: Quick-Payment-updater\r\n"]]);
        $body = @file_get_contents($url, false, $ctx);
        return $body === false ? null : $body;
    }
    return null;
}
function update_remove_tree(string $dir): void {
    if (!is_dir($dir)) return;
    foreach (scandir($dir) ?: [] as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . '/' . $item;
        is_dir($path) ? update_remove_tree($path) : @unlink($path);
    }
    @rmdir($dir);
}
function action_check_update(): void {
    $cfg = cfg_read(); require_auth($cfg);
    $local = local_version();
    $url = sprintf('https://raw.githubusercontent.com/%s/%s/%s/VERSION', UPDATE_REPO_OWNER, UPDATE_REPO_NAME, UPDATE_BRANCH);
    $remote = update_http_get($url, 10);

    // Якщо raw.githubusercontent.com недоступний з хостингу, пробуємо GitHub Contents API.
    if ($remote === null) {
        $apiUrl = sprintf('https://api.github.com/repos/%s/%s/contents/VERSION?ref=%s', UPDATE_REPO_OWNER, UPDATE_REPO_NAME, UPDATE_BRANCH);
        $metaRaw = update_http_get($apiUrl, 10);
        if ($metaRaw !== null) {
            $meta = json_decode($metaRaw, true);
            if (is_array($meta) && ($meta['encoding'] ?? '') === 'base64' && isset($meta['content'])) {
                $decoded = base64_decode((string)$meta['content'], true);
                if ($decoded !== false) $remote = $decoded;
            }
        }
    }
    if ($remote === null) respond_json(200, ['ok' => false, 'error' => 'Не вдалося прочитати VERSION з GitHub ні через raw.githubusercontent.com, ні через GitHub API. Перевірте вихідні HTTPS-запити сервера.', 'local' => $local]);
    $latest = trim($remote);
    if ($latest === '' || strlen($latest) > 40 || !preg_match('/^[\\w.\\-]+$/', $latest)) respond_json(200, ['ok' => false, 'error' => 'GitHub повернув некоректний номер версії.', 'local' => $local]);
    respond_json(200, ['ok' => true, 'local' => $local, 'latest' => $latest, 'updateAvailable' => version_compare($latest, $local, '>')]);
}
function action_update(): void {
    $cfg = cfg_read(); require_auth($cfg);
    if (!class_exists('ZipArchive')) fail(500, 'На сервері немає PHP-розширення ZipArchive. Оновлення одним натисканням недоступне.');
    $zipUrl = sprintf('https://codeload.github.com/%s/%s/zip/refs/heads/%s', UPDATE_REPO_OWNER, UPDATE_REPO_NAME, UPDATE_BRANCH);
    $zipData = update_http_get($zipUrl, 60);
    if ($zipData === null || strlen($zipData) < 1000) fail(502, 'Не вдалося завантажити архів оновлення з GitHub.');
    $tmpZip = tempnam(sys_get_temp_dir(), 'qpupd_');
    if ($tmpZip === false || file_put_contents($tmpZip, $zipData) === false) fail(500, 'Не вдалося зберегти тимчасовий архів.');
    $zip = new ZipArchive();
    if ($zip->open($tmpZip) !== true) { @unlink($tmpZip); fail(500, 'Архів оновлення пошкоджений.'); }
    $tmpDir = sys_get_temp_dir() . '/qpupd_' . bin2hex(random_bytes(6));
    if (!@mkdir($tmpDir, 0700, true)) { $zip->close(); @unlink($tmpZip); fail(500, 'Не вдалося створити тимчасову теку.'); }
    if (!$zip->extractTo($tmpDir)) { $zip->close(); @unlink($tmpZip); update_remove_tree($tmpDir); fail(500, 'Не вдалося розпакувати архів оновлення.'); }
    $zip->close(); @unlink($tmpZip);
    $entries = glob($tmpDir . '/*', GLOB_ONLYDIR);
    $srcDir = $entries[0] ?? null;
    if ($srcDir === null) { update_remove_tree($tmpDir); fail(500, 'Структура архіву неочікувана.'); }
    $copied = []; $errors = [];
    foreach (UPDATE_CODE_FILES as $name) {
        $src = $srcDir . '/' . $name;
        if (!is_file($src)) continue;
        if (@copy($src, __DIR__ . '/' . $name)) $copied[] = $name; else $errors[] = $name;
    }
    update_remove_tree($tmpDir);
    if (function_exists('opcache_reset')) @opcache_reset();
    if ($errors) fail(500, 'Оновлення виконано частково. Не вдалося записати: ' . implode(', ', $errors) . '. Перевірте права запису.');
    if (!$copied) fail(500, 'В архіві не знайдено файлів для оновлення.');
    // Старі короткі посилання більше не підтримуються — видаляємо їхні файли під час оновлення.
    @unlink(__DIR__ . '/links.json');
    @unlink(__DIR__ . '/links.json.bak');
    respond_json(200, ['ok' => true, 'version' => local_version(), 'files' => $copied]);
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
    $e = $c['admin_email'] ?? '';
    return is_string($e) && filter_var($e, FILTER_VALIDATE_EMAIL) ? $e : '';
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

// ───────────────────────── маршрутизація ─────────────────────────
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = (string)($_GET['action'] ?? ($method === 'POST' ? 'save' : ''));
$routes = [
    'config'        => ['GET',  'action_config'],
    'setup'         => ['POST', 'action_setup'],
    'login'         => ['POST', 'action_login'],
    'whoami'        => ['POST', 'action_whoami'],
    'logout'        => ['POST', 'action_logout'],
    'reset_request' => ['POST', 'action_reset_request'],
    'visibility'    => ['POST', 'action_set_visibility'],
    'check_update'  => ['POST', 'action_check_update'],
    'update'        => ['POST', 'action_update'],
];
if ($action === 'reset') {
    if ($method === 'GET')  action_reset_page();
    if ($method === 'POST') action_reset_confirm();
}
if (!isset($routes[$action])) fail(404, 'Невідома дія');
if ($method !== $routes[$action][0]) { header('Allow: ' . $routes[$action][0]); fail(405, 'Метод не підтримується'); }
call_user_func($routes[$action][1]);
