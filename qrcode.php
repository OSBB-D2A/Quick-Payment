<?php
declare(strict_types=1);
/**
 * qrcode.php — мінімальний QR-кодогенератор (Model 2, версії 1-15, байтовий режим, EC M/Q).
 * Без сторонніх залежностей. Маска завжди фіксована (0) — це лишається валідним QR-кодом
 * (вибір маски — це лише оптимізація контрастності, а не вимога стандарту), але спрощує
 * і прибирає цілий клас можливих помилок у розрахунку штрафних балів.
 *
 * Рівень корекції обмежений M/Q: постанова НБУ №97 від 19.08.2025 (чинна з 01.11.2025) забороняє
 * рівень L для платіжних QR форматів 002/003 з обов'язковим логотипом ₴ у центрі (qr_draw_logo()).
 *
 * Використання: [$matrix, $size] = qr_encode($bytes, $maxVersion = 15);
 * $matrix — квадратний масив size×size з true (темний модуль) / false (світлий).
 */

// ── Таблиця EC-блоків (версії 1-15, рівні M/Q): [count1,total1,data1[,count2,total2,data2]] ──
// Джерело даних: стандартна публічна таблиця QR (ISO/IEC 18004, Annex D; https://www.thonky.com/qr-code-tutorial/error-correction-table),
// звірено побітово зі значеннями з бібліотеки qrcode-generator (Kazuhiko Arase), яку використовує клієнтський JS на цій сторінці.
const QR_EC_TABLE = [
    1  => ['M' => [1, 26, 16],              'Q' => [1, 26, 13]],
    2  => ['M' => [1, 44, 28],              'Q' => [1, 44, 22]],
    3  => ['M' => [1, 70, 44],              'Q' => [2, 35, 17]],
    4  => ['M' => [2, 50, 32],              'Q' => [2, 50, 24]],
    5  => ['M' => [2, 67, 43],              'Q' => [2, 33, 15, 2, 34, 16]],
    6  => ['M' => [4, 43, 27],              'Q' => [4, 43, 19]],
    7  => ['M' => [4, 49, 31],              'Q' => [2, 32, 14, 4, 33, 15]],
    8  => ['M' => [2, 60, 38, 2, 61, 39],   'Q' => [4, 40, 18, 2, 41, 19]],
    9  => ['M' => [3, 58, 36, 2, 59, 37],   'Q' => [4, 36, 16, 4, 37, 17]],
    10 => ['M' => [4, 69, 43, 1, 70, 44],   'Q' => [6, 43, 19, 2, 44, 20]],
    11 => ['M' => [1, 80, 50, 4, 81, 51],   'Q' => [4, 50, 22, 4, 51, 23]],
    12 => ['M' => [6, 58, 36, 2, 59, 37],   'Q' => [4, 46, 20, 6, 47, 21]],
    13 => ['M' => [8, 59, 37, 1, 60, 38],   'Q' => [8, 44, 20, 4, 45, 21]],
    14 => ['M' => [4, 64, 40, 5, 65, 41],   'Q' => [11, 36, 16, 5, 37, 17]],
    15 => ['M' => [5, 65, 41, 5, 66, 42],   'Q' => [5, 54, 24, 7, 55, 25]],
];
const QR_ALIGN = [
    2 => [6, 18], 3 => [6, 22], 4 => [6, 26], 5 => [6, 30], 6 => [6, 34],
    7 => [6, 22, 38], 8 => [6, 24, 42], 9 => [6, 26, 46], 10 => [6, 28, 50],
    11 => [6, 30, 54], 12 => [6, 32, 58], 13 => [6, 34, 62], 14 => [6, 26, 46, 66], 15 => [6, 26, 48, 70],
];
const QR_EC_BITS = ['L' => 0b01, 'M' => 0b00, 'Q' => 0b11, 'H' => 0b10];
const QR_FORMAT_GENERATOR = 0x537;   // 10-бітний генераторний поліном формат-інформації
const QR_FORMAT_MASK = 0x5412;
const QR_VERSION_GENERATOR = 0x1F25; // 12-бітний генераторний поліном версійної інформації

// ── GF(256), поліном x^8+x^4+x^3+x^2+1 = 0x11D ──
function qr_gf_tables(): array {
    static $exp = null, $log = null;
    if ($exp !== null) return [$exp, $log];
    $exp = array_fill(0, 512, 0); $log = array_fill(0, 256, 0);
    $x = 1;
    for ($i = 0; $i < 255; $i++) {
        $exp[$i] = $x; $log[$x] = $i;
        $x <<= 1; if ($x & 0x100) $x ^= 0x11D;
    }
    for ($i = 255; $i < 512; $i++) $exp[$i] = $exp[$i - 255];
    return [$exp, $log];
}
function qr_gf_mul(int $a, int $b): int {
    if ($a === 0 || $b === 0) return 0;
    [$exp, $log] = qr_gf_tables();
    return $exp[$log[$a] + $log[$b]];
}
function qr_generator_poly(int $degree): array {                 // коефіцієнти від старшого до молодшого, старший завжди 1
    [$exp, $log] = qr_gf_tables();
    $poly = [1];
    for ($i = 0; $i < $degree; $i++) {
        $next = array_fill(0, count($poly) + 1, 0);
        for ($j = 0; $j < count($poly); $j++) {
            $next[$j] ^= qr_gf_mul($poly[$j], 1);
            $next[$j + 1] ^= qr_gf_mul($poly[$j], $exp[$i]);
        }
        $poly = $next;
    }
    return $poly;
}
function qr_rs_encode(array $data, int $ecCount): array {         // ділення поліномів у GF(256) — залишок є EC-кодовими словами
    $gen = qr_generator_poly($ecCount);
    $buf = array_merge($data, array_fill(0, $ecCount, 0));
    for ($i = 0; $i < count($data); $i++) {
        $coef = $buf[$i];
        if ($coef === 0) continue;
        for ($j = 0; $j < count($gen); $j++) $buf[$i + $j] ^= qr_gf_mul($gen[$j], $coef);
    }
    return array_slice($buf, count($data));
}

// ── Потік бітів ──
final class QrBits {
    private array $bits = [];
    public function put(int $value, int $length): void { for ($i = $length - 1; $i >= 0; $i--) $this->bits[] = ($value >> $i) & 1; }
    public function len(): int { return count($this->bits); }
    public function bits(): array { return $this->bits; }
}

function qr_pick_version(int $byteLen, int $maxVersion, string $level): ?int {
    for ($v = 1; $v <= $maxVersion; $v++) {
        $entry = QR_EC_TABLE[$v][$level] ?? null; if (!$entry) continue;
        $dataCodewords = $entry[0] * $entry[2] + (isset($entry[3]) ? $entry[3] * $entry[5] : 0);
        $countBits = $v <= 9 ? 8 : 16;
        $capacityBytes = intdiv($dataCodewords * 8 - 4 - $countBits, 8);
        if ($byteLen <= $capacityBytes) return $v;
    }
    return null;
}

/** @return array{0: array<int,array<int,bool>>, 1:int, 2:int, 3:string} [матриця, розмір, версія, рівень EC] */
function qr_encode(string $bytes, int $maxVersion = 15): array {
    $level = 'M'; $version = qr_pick_version(strlen($bytes), $maxVersion, 'M');
    if ($version === null) { $level = 'Q'; $version = qr_pick_version(strlen($bytes), $maxVersion, 'Q'); }
    if ($version === null) throw new RuntimeException('Дані завеликі для QR (версія > ' . $maxVersion . ')');

    $entry = QR_EC_TABLE[$version][$level];
    $blocks = []; // [[data...], ecCount]
    $groups = count($entry) === 3 ? [[$entry[0], $entry[1], $entry[2]]] : [[$entry[0], $entry[1], $entry[2]], [$entry[3], $entry[4], $entry[5]]];
    $totalDataCodewords = 0;
    foreach ($groups as $g) $totalDataCodewords += $g[0] * $g[2];

    // ── біти: режим(4) + довжина + байти + термінатор + вирівнювання + доповнення ──
    $bits = new QrBits();
    $bits->put(0b0100, 4);
    $bits->put(strlen($bytes), $version <= 9 ? 8 : 16);
    foreach (str_split($bytes) as $ch) $bits->put(ord($ch), 8);
    $totalBits = $totalDataCodewords * 8;
    $term = min(4, $totalBits - $bits->len()); if ($term > 0) $bits->put(0, $term);
    while ($bits->len() % 8 !== 0) $bits->put(0, 1);
    $codewords = [];
    foreach (array_chunk($bits->bits(), 8) as $byte) { $v = 0; foreach ($byte as $b) $v = ($v << 1) | $b; $codewords[] = $v; }
    $pad = [0xEC, 0x11]; $pi = 0;
    while (count($codewords) < $totalDataCodewords) { $codewords[] = $pad[$pi % 2]; $pi++; }

    // ── розбиття на блоки, RS-кодування, чергування ──
    $ecCount = $entry[1] - $entry[2];
    $offset = 0;
    foreach ($groups as $g) {
        [$count, , $dataLen] = $g;
        for ($i = 0; $i < $count; $i++) {
            $data = array_slice($codewords, $offset, $dataLen); $offset += $dataLen;
            $blocks[] = [$data, qr_rs_encode($data, $ecCount)];
        }
    }
    $maxData = max(array_map(fn($b) => count($b[0]), $blocks));
    $final = [];
    for ($i = 0; $i < $maxData; $i++) foreach ($blocks as $b) if ($i < count($b[0])) $final[] = $b[0][$i];
    for ($i = 0; $i < $ecCount; $i++) foreach ($blocks as $b) $final[] = $b[1][$i];

    // ── матриця ──
    $size = $version * 4 + 17;
    $mat = array_fill(0, $size, array_fill(0, $size, null));
    $set = function (&$m, $r, $c, $v) use ($size) { if ($r >= 0 && $r < $size && $c >= 0 && $c < $size) $m[$r][$c] = $v; };
    $finder = function (&$m, $r0, $c0) use ($set) {
        for ($r = -1; $r <= 7; $r++) for ($c = -1; $c <= 7; $c++) {
            $dark = $r >= 0 && $r <= 6 && $c >= 0 && $c <= 6 && ($r === 0 || $r === 6 || $c === 0 || $c === 6 || ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4));
            $set($m, $r0 + $r, $c0 + $c, $dark);
        }
    };
    $finder($mat, 0, 0); $finder($mat, 0, $size - 7); $finder($mat, $size - 7, 0);
    for ($i = 0; $i < $size; $i++) { if ($mat[$i][6] === null) $set($mat, $i, 6, $i % 2 === 0); if ($mat[6][$i] === null) $set($mat, 6, $i, $i % 2 === 0); }
    $align = QR_ALIGN[$version] ?? [];
    foreach ($align as $r0) foreach ($align as $c0) {
        if (($r0 <= 8 && $c0 <= 8) || ($r0 <= 8 && $c0 >= $size - 9) || ($r0 >= $size - 9 && $c0 <= 8)) continue; // перекриття з finder
        for ($r = -2; $r <= 2; $r++) for ($c = -2; $c <= 2; $c++) $set($mat, $r0 + $r, $c0 + $c, max(abs($r), abs($c)) !== 1);
    }
    $set($mat, 4 * $version + 9, 8, true);                          // фіксований темний модуль
    // формат-інформація (маска завжди 0)
    $fd = (QR_EC_BITS[$level] << 3) | 0;
    $rem = $fd << 10; for ($i = 14; $i >= 10; $i--) if (($rem >> $i) & 1) $rem ^= QR_FORMAT_GENERATOR << ($i - 10);
    $fbits = (($fd << 10) | $rem) ^ QR_FORMAT_MASK;
    $fget = fn($i) => ($fbits >> $i) & 1;
    for ($i = 0; $i <= 5; $i++) $set($mat, 8, $i, (bool)$fget(14 - $i));
    $set($mat, 8, 7, (bool)$fget(8)); $set($mat, 8, 8, (bool)$fget(7)); $set($mat, 7, 8, (bool)$fget(6));
    for ($i = 9; $i <= 14; $i++) $set($mat, 14 - $i, 8, (bool)$fget(14 - $i));
    for ($i = 0; $i <= 7; $i++) $set($mat, 8, $size - 1 - $i, (bool)$fget($i));
    for ($i = 8; $i <= 14; $i++) $set($mat, $size - 15 + $i, 8, (bool)$fget($i));
    // версійна інформація (версії 7+)
    if ($version >= 7) {
        $vrem = $version << 12; for ($i = 17; $i >= 12; $i--) if (($vrem >> $i) & 1) $vrem ^= QR_VERSION_GENERATOR << ($i - 12);
        $vbits = ($version << 12) | $vrem; $vget = fn($i) => ($vbits >> $i) & 1;
        for ($i = 0; $i < 18; $i++) { $r = intdiv($i, 3); $c = $i % 3; $set($mat, $r, $size - 11 + $c, (bool)$vget($i)); $set($mat, $size - 11 + $c, $r, (bool)$vget($i)); }
    }

    // ── зигзаг-заповнення даними, маска 0 ──
    $bitIdx = 0; $totalBitsAvail = count($final) * 8;
    $getBit = function (int $i) use ($final): bool { return $i < count($final) * 8 && ((($final[intdiv($i, 8)] >> (7 - $i % 8)) & 1) === 1); };
    $row = $size - 1; $dir = -1;
    for ($col = $size - 1; $col > 0; $col -= 2) {
        if ($col === 6) $col--;
        while (true) {
            for ($c = 0; $c < 2; $c++) {
                $cc = $col - $c;
                if ($mat[$row][$cc] === null) {
                    $dark = $getBit($bitIdx); $bitIdx++;
                    if (($row + $cc) % 2 === 0) $dark = !$dark;      // маска 0
                    $mat[$row][$cc] = $dark;
                }
            }
            $row += $dir;
            if ($row < 0 || $row >= $size) { $row -= $dir; $dir = -$dir; break; }
        }
    }
    foreach ($mat as &$r) foreach ($r as &$v) $v = (bool)$v;
    return [$mat, $size, $version, $level];
}
