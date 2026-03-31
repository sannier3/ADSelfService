<?php
// Version du module "mot de passe oublié" (alignée sur intranet.php)
$APP_VERSION = '1.00.00';

/**
 * Mot de passe oublié — Demande de code par email, reset via API /admin/changePassword.
 * Utilise config-intranet.php, la même base que l’intranet (outils), et l’envoi de mail
 * en mode internal (PHP mail) ou api (votre API mailer).
 */
$sessionLifetime = 12 * 3600;
session_set_cookie_params([
    'lifetime' => $sessionLifetime,
    'path' => '/',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
    'httponly' => true,
    'samesite' => 'Lax',
]);
ini_set('session.gc_maxlifetime', (string) $sessionLifetime);
session_start();

$CONFIG = @include __DIR__ . '/config-intranet.php';
if (!is_array($CONFIG)) {
    header('Location: intranet.php');
    exit;
}
$GLOBALS['CONFIG'] = $CONFIG;
require_once __DIR__ . '/intranet-i18n.php';
intranet_i18n_bootstrap();

$FORGOT_ENABLED = (bool) ($CONFIG['FORGOT_PASSWORD_ENABLED'] ?? true);
if (!$FORGOT_ENABLED) {
    header('Location: intranet.php');
    exit;
}

$API_BASE = (string) ($CONFIG['API_BASE'] ?? '');
$API_SHARED_SECRET = (string) ($CONFIG['INTERNAL_SHARED_SECRET'] ?? '');
$API_INSECURE_SKIP_VERIFY = (bool) ($CONFIG['API_INSECURE_SKIP_VERIFY'] ?? false);
if ($API_BASE === '' || $API_SHARED_SECRET === '' || strlen($API_SHARED_SECRET) < 32) {
    http_response_code(500);
    echo htmlspecialchars(__('forgot_error_config'));
    exit;
}
if (stripos($API_BASE, 'https://') !== 0) {
    $API_INSECURE_SKIP_VERIFY = false; // option sans effet en HTTP, neutralisée explicitement
}

$HCAPTCHA_ENABLED = (bool) ($CONFIG['HCAPTCHA_ENABLED'] ?? true);
$HCAPTCHA_SITEKEY = (string) ($CONFIG['HCAPTCHA_SITEKEY'] ?? '');
$HCAPTCHA_SECRET  = (string) ($CONFIG['HCAPTCHA_SECRET'] ?? '');

$MAIL_MODE = (string) ($CONFIG['MAIL_MODE'] ?? 'internal');
$MAILER_API_URL = (string) ($CONFIG['MAILER_API_URL'] ?? '');
$MAILER_API_KEY = (string) ($CONFIG['MAILER_API_KEY'] ?? '') ?: (string) getenv('MAILER_API_KEY');
$MAIL_FROM = (string) ($CONFIG['MAIL_FROM'] ?? 'Intranet <no-reply@exemple.local>');

$TWILIO_SMS_ENABLED = (bool) ($CONFIG['TWILIO_SMS_ENABLED'] ?? false);
$TWILIO_ACCOUNT_SID = (string) ($CONFIG['TWILIO_ACCOUNT_SID'] ?? '');
$TWILIO_AUTH_TOKEN  = (string) ($CONFIG['TWILIO_AUTH_TOKEN'] ?? '') ?: (string) getenv('TWILIO_AUTH_TOKEN');
$TWILIO_FROM_NUMBER = (string) ($CONFIG['TWILIO_FROM_NUMBER'] ?? '');

define('RESET_CODE_TTL', 30); // minutes
define('USER_PAGE_SIZE', 500);
define('RESET_MAX_ATTEMPTS_PER_SAM_IP', 5);
define('RESET_MAX_ATTEMPTS_PER_IP', 20);
define('RESET_BLOCK_MINUTES', 30);

function csrf(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_ok(?string $t): bool
{
    return is_string($t) && hash_equals($_SESSION['csrf'] ?? '', $t);
}

function verifyCaptcha(string $token, string $secret, string $ip): bool
{
    if ($token === '' || $secret === '') return false;
    $ch = curl_init('https://hcaptcha.com/siteverify');
    $post = http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $post, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10]);
    $res = curl_exec($ch);
    curl_close($ch);
    $j = json_decode($res, true);
    return is_array($j) && !empty($j['success']);
}

/** @return array{error:bool,httpCode:int,message:string,data:mixed} */
function callApi(string $method, string $endpoint, ?array $data = null): array
{
    global $API_BASE, $API_SHARED_SECRET, $API_INSECURE_SKIP_VERIFY;
    $url = rtrim($API_BASE, '/') . $endpoint;
    $ch = curl_init($url);
    $hdr = ['Content-Type: application/json'];
    $hdr[] = 'X-App-Context: forgot-reset';
    if ($API_SHARED_SECRET !== '') $hdr[] = 'X-Internal-Auth: ' . $API_SHARED_SECRET;
    $opt = [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $hdr, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 25, CURLOPT_CONNECTTIMEOUT => 10];
    if (stripos($url, 'https://') === 0 && $API_INSECURE_SKIP_VERIFY) {
        $opt[CURLOPT_SSL_VERIFYPEER] = false;
        $opt[CURLOPT_SSL_VERIFYHOST] = 0;
    }
    if ($data !== null) $opt[CURLOPT_POSTFIELDS] = json_encode($data, JSON_UNESCAPED_UNICODE);
    curl_setopt_array($ch, $opt);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($resp === false) {
        $err = curl_error($ch);
        curl_close($ch);
        return ['error' => true, 'httpCode' => $code, 'message' => sprintf(__('err_network'), $err), 'data' => null];
    }
    curl_close($ch);
    $json = json_decode($resp, true);
    if ($json === null && json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => true, 'httpCode' => $code, 'message' => __('err_invalid_json'), 'data' => null];
    }
    return ['error' => ($code < 200 || $code >= 300), 'httpCode' => $code, 'message' => is_array($json) && isset($json['error']) ? $json['error'] : '', 'data' => $json];
}

function normalizePhone(string $raw): string|false
{
    $clean = preg_replace('/[^\d\+]/', '', $raw ?? '');
    if ($clean === null) return false;
    if (str_starts_with($clean, '+')) return preg_match('/^\+33[1-9]\d{8}$/', $clean) ? $clean : false;
    $d = preg_replace('/\D+/', '', $clean);
    if ($d === null) return false;
    if (strlen($d) === 10 && $d[0] === '0') { $e = '+33' . substr($d, 1); return preg_match('/^\+33[1-9]\d{8}$/', $e) ? $e : false; }
    if (strlen($d) === 11 && substr($d, 0, 2) === '33') { $e = '+' . $d; return preg_match('/^\+33[1-9]\d{8}$/', $e) ? $e : false; }
    if (strlen($d) === 12 && substr($d, 0, 4) === '0033') { $e = '+' . substr($d, 2); return preg_match('/^\+33[1-9]\d{8}$/', $e) ? $e : false; }
    return false;
}

function get_pdo(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    $CFG = $GLOBALS['CONFIG'];
    if (!empty($CFG['DB_DSN'])) {
        $pdo = new PDO($CFG['DB_DSN'], $CFG['DB_USER'] ?? null, $CFG['DB_PASS'] ?? null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } else {
        if (!extension_loaded('pdo_sqlite') && !extension_loaded('sqlite3')) {
            throw new RuntimeException('SQLite driver not available: please enable or install sqlite3 (pdo_sqlite).');
        }
        $path = $CFG['DB_PATH'] ?? (__DIR__ . '/intranet.sqlite');
        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec("PRAGMA journal_mode=WAL;");
    }
    return $pdo;
}

function reset_codes_bootstrap(PDO $pdo): void
{
    $drv = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($drv === 'mysql') {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_codes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                samaccountname VARCHAR(255) NOT NULL,
                reset_code_hash VARCHAR(255) NOT NULL,
                reset_code_date DATETIME NOT NULL,
                UNIQUE KEY uq_sam (samaccountname)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    } else {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                samaccountname TEXT NOT NULL UNIQUE,
                reset_code_hash TEXT NOT NULL,
                reset_code_date TEXT NOT NULL
            )
        ");
    }
}

function reset_attempts_bootstrap(PDO $pdo): void
{
    $drv = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($drv === 'mysql') {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_attempts (
                samaccountname VARCHAR(255) NOT NULL,
                ip VARCHAR(64) NOT NULL,
                fail_count INT NOT NULL DEFAULT 0,
                blocked_until DATETIME NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (samaccountname, ip)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    } else {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_attempts (
                samaccountname TEXT NOT NULL,
                ip TEXT NOT NULL,
                fail_count INTEGER NOT NULL DEFAULT 0,
                blocked_until TEXT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (samaccountname, ip)
            )
        ");
    }
}

function reset_attempts_is_blocked(PDO $pdo, string $sam, string $ip): bool
{
    reset_attempts_bootstrap($pdo);
    $q = $pdo->prepare("SELECT blocked_until FROM reset_attempts WHERE samaccountname = ? AND ip = ? LIMIT 1");
    $q->execute([$sam, $ip]);
    $row = $q->fetch(PDO::FETCH_ASSOC);
    if (!$row || empty($row['blocked_until'])) {
        return false;
    }
    $ts = DateTime::createFromFormat('Y-m-d H:i:s', (string) $row['blocked_until']);
    return $ts instanceof DateTime && $ts->getTimestamp() > time();
}

function reset_attempts_register_failure(PDO $pdo, string $sam, string $ip): void
{
    reset_attempts_bootstrap($pdo);
    $now = date('Y-m-d H:i:s');

    $q = $pdo->prepare("SELECT fail_count FROM reset_attempts WHERE samaccountname = ? AND ip = ? LIMIT 1");
    $q->execute([$sam, $ip]);
    $row = $q->fetch(PDO::FETCH_ASSOC);
    $count = (int) ($row['fail_count'] ?? 0) + 1;
    $blockedUntil = null;
    if ($count >= RESET_MAX_ATTEMPTS_PER_SAM_IP) {
        $blockedUntil = date('Y-m-d H:i:s', time() + (RESET_BLOCK_MINUTES * 60));
        $count = 0; // on repart après verrouillage
    }

    if ($row) {
        $u = $pdo->prepare("UPDATE reset_attempts SET fail_count = ?, blocked_until = ?, updated_at = ? WHERE samaccountname = ? AND ip = ?");
        $u->execute([$count, $blockedUntil, $now, $sam, $ip]);
    } else {
        $i = $pdo->prepare("INSERT INTO reset_attempts (samaccountname, ip, fail_count, blocked_until, updated_at) VALUES (?, ?, ?, ?, ?)");
        $i->execute([$sam, $ip, $count, $blockedUntil, $now]);
    }
}

function reset_attempts_clear(PDO $pdo, string $sam, string $ip): void
{
    reset_attempts_bootstrap($pdo);
    $d = $pdo->prepare("DELETE FROM reset_attempts WHERE samaccountname = ? AND ip = ?");
    $d->execute([$sam, $ip]);
}

function reset_attempts_ip_bootstrap(PDO $pdo): void
{
    $drv = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($drv === 'mysql') {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_attempts_ip (
                ip VARCHAR(64) NOT NULL PRIMARY KEY,
                fail_count INT NOT NULL DEFAULT 0,
                blocked_until DATETIME NULL,
                updated_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    } else {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_attempts_ip (
                ip TEXT NOT NULL PRIMARY KEY,
                fail_count INTEGER NOT NULL DEFAULT 0,
                blocked_until TEXT NULL,
                updated_at TEXT NOT NULL
            )
        ");
    }
}

function reset_attempts_ip_is_blocked(PDO $pdo, string $ip): bool
{
    reset_attempts_ip_bootstrap($pdo);
    $q = $pdo->prepare("SELECT blocked_until FROM reset_attempts_ip WHERE ip = ? LIMIT 1");
    $q->execute([$ip]);
    $row = $q->fetch(PDO::FETCH_ASSOC);
    if (!$row || empty($row['blocked_until'])) {
        return false;
    }
    $ts = DateTime::createFromFormat('Y-m-d H:i:s', (string) $row['blocked_until']);
    return $ts instanceof DateTime && $ts->getTimestamp() > time();
}

function reset_attempts_ip_register_failure(PDO $pdo, string $ip): void
{
    reset_attempts_ip_bootstrap($pdo);
    $now = date('Y-m-d H:i:s');
    $q = $pdo->prepare("SELECT fail_count FROM reset_attempts_ip WHERE ip = ? LIMIT 1");
    $q->execute([$ip]);
    $row = $q->fetch(PDO::FETCH_ASSOC);
    $count = (int) ($row['fail_count'] ?? 0) + 1;
    $blockedUntil = null;
    if ($count >= RESET_MAX_ATTEMPTS_PER_IP) {
        $blockedUntil = date('Y-m-d H:i:s', time() + (RESET_BLOCK_MINUTES * 60));
        $count = 0;
    }
    if ($row) {
        $u = $pdo->prepare("UPDATE reset_attempts_ip SET fail_count = ?, blocked_until = ?, updated_at = ? WHERE ip = ?");
        $u->execute([$count, $blockedUntil, $now, $ip]);
    } else {
        $i = $pdo->prepare("INSERT INTO reset_attempts_ip (ip, fail_count, blocked_until, updated_at) VALUES (?, ?, ?, ?)");
        $i->execute([$ip, $count, $blockedUntil, $now]);
    }
}

function reset_attempts_ip_clear(PDO $pdo, string $ip): void
{
    reset_attempts_ip_bootstrap($pdo);
    $d = $pdo->prepare("DELETE FROM reset_attempts_ip WHERE ip = ?");
    $d->execute([$ip]);
}

/**
 * Envoi d’email : mode 'internal' (PHP mail) ou 'api' (votre API mailer).
 */
function send_mail(string $toEmail, string $subject, string $bodyHtml, ?string $replyToEmail = null, ?string $replyToName = null): bool
{
    global $MAIL_MODE, $MAILER_API_URL, $MAILER_API_KEY, $MAIL_FROM;

    if ($MAIL_MODE === 'api' && $MAILER_API_URL !== '' && $MAILER_API_KEY !== '') {
        $payload = [
            'to'      => [$toEmail],
            'subject' => $subject,
            'type'    => 'html',
            'content' => $bodyHtml,
            'metadata' => ['env' => 'forgot_password'],
        ];
        if ($replyToEmail !== null) {
            $payload['reply_to'] = ['email' => $replyToEmail, 'name' => $replyToName ?? $replyToEmail];
        }
        $ch = curl_init($MAILER_API_URL);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-API-Key: ' . $MAILER_API_KEY,
            ],
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
        ]);
        $resp = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $json = json_decode($resp, true);
        if ($code !== 200 || empty($json['success'])) {
            error_log('Mailer API failed: ' . ($json['error'] ?? "HTTP $code"));
            return false;
        }
        return true;
    }

    $headers = "From: $MAIL_FROM\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n";
    return @mail($toEmail, $subject, $bodyHtml, $headers);
}

function sendResetEmail(string $toEmail, string $username, int $code): bool
{
    $subject = __('forgot_email_subject');
    $html = '<html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
    <div style="max-width:560px;margin:auto;border:1px solid #ddd;border-radius:12px;padding:16px">
      <h2 style="margin:0 0 8px;color:#1d4ed8">' . htmlspecialchars(__('forgot_email_heading')) . '</h2>
      <p>' . sprintf(__('forgot_email_greeting'), '<strong>' . htmlspecialchars($username) . '</strong>') . '</p>
      <p>' . htmlspecialchars(__('forgot_email_code_intro')) . '</p>
      <p style="font-size:24px;font-weight:700;letter-spacing:6px;background:#eef2ff;border:1px solid #c7d2fe;border-radius:10px;padding:10px;text-align:center;color:#1e40af">' . $code . '</p>
      <p>' . sprintf(__('forgot_email_valid_for'), RESET_CODE_TTL) . '</p>
    </div></body></html>';
    return send_mail($toEmail, $subject, $html);
}

/**
 * Envoi SMS via Twilio (identifiants lus depuis la config / getenv, jamais en dur).
 * $toE164 = numéro au format E.164 (ex. +33612345678).
 */
function send_sms_twilio(string $toE164, string $message): bool
{
    global $TWILIO_ACCOUNT_SID, $TWILIO_AUTH_TOKEN, $TWILIO_FROM_NUMBER;
    if ($TWILIO_ACCOUNT_SID === '' || $TWILIO_AUTH_TOKEN === '' || $TWILIO_FROM_NUMBER === '') {
        return false;
    }
    $url = 'https://api.twilio.com/2010-04-01/Accounts/' . rawurlencode($TWILIO_ACCOUNT_SID) . '/Messages.json';
    $body = http_build_query([
        'To'   => $toE164,
        'From' => $TWILIO_FROM_NUMBER,
        'Body' => $message,
    ]);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_USERPWD => $TWILIO_ACCOUNT_SID . ':' . $TWILIO_AUTH_TOKEN,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code < 200 || $code >= 300) {
        error_log('Twilio SMS failed: HTTP ' . $code . ' ' . substr($resp, 0, 200));
        return false;
    }
    $json = json_decode($resp, true);
    return is_array($json) && !empty($json['sid']);
}

/* ===== Flow ===== */
$mode = 'request';
$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (($_POST['step'] ?? '') === 'request_code') {
        if (!csrf_ok($_POST['csrf'] ?? '')) {
            $errors[] = __('msg_session_expired');
            $mode = 'request';
        } elseif ($HCAPTCHA_ENABLED && (empty($_POST['h-captcha-response']) || !verifyCaptcha($_POST['h-captcha-response'], $HCAPTCHA_SECRET, $_SERVER['REMOTE_ADDR'] ?? ''))) {
            $errors[] = __('msg_captcha_invalid');
            $mode = 'request';
        } else {
            $identifier = trim((string) ($_POST['identifier'] ?? ''));
            if ($identifier === '') $errors[] = __('forgot_error_identifier_required');
            if (!$errors && $API_BASE !== '') {
                // Réponse volontairement uniforme pour éviter l'énumération de comptes.
                $success = sprintf(__('forgot_success_code_sent'), RESET_CODE_TTL);
                $mode = 'reset';

                $lookup = callApi('GET', '/recovery/lookup?identifier=' . rawurlencode($identifier));
                $found = (!$lookup['error'] && is_array($lookup['data']) && !empty($lookup['data']['found'])) ? $lookup['data'] : null;

                if ($found) {
                    $sam = trim((string) ($found['sam'] ?? ''));
                    if ($sam !== '') {
                        $code = random_int(100000, 999999);
                        $now = date('Y-m-d H:i:s');
                        try {
                            $pdo = get_pdo();
                            reset_codes_bootstrap($pdo);
                            $codeHash = password_hash((string) $code, PASSWORD_DEFAULT);
                            $up = $pdo->prepare("UPDATE reset_codes SET reset_code_hash = ?, reset_code_date = ? WHERE samaccountname = ?");
                            $up->execute([(string) $codeHash, $now, $sam]);
                            if ($up->rowCount() === 0) {
                                $pdo->prepare("INSERT INTO reset_codes (samaccountname, reset_code_hash, reset_code_date) VALUES (?, ?, ?)")
                                    ->execute([$sam, (string) $codeHash, $now]);
                            }

                            $sent = false;
                            if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
                                $sent = sendResetEmail($identifier, (string) ($found['givenName'] ?? $sam), $code);
                            } else {
                                $phone = normalizePhone($identifier);
                                if ($phone !== false && $TWILIO_SMS_ENABLED) {
                                    $msg = sprintf(__('forgot_sms_message'), $code, RESET_CODE_TTL);
                                    $sent = send_sms_twilio($phone, $msg);
                                }
                            }
                            if (!$sent) {
                                error_log('[forgot_password] code generated but delivery failed for ' . $sam);
                            }
                        } catch (Throwable $e) {
                            error_log('[forgot_password] request_code failure: ' . $e->getMessage());
                        }
                    }
                }
            }
        }
    }

    if (($_POST['step'] ?? '') === 'do_reset') {
        if (!csrf_ok($_POST['csrf'] ?? '')) {
            $errors[] = __('msg_session_expired');
            $mode = 'reset';
        } else {
            $sam = trim((string) ($_POST['samaccountname'] ?? ''));
            $codeIn = trim((string) ($_POST['reset_code'] ?? ''));
            $new = (string) ($_POST['new_password'] ?? '');
            $conf = (string) ($_POST['confirm_password'] ?? '');
            if ($sam === '' || $codeIn === '' || $new === '' || $conf === '') $errors[] = __('msg_all_fields_required');
            if ($new !== $conf) $errors[] = __('msg_password_mismatch');
            if (!$errors) {
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                try {
                    $pdo = get_pdo();
                    reset_codes_bootstrap($pdo);
                    if (reset_attempts_is_blocked($pdo, $sam, $ip)) {
                        $errors[] = __('forgot_error_too_many_attempts');
                        $mode = 'reset';
                    }
                    if (reset_attempts_ip_is_blocked($pdo, $ip)) {
                        $errors[] = __('forgot_error_too_many_attempts');
                        $mode = 'reset';
                    }
                    if ($errors) {
                        throw new RuntimeException('blocked');
                    }
                    $q = $pdo->prepare("SELECT reset_code_hash, reset_code_date FROM reset_codes WHERE samaccountname = ? LIMIT 1");
                    $q->execute([$sam]);
                    $row = $q->fetch(PDO::FETCH_ASSOC);
                    if (!$row) $errors[] = __('forgot_error_code_invalid');
                    else {
                        $hash = (string) ($row['reset_code_hash'] ?? '');
                        $okCode = ($hash !== '') && password_verify((string) $codeIn, $hash);
                        if (!$okCode) $errors[] = __('forgot_error_code_invalid');
                        else {
                            $ts = DateTime::createFromFormat('Y-m-d H:i:s', $row['reset_code_date']);
                            if (!$ts) $errors[] = __('forgot_error_code_invalid');
                            else {
                                $ageMin = (time() - $ts->getTimestamp()) / 60;
                                if ($ageMin > RESET_CODE_TTL) $errors[] = __('forgot_error_code_invalid');
                            }
                        }
                    }
                } catch (Throwable $e) {
                    if ($e->getMessage() !== 'blocked') {
                        $errors[] = __('forgot_error_internal');
                    }
                }
                if (!$errors) {
                    $r = callApi('POST', '/admin/changePassword', ['username' => $sam, 'newPassword' => $new]);
                    if ($r['error']) {
                        $errors[] = __('forgot_error_change_password');
                        try {
                            reset_attempts_register_failure($pdo, $sam, $ip);
                            reset_attempts_ip_register_failure($pdo, $ip);
                        } catch (Throwable) {
                        }
                    }
                    else {
                        $pdo->prepare("DELETE FROM reset_codes WHERE samaccountname = ?")->execute([$sam]);
                        reset_attempts_clear($pdo, $sam, $ip);
                        reset_attempts_ip_clear($pdo, $ip);
                        $success = __('forgot_success_password_reset');
                        $mode = 'request';
                    }
                } else {
                    try {
                        $pdo = $pdo ?? get_pdo();
                        reset_attempts_register_failure($pdo, $sam, $ip ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                        reset_attempts_ip_register_failure($pdo, $ip ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                    } catch (Throwable) {
                    }
                }
            }
        }
    }
}

$csrf = csrf();
?>
<!doctype html>
<html lang="<?= htmlspecialchars($INTRANET_LANG ?? 'fr', ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars(__('forgot_title')) ?></title>
<?php if ($HCAPTCHA_ENABLED): ?><script src="https://hcaptcha.com/1/api.js" async defer></script><?php endif; ?>
<style>
:root{ --bg:#0f172a; --card:#111827; --text:#e5e7eb; --sub:#9ca3af; --primary:#3b82f6; --border:#334155; --shadow-card:0 16px 38px rgba(0,0,0,.35); }
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(180deg,#0b1220,#0f172a 40%,#0b1220);color:var(--text);
  font:16px/1.4 system-ui,Segoe UI,Roboto,Arial,sans-serif;min-height:100vh;padding:24px;}
.container{max-width:560px;margin:0 auto}
.nav{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.nav-brand{font-weight:700}
.lang-switch-wrap{position:relative}
.lang-switch{appearance:none;background:#111827;border:1px solid var(--border);color:var(--text);border-radius:10px;padding:8px 34px 8px 12px;cursor:pointer}
.lang-switch-wrap::after{content:"▾";position:absolute;right:11px;top:50%;transform:translateY(-52%);pointer-events:none;color:#9ca3af;font-size:12px}
.card{width:100%;background:rgba(17,24,39,.9);border:1px solid var(--border);border-radius:0;padding:24px;box-shadow:var(--shadow-card);backdrop-filter:blur(8px)}
h1{margin:.2rem 0 1rem;font-size:1.4rem}
.label{display:block;margin:10px 2px 6px;color:var(--sub);font-size:.9rem}
.input{width:100%;background:#1f2937;color:var(--text);border:1px solid var(--border);border-radius:0;padding:12px 14px;outline:none;transition:.15s;border-bottom-width:2px}
.input:focus{border-color:var(--primary)}
.btn{background:var(--primary);color:white;border:none;border-radius:0;padding:12px 16px;font-weight:600;cursor:pointer;transition:.15s;width:100%}
.btn:hover{filter:brightness(.95)}
.alert{padding:12px;border-radius:0;margin:10px 0}
.err{background:rgba(239,68,68,.12);border:1px solid #7f1d1d}
.ok{background:rgba(34,197,94,.12);border:1px solid #14532d}
.link{display:inline-block;margin-top:8px;color:var(--primary)}
</style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <div class="nav-brand">Intranet</div>
      <?php if (!empty($INTRANET_LANG_SWITCH_UI)): ?>
      <div class="lang-switch-wrap" title="<?= htmlspecialchars(__('lang_switch_title')) ?>">
        <form method="post" action="">
          <input type="hidden" name="csrf" value="<?= htmlspecialchars(csrf()) ?>">
          <input type="hidden" name="intranet_set_lang" value="1">
          <label class="visually-hidden" for="forgot-lang"><?= htmlspecialchars(__('lang_switch_aria')) ?></label>
          <select id="forgot-lang" name="intranet_lang" class="lang-switch" onchange="this.form.submit()">
            <?php foreach (intranet_i18n_allowed_locales() as $loc): ?>
              <option value="<?= htmlspecialchars($loc, ENT_QUOTES, 'UTF-8') ?>" <?= (($INTRANET_LANG ?? 'fr') === $loc) ? 'selected' : '' ?>>
                <?= htmlspecialchars(intranet_i18n_locale_native_label($loc)) ?>
              </option>
            <?php endforeach; ?>
          </select>
        </form>
      </div>
      <?php endif; ?>
    </div>
    <div class="card">
    <?php if ($mode === 'request'): ?>
      <h1><?= htmlspecialchars(__('forgot_request_title')) ?></h1>
      <?php if ($errors): ?><div class="alert err"><?php foreach ($errors as $e) echo '<div>' . htmlspecialchars($e) . '</div>'; ?></div><?php endif; ?>
      <?php if ($success): ?><div class="alert ok"><?= htmlspecialchars($success) ?></div><?php endif; ?>
      <form method="post" autocomplete="off" novalidate>
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
        <input type="hidden" name="step" value="request_code">
        <label class="label" for="identifier"><?= htmlspecialchars(__('forgot_identifier_label')) ?></label>
        <input class="input" id="identifier" name="identifier" placeholder="<?= htmlspecialchars(__('forgot_identifier_placeholder')) ?>" required>
        <?php if ($HCAPTCHA_ENABLED): ?>
        <div style="margin:14px 0" class="h-captcha" data-sitekey="<?= htmlspecialchars($HCAPTCHA_SITEKEY) ?>"></div>
        <?php endif; ?>
        <button class="btn" type="submit"><?= htmlspecialchars(__('forgot_send_code')) ?></button>
      </form>
      <a class="link" href="intranet.php">← <?= htmlspecialchars(__('forgot_back_login')) ?></a>

    <?php else: ?>
      <h1><?= htmlspecialchars(__('forgot_reset_title')) ?></h1>
      <?php if ($errors): ?><div class="alert err"><?php foreach ($errors as $e) echo '<div>' . htmlspecialchars($e) . '</div>'; ?></div><?php endif; ?>
      <?php if ($success): ?><div class="alert ok"><?= htmlspecialchars($success) ?></div><?php endif; ?>
      <form method="post" autocomplete="off" novalidate>
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
        <input type="hidden" name="step" value="do_reset">
        <label class="label" for="sam"><?= htmlspecialchars(__('forgot_sam_label')) ?></label>
        <input class="input" id="sam" name="samaccountname" required>
        <label class="label" for="code"><?= htmlspecialchars(__('forgot_code_label')) ?></label>
        <input class="input" id="code" name="reset_code" inputmode="numeric" required>
        <label class="label" for="npw"><?= htmlspecialchars(__('forgot_new_password_label')) ?></label>
        <input class="input" id="npw" name="new_password" type="password" required>
        <label class="label" for="cpw"><?= htmlspecialchars(__('forgot_confirm_password_label')) ?></label>
        <input class="input" id="cpw" name="confirm_password" type="password" required>
        <button class="btn" type="submit"><?= htmlspecialchars(__('forgot_submit_reset')) ?></button>
      </form>
      <a class="link" href="intranet.php">← <?= htmlspecialchars(__('forgot_back_login')) ?></a>
    <?php endif; ?>
    </div>
    <footer style="margin-top:24px;padding:8px 16px;font-size:12px;opacity:.65;text-align:center;">
    ADSelfService forgot password v<?= htmlspecialchars($APP_VERSION, ENT_QUOTES, 'UTF-8') ?>
    </footer>
  </div>
</body>
</html>
