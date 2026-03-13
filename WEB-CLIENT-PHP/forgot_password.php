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
    echo 'Configuration API invalide.';
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
        return ['error' => true, 'httpCode' => $code, 'message' => "Erreur réseau: $err", 'data' => null];
    }
    curl_close($ch);
    $json = json_decode($resp, true);
    if ($json === null && json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => true, 'httpCode' => $code, 'message' => 'Réponse JSON invalide', 'data' => null];
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
                reset_code VARCHAR(20) NOT NULL,
                reset_code_date DATETIME NOT NULL,
                UNIQUE KEY uq_sam (samaccountname)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    } else {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS reset_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                samaccountname TEXT NOT NULL UNIQUE,
                reset_code TEXT NOT NULL,
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
    $maxAttempts = 5;
    $blockMinutes = 30;

    $q = $pdo->prepare("SELECT fail_count FROM reset_attempts WHERE samaccountname = ? AND ip = ? LIMIT 1");
    $q->execute([$sam, $ip]);
    $row = $q->fetch(PDO::FETCH_ASSOC);
    $count = (int) ($row['fail_count'] ?? 0) + 1;
    $blockedUntil = null;
    if ($count >= $maxAttempts) {
        $blockedUntil = date('Y-m-d H:i:s', time() + ($blockMinutes * 60));
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
    $subject = '[Intranet] Code de réinitialisation';
    $html = '<html><body style="font-family:system-ui,Segoe UI,Roboto,Arial">
    <div style="max-width:560px;margin:auto;border:1px solid #ddd;border-radius:12px;padding:16px">
      <h2 style="margin:0 0 8px;color:#1d4ed8">Réinitialisation</h2>
      <p>Bonjour <strong>' . htmlspecialchars($username) . '</strong>, voici votre code :</p>
      <p style="font-size:24px;font-weight:700;letter-spacing:6px;background:#eef2ff;border:1px solid #c7d2fe;border-radius:10px;padding:10px;text-align:center;color:#1e40af">' . $code . '</p>
      <p>Valable ' . RESET_CODE_TTL . ' minutes.</p>
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
            $errors[] = 'Session expirée.';
            $mode = 'request';
        } elseif ($HCAPTCHA_ENABLED && (empty($_POST['h-captcha-response']) || !verifyCaptcha($_POST['h-captcha-response'], $HCAPTCHA_SECRET, $_SERVER['REMOTE_ADDR'] ?? ''))) {
            $errors[] = 'Captcha invalide.';
            $mode = 'request';
        } else {
            $identifier = trim((string) ($_POST['identifier'] ?? ''));
            if ($identifier === '') $errors[] = 'Saisissez votre e-mail ou téléphone.';
            if (!$errors && $API_BASE !== '') {
                // Réponse volontairement uniforme pour éviter l'énumération de comptes.
                $success = 'Si un compte correspond, un code de réinitialisation a été envoyé. Il est valable ' . RESET_CODE_TTL . ' minutes.';
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
                            $up = $pdo->prepare("UPDATE reset_codes SET reset_code = ?, reset_code_date = ? WHERE samaccountname = ?");
                            $up->execute([(string) $code, $now, $sam]);
                            if ($up->rowCount() === 0) {
                                $pdo->prepare("INSERT INTO reset_codes (samaccountname, reset_code, reset_code_date) VALUES (?, ?, ?)")->execute([$sam, (string) $code, $now]);
                            }

                            $sent = false;
                            if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
                                $sent = sendResetEmail($identifier, (string) ($found['givenName'] ?? $sam), $code);
                            } else {
                                $phone = normalizePhone($identifier);
                                if ($phone !== false && $TWILIO_SMS_ENABLED) {
                                    $msg = 'Votre code de réinitialisation : ' . $code . '. Valable ' . RESET_CODE_TTL . ' min.';
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
            $errors[] = 'Session expirée.';
            $mode = 'reset';
        } else {
            $sam = trim((string) ($_POST['samaccountname'] ?? ''));
            $codeIn = trim((string) ($_POST['reset_code'] ?? ''));
            $new = (string) ($_POST['new_password'] ?? '');
            $conf = (string) ($_POST['confirm_password'] ?? '');
            if ($sam === '' || $codeIn === '' || $new === '' || $conf === '') $errors[] = 'Tous les champs sont requis.';
            if ($new !== $conf) $errors[] = 'Le mot de passe et sa confirmation diffèrent.';
            if (!$errors) {
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                try {
                    $pdo = get_pdo();
                    reset_codes_bootstrap($pdo);
                    if (reset_attempts_is_blocked($pdo, $sam, $ip)) {
                        $errors[] = 'Trop de tentatives. Réessayez plus tard.';
                        $mode = 'reset';
                    }
                    if ($errors) {
                        throw new RuntimeException('blocked');
                    }
                    $q = $pdo->prepare("SELECT reset_code, reset_code_date FROM reset_codes WHERE samaccountname = ? LIMIT 1");
                    $q->execute([$sam]);
                    $row = $q->fetch(PDO::FETCH_ASSOC);
                    if (!$row) $errors[] = 'Code invalide ou expiré.';
                    else {
                        if ((string) $row['reset_code'] !== (string) $codeIn) $errors[] = 'Code invalide ou expiré.';
                        else {
                            $ts = DateTime::createFromFormat('Y-m-d H:i:s', $row['reset_code_date']);
                            if (!$ts) $errors[] = 'Code invalide ou expiré.';
                            else {
                                $ageMin = (time() - $ts->getTimestamp()) / 60;
                                if ($ageMin > RESET_CODE_TTL) $errors[] = 'Code invalide ou expiré.';
                            }
                        }
                    }
                } catch (Throwable $e) {
                    if ($e->getMessage() !== 'blocked') {
                        $errors[] = 'Erreur interne.';
                    }
                }
                if (!$errors) {
                    $r = callApi('POST', '/admin/changePassword', ['username' => $sam, 'newPassword' => $new]);
                    if ($r['error']) {
                        $errors[] = 'Impossible de changer le mot de passe.';
                        try {
                            reset_attempts_register_failure($pdo, $sam, $ip);
                        } catch (Throwable) {
                        }
                    }
                    else {
                        $pdo->prepare("DELETE FROM reset_codes WHERE samaccountname = ?")->execute([$sam]);
                        reset_attempts_clear($pdo, $sam, $ip);
                        $success = 'Mot de passe réinitialisé. Vous pouvez vous connecter.';
                        $mode = 'request';
                    }
                } else {
                    try {
                        $pdo = $pdo ?? get_pdo();
                        reset_attempts_register_failure($pdo, $sam, $ip ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
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
<html lang="fr">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mot de passe oublié</title>
<?php if ($HCAPTCHA_ENABLED): ?><script src="https://hcaptcha.com/1/api.js" async defer></script><?php endif; ?>
<style>
:root{ --bg:#0f172a; --card:#111827; --text:#e5e7eb; --sub:#9ca3af; --primary:#3b82f6; --border:#334155; }
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(180deg,#0b1220,#0f172a 40%,#0b1220);color:var(--text);
  font:16px/1.4 system-ui,Segoe UI,Roboto,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
.card{width:100%;max-width:480px;background:rgba(17,24,39,.9);border:1px solid var(--border);border-radius:18px;padding:24px;box-shadow:0 10px 30px rgba(0,0,0,.35);backdrop-filter:blur(8px)}
h1{margin:.2rem 0 1rem;font-size:1.4rem}
.label{display:block;margin:10px 2px 6px;color:var(--sub);font-size:.9rem}
.input{width:100%;background:#1f2937;color:var(--text);border:1px solid var(--border);border-radius:12px;padding:12px 14px;outline:none;transition:.15s;border-bottom-width:2px}
.input:focus{border-color:var(--primary)}
.btn{background:var(--primary);color:white;border:none;border-radius:12px;padding:12px 16px;font-weight:600;cursor:pointer;transition:.15s;width:100%}
.btn:hover{filter:brightness(.95)}
.alert{padding:12px;border-radius:12px;margin:10px 0}
.err{background:rgba(239,68,68,.12);border:1px solid #7f1d1d}
.ok{background:rgba(34,197,94,.12);border:1px solid #14532d}
.link{display:inline-block;margin-top:8px;color:var(--primary)}
</style>
</head>
<body>
  <div class="card">
    <?php if ($mode === 'request'): ?>
      <h1>Mot de passe oublié</h1>
      <?php if ($errors): ?><div class="alert err"><?php foreach ($errors as $e) echo '<div>' . htmlspecialchars($e) . '</div>'; ?></div><?php endif; ?>
      <?php if ($success): ?><div class="alert ok"><?= htmlspecialchars($success) ?></div><?php endif; ?>
      <form method="post" autocomplete="off" novalidate>
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
        <input type="hidden" name="step" value="request_code">
        <label class="label" for="identifier">E-mail ou téléphone</label>
        <input class="input" id="identifier" name="identifier" placeholder="mon@domaine.com ou 06XXXXXXXX" required>
        <?php if ($HCAPTCHA_ENABLED): ?>
        <div style="margin:14px 0" class="h-captcha" data-sitekey="<?= htmlspecialchars($HCAPTCHA_SITEKEY) ?>"></div>
        <?php endif; ?>
        <button class="btn" type="submit">Envoyer le code</button>
      </form>
      <a class="link" href="intranet.php">← Retour à la connexion</a>

    <?php else: ?>
      <h1>Réinitialisation</h1>
      <?php if ($errors): ?><div class="alert err"><?php foreach ($errors as $e) echo '<div>' . htmlspecialchars($e) . '</div>'; ?></div><?php endif; ?>
      <?php if ($success): ?><div class="alert ok"><?= htmlspecialchars($success) ?></div><?php endif; ?>
      <form method="post" autocomplete="off" novalidate>
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
        <input type="hidden" name="step" value="do_reset">
        <label class="label" for="sam">Identifiant (sAM)</label>
        <input class="input" id="sam" name="samaccountname" required>
        <label class="label" for="code">Code reçu</label>
        <input class="input" id="code" name="reset_code" inputmode="numeric" required>
        <label class="label" for="npw">Nouveau mot de passe</label>
        <input class="input" id="npw" name="new_password" type="password" required>
        <label class="label" for="cpw">Confirmer le mot de passe</label>
        <input class="input" id="cpw" name="confirm_password" type="password" required>
        <button class="btn" type="submit">Valider</button>
      </form>
      <a class="link" href="intranet.php">← Retour à la connexion</a>
    <?php endif; ?>
  </div>
  <footer style="margin-top:24px;padding:8px 16px;font-size:12px;opacity:.65;text-align:center;">
    ADSelfService forgot password v<?= htmlspecialchars($APP_VERSION, ENT_QUOTES, 'UTF-8') ?>
  </footer>
</body>
</html>
