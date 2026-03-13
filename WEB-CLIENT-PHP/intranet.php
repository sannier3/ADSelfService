<?php
// intranet.php — Auth, "Mon profil", "Mes outils", "Administration"
// Version de l'intranet ADSelfService (doit suivre les releases du projet GitHub)
$APP_VERSION = '1.00.00';
// Limite la saisie manuelle : sélections pour Groupes & OU (via /groups et /tree)
error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED);
error_reporting(0);

if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY"); // secours vieux navigateurs
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), camera=(), microphone=()");
header("Cache-Control: no-store"); // pour les pages authentifiées

// CSP : adapte la liste à tes domaines exacts
//header("Content-Security-Policy: default-src 'self' https:; img-src 'self' data: https:; script-src 'self' https://hcaptcha.com https://*.hcaptcha.com; frame-src https://hcaptcha.com https://*.hcaptcha.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests");

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

/* ================================
   Config — via fichiers PHP
   - config-intranet.php          (personnalisé, requis)
   - config-intranet-default.php  (valeurs de démo)
=================================== */
function fatal_config(string $msg): void
{
    http_response_code(500);
    // message simple, sans dépendre de la config
    echo "<!doctype html><meta charset='utf-8'><title>Config intranet</title>";
    echo "<div style='font:16px system-ui;max-width:720px;margin:40px auto;padding:16px;
                 border:1px solid #444;border-radius:12px;background:#111;color:#eee'>
            <h2 style='margin-top:0'>Configuration introuvable/invalide</h2>
            <p>" . htmlspecialchars($msg, ENT_QUOTES) . "</p>
            <p>Créez <code>config-intranet.php</code> en copiant
               <code>config-intranet-default.php</code> puis personnalisez-le.</p>
          </div>";
    exit;
}

$cfgFile = __DIR__ . '/config-intranet.php';
$defFile = __DIR__ . '/config-intranet-default.php';

if (!is_file($defFile)) {
    fatal_config("Fichier 'config-intranet-default.php' manquant.");
}
if (!is_file($cfgFile)) {
    fatal_config("Fichier 'config-intranet.php' manquant.");
}

$CONFIG = require $cfgFile;
if (!is_array($CONFIG)) {
    fatal_config("'config-intranet.php' ne retourne pas un tableau PHP (return [...]).");
}

/* Détection “valeurs par défaut” :
   - __IS_DEFAULT === true  => on stoppe
   - ou secret resté en placeholder
*/
if (!empty($CONFIG['__IS_DEFAULT'])) {
    fatal_config("'config-intranet.php' contient encore des valeurs par défaut (__IS_DEFAULT=true).");
}
if (empty($CONFIG['API_BASE'])) {
    fatal_config("'API_BASE' n'est pas défini dans 'config-intranet.php'.");
}
if (
    empty($CONFIG['INTERNAL_SHARED_SECRET'])
    || stripos((string) $CONFIG['INTERNAL_SHARED_SECRET'], 'change-me') !== false
) {
    fatal_config("'INTERNAL_SHARED_SECRET' doit être personnalisé dans 'config-intranet.php'.");
}
if (strlen((string) $CONFIG['INTERNAL_SHARED_SECRET']) < 32) {
    fatal_config("'INTERNAL_SHARED_SECRET' doit faire au moins 32 caractères.");
}

/* Mappage des variables attendues par le reste du code */
$TRUSTED_PROXIES = array_filter(array_map('trim', explode(',', (string) ($CONFIG['TRUSTED_PROXIES'] ?? ''))));
$CLIENT_IP_HEADER = (string) ($CONFIG['CLIENT_IP_HEADER'] ?? 'X-Forwarded-For');

$FORGOT_ENABLED = (bool) ($CONFIG['FORGOT_PASSWORD_ENABLED'] ?? true);

$SHOW_CLIENT_IP = (bool) ($CONFIG['SHOW_CLIENT_IP'] ?? true);

$API_BASE = (string) $CONFIG['API_BASE'];
$API_SHARED_SECRET = (string) ($CONFIG['INTERNAL_SHARED_SECRET'] ?? '');
$API_INSECURE_SKIP_VERIFY = (bool) ($CONFIG['API_INSECURE_SKIP_VERIFY'] ?? false);
if (stripos($API_BASE, 'https://') !== 0) {
    $API_INSECURE_SKIP_VERIFY = false; // option sans effet en HTTP, neutralisée explicitement
}

$HCAPTCHA_ENABLED = (bool) ($CONFIG['HCAPTCHA_ENABLED'] ?? true);
$HCAPTCHA_SITEKEY = (string) ($CONFIG['HCAPTCHA_SITEKEY'] ?? '');
$HCAPTCHA_SECRET = (string) ($CONFIG['HCAPTCHA_SECRET'] ?? '');

$RL_FILE_ENABLED = (bool) ($CONFIG['RL_FILE_ENABLED'] ?? true);

$DEFAULT_PAGE_SIZE = (int) ($CONFIG['ADMIN_LIST_PAGE_SIZE'] ?? 50);

$LOGIN_RL_WINDOW = (int) ($CONFIG['LOGIN_RL_WINDOW'] ?? 1200);
$LOGIN_RL_MAX = (int) ($CONFIG['LOGIN_RL_MAX'] ?? 10);
$LOGIN_RL_BLOCK = (int) ($CONFIG['LOGIN_RL_BLOCK'] ?? 1200);
$LOGIN_RL_BACKEND = (string) ($CONFIG['LOGIN_RL_BACKEND'] ?? 'auto');

// Rate limit fichier (fenêtre 30 min, blocage à 15 échecs, historique par IP)
$RL_FILE_DIR = !empty($CONFIG['RL_LOG_DIR']) ? (string) $CONFIG['RL_LOG_DIR'] : (__DIR__ . '/rl_logs');
$RL_WINDOW_SECONDS = (int) ($CONFIG['RL_WINDOW_SECONDS'] ?? 1800);   // 30 min
$RL_BLOCK_AFTER = (int) ($CONFIG['RL_BLOCK_AFTER'] ?? 15);
$RL_WARN_AFTER = (int) ($CONFIG['RL_WARN_AFTER'] ?? 5);


// Recherches groupes — scopes distincts
$groupQueryGlobal = '';
$groupResultsGlobal = [];
$groupsHasMoreGlobal = false;

// --- DEBUG – toggle persistant via session ---
// ?debug=1 active, ?debug=0 désactive
// --- DEBUG — admin-only ---
if (isset($_GET['debug']) && !empty($_SESSION['is_admin'])) {
    $_SESSION['_debug'] = ($_GET['debug'] === '1');
}
$DEBUG = !empty($_SESSION['_debug']) && !empty($_SESSION['is_admin']);

function scrub_sensitive($v)
{
    $maskKeys = '/(?:pass|password|secret|token|captcha|authorization|cookie|set-cookie|X-Internal-Auth)/i';
    if (is_array($v)) {
        $out = [];
        foreach ($v as $k => $val) {
            $out[$k] = (is_string($k) && preg_match($maskKeys, $k)) ? '***' : scrub_sensitive($val);
        }
        return $out;
    }
    return $v;
}

function dd($label, $value)
{
    global $DEBUG;
    if (!$DEBUG)
        return;
    $safe = scrub_sensitive($value);
    $dump = $label . ":\n" . var_export($safe, true) . "\n\n";
    if ($_SERVER['REQUEST_METHOD'] === 'POST')
        error_log($dump);
    else
        echo "<pre style='background:#111;color:#eee;padding:10px;border:1px solid #444;border-radius:8px;white-space:pre-wrap'>"
            . htmlspecialchars($dump, ENT_QUOTES) . "</pre>";
}

/* ================================
   Utilitaires
=================================== */
const INTRANET_KEY_COOKIE = 'Intra-Sync-Key';

function intra_sync_key_generate(): string
{
    return bin2hex(random_bytes(32));
}

function intra_sync_key_cookie_params(int $sessionLifetime): array
{
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    return [
        'expires' => time() + $sessionLifetime,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
}

function intra_sync_invalidate(): void
{
    $_SESSION = [];
    if (session_id() !== '') {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 3600,
            'path' => $params['path'] ?? '/',
            'secure' => $params['secure'] ?? false,
            'httponly' => $params['httponly'] ?? true,
            'samesite' => $params['samesite'] ?? 'Lax',
        ]);
    }
    setcookie(INTRANET_KEY_COOKIE, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_destroy();
}
function ip_in_cidr_list(string $ip, array $cidrs): bool
{
    foreach ($cidrs as $c) {
        if ($c === '')
            continue;
        if (strpos($c, '/') === false) {
            if ($ip === $c)
                return true;
            continue;
        }
        [$subnet, $mask] = explode('/', $c, 2);
        if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($subnet, FILTER_VALIDATE_IP))
            continue;
        $mask = (int) $mask;
        if (strpos($ip, ':') !== false) { // IPv6
            $ipBin = inet_pton($ip);
            $subBin = inet_pton($subnet);
            $bytes = intdiv($mask, 8);
            $bits = $mask % 8;
            if ($bytes && substr($ipBin, 0, $bytes) !== substr($subBin, 0, $bytes))
                continue;
            if ($bits) {
                $b1 = ord($ipBin[$bytes]) & (0xFF << (8 - $bits));
                $b2 = ord($subBin[$bytes]) & (0xFF << (8 - $bits));
                if ($b1 !== $b2)
                    continue;
            }
            return true;
        } else { // IPv4
            $ipLong = ip2long($ip);
            $subLong = ip2long($subnet);
            $maskLong = -1 << (32 - $mask);
            if (($ipLong & $maskLong) === ($subLong & $maskLong))
                return true;
        }
    }
    return false;
}

function client_ip(): string
{
    global $TRUSTED_PROXIES, $CLIENT_IP_HEADER;
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $headerKey = 'HTTP_' . strtoupper(str_replace('-', '_', $CLIENT_IP_HEADER));
    $xff = $_SERVER[$headerKey] ?? '';

    // On ne fait confiance à l’en-tête que si la requête vient d’un proxy “de confiance”
    $trusted = $remote && (in_array($remote, $TRUSTED_PROXIES, true) || ip_in_cidr_list($remote, $TRUSTED_PROXIES));

    if ($trusted && $xff) {
        // Chaîne "client, proxy1, proxy2" -> on prend le premier IP valide non proxy
        foreach (array_map('trim', explode(',', $xff)) as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                if (!$TRUSTED_PROXIES || (!in_array($ip, $TRUSTED_PROXIES, true) && !ip_in_cidr_list($ip, $TRUSTED_PROXIES))) {
                    return $ip;
                }
            }
        }
    }
    return $remote ?: 'unknown';
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
function csrf_ok(?string $t): bool
{
    return is_string($t) && hash_equals($_SESSION['csrf_token'] ?? '', $t);
}
function verifyCaptcha(string $token, string $secret, string $ip): bool
{
    if ($token === '' || $secret === '')
        return false;
    $ch = curl_init('https://hcaptcha.com/siteverify');
    $post = http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $post,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    $j = json_decode($res, true);
    return is_array($j) && !empty($j['success']);
}

function api_call_context(string $endpoint): string
{
    $path = strtolower((string) parse_url($endpoint, PHP_URL_PATH));
    $isAdmin = !empty($_SESSION['is_admin']);

    $userInfo = $_SESSION['user_info'] ?? [];
    $memberOf = $userInfo['memberOf'] ?? [];
    $memberOf = is_array($memberOf) ? $memberOf : ($memberOf ? [$memberOf] : []);
    $userCnGroups = ad_groups_to_cn_list($memberOf);

    $cfg = $GLOBALS['CONFIG'] ?? [];
    $ADM_USER_GROUPS = $cfg['ADM_USER_GROUPS'] ?? [];
    $ADM_DOMAIN_GROUPS = $cfg['ADM_DOMAIN_GROUPS'] ?? [];
    if (is_string($ADM_USER_GROUPS))
        $ADM_USER_GROUPS = array_values(array_filter(array_map('trim', explode(',', $ADM_USER_GROUPS)), 'strlen'));
    if (is_string($ADM_DOMAIN_GROUPS))
        $ADM_DOMAIN_GROUPS = array_values(array_filter(array_map('trim', explode(',', $ADM_DOMAIN_GROUPS)), 'strlen'));

    $canUserAdmin = $isAdmin || (is_array($ADM_USER_GROUPS) && count($ADM_USER_GROUPS) > 0 && hasGroup($userCnGroups, $ADM_USER_GROUPS));
    $canDomainAdmin = $isAdmin || (is_array($ADM_DOMAIN_GROUPS) && count($ADM_DOMAIN_GROUPS) > 0 && hasGroup($userCnGroups, $ADM_DOMAIN_GROUPS));

    if ($path === '/auth')
        return 'intranet-login';
    if (str_starts_with($path, '/explorer/') || $path === '/tree' || $path === '/meta/ad' || $path === '/groups'
        || str_starts_with($path, '/admin/ou/') || $path === '/admin/creategroup' || $path === '/admin/deletegroup') {
        return $canDomainAdmin ? 'admin-domain' : 'self-service';
    }
    if ($path === '/admin/changepassword') {
        if ($canDomainAdmin)
            return 'admin-domain';
        if ($canUserAdmin)
            return 'admin-user';
        return 'self-service';
    }
    if (str_starts_with($path, '/admin/')) {
        if ($canDomainAdmin)
            return 'admin-domain';
        if ($canUserAdmin)
            return 'admin-user';
        return 'self-service';
    }
    if (str_starts_with($path, '/user/') || str_starts_with($path, '/users'))
        return ($canUserAdmin || $canDomainAdmin) ? 'admin-user' : 'self-service';
    return 'self-service';
}

function sanitize_tool_instructions_html(string $html): string
{
    $html = trim($html);
    if ($html === '')
        return '';

    $allowedTags = ['p', 'br', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li', 'a', 'img', 'div', 'span', 'code', 'pre', 'blockquote'];
    $allowedAttrs = [
        'a' => ['href', 'title', 'target', 'rel'],
        'img' => ['src', 'alt', 'title', 'width', 'height', 'loading'],
        'div' => ['class'],
        'span' => ['class'],
        'p' => ['class'],
        'ul' => ['class'],
        'ol' => ['class'],
        'li' => ['class'],
        'pre' => ['class'],
        'code' => ['class'],
        'blockquote' => ['class'],
    ];

    if (!class_exists('DOMDocument')) {
        return strip_tags($html, '<p><br><strong><b><em><i><u><ul><ol><li><a><img><div><span><code><pre><blockquote>');
    }

    $prev = libxml_use_internal_errors(true);
    $dom = new DOMDocument('1.0', 'UTF-8');
    $wrapperId = '__inst_root__';
    $ok = $dom->loadHTML(
        '<?xml encoding="UTF-8"><div id="' . $wrapperId . '">' . $html . '</div>',
        LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
    );
    if (!$ok) {
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        return '';
    }

    $root = $dom->getElementById($wrapperId);
    if (!$root) {
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        return '';
    }

    $sanitizeNode = function (DOMNode $node) use (&$sanitizeNode, $allowedTags, $allowedAttrs) {
        for ($child = $node->firstChild; $child !== null;) {
            $next = $child->nextSibling;
            if ($child instanceof DOMElement) {
                $tag = strtolower($child->tagName);
                if (!in_array($tag, $allowedTags, true)) {
                    while ($child->firstChild) {
                        $node->insertBefore($child->firstChild, $child);
                    }
                    $node->removeChild($child);
                    $child = $next;
                    continue;
                }

                $keepAttrs = $allowedAttrs[$tag] ?? [];
                $toRemove = [];
                if ($child->hasAttributes()) {
                    foreach ($child->attributes as $attr) {
                        $name = strtolower($attr->name);
                        $val = trim((string) $attr->value);
                        if (str_starts_with($name, 'on')) {
                            $toRemove[] = $attr->name;
                            continue;
                        }
                        if (!in_array($name, $keepAttrs, true)) {
                            $toRemove[] = $attr->name;
                            continue;
                        }
                        if (($name === 'href' || $name === 'src')
                            && !preg_match('#^(https?:|mailto:|tel:|/|#|data:image/)#i', $val)) {
                            $toRemove[] = $attr->name;
                            continue;
                        }
                        if ($name === 'target' && !in_array(strtolower($val), ['_blank', '_self'], true)) {
                            $toRemove[] = $attr->name;
                            continue;
                        }
                    }
                }
                foreach ($toRemove as $n) {
                    $child->removeAttribute($n);
                }
                if ($tag === 'a' && strtolower((string) $child->getAttribute('target')) === '_blank') {
                    $child->setAttribute('rel', 'noopener noreferrer');
                }
                if ($tag === 'img' && !$child->hasAttribute('loading')) {
                    $child->setAttribute('loading', 'lazy');
                }
            }
            $sanitizeNode($child);
            $child = $next;
        }
    };
    $sanitizeNode($root);

    $out = '';
    foreach ($root->childNodes as $n) {
        $out .= $dom->saveHTML($n);
    }
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    return trim((string) $out);
}

/**
 * Appel API robuste
 * @return array{error:bool,httpCode:int,message:string,data:mixed,headers?:array}
 */
function callApi(string $method, string $endpoint, ?array $data = null, bool $withHeaders = false): array
{
    global $API_BASE, $API_SHARED_SECRET, $API_INSECURE_SKIP_VERIFY, $DEBUG;
    $url = rtrim($API_BASE, '/') . $endpoint;
    if ($DEBUG) {
        error_log("[callApi] --> {$method} {$url}");
        if (!is_null($data))
            error_log("[callApi] payload: " . json_encode(scrub_sensitive($data), JSON_UNESCAPED_UNICODE));
    }
    $url = rtrim($API_BASE, '/') . $endpoint;
    $ch = curl_init($url);
    $headers = ['Content-Type: application/json'];
    $headers[] = 'X-App-Context: ' . api_call_context($endpoint);
    if (!empty($_SESSION['username'])) {
        $safeUser = preg_replace('/[\r\n]+/', '', (string) $_SESSION['username']);
        $headers[] = 'X-App-User: ' . $safeUser;
    }
    if ($API_SHARED_SECRET !== '')
        $headers[] = 'X-Internal-Auth: ' . $API_SHARED_SECRET;
    $opts = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 25,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_FAILONERROR => false,
        CURLOPT_HEADER => $withHeaders ? 1 : 0,
    ];
    if (!is_null($data))
        $opts[CURLOPT_POSTFIELDS] = json_encode($data, JSON_UNESCAPED_UNICODE);
    if (stripos($url, 'https://') === 0 && $API_INSECURE_SKIP_VERIFY) {
        $opts[CURLOPT_SSL_VERIFYPEER] = false;
        $opts[CURLOPT_SSL_VERIFYHOST] = 0;
    }
    curl_setopt_array($ch, $opts);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false) {
        $err = curl_error($ch);
        curl_close($ch);
        return ['error' => true, 'httpCode' => $httpCode ?: 0, 'message' => "Erreur réseau: $err", 'data' => null];
    }

    $respHeaders = [];
    if ($withHeaders) {
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headerRaw = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        foreach (explode("\r\n", trim($headerRaw)) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $respHeaders[strtolower($k)] = $v;
            }
        }
        $response = $body;
    }
    curl_close($ch);

    $decoded = json_decode($response, true);
    if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => true, 'httpCode' => $httpCode, 'message' => 'Réponse JSON invalide', 'data' => null];
    }
    $isError = ($httpCode < 200 || $httpCode >= 300);
    $message = '';
    if (is_array($decoded)) {
        if (isset($decoded['error']) && is_string($decoded['error']))
            $message = $decoded['error'];
        elseif (isset($decoded['message']) && is_string($decoded['message']))
            $message = $decoded['message'];
        elseif (isset($decoded['serverError']) && is_string($decoded['serverError']))
            $message = $decoded['serverError'];
    }
    $res = ['error' => $isError, 'httpCode' => $httpCode, 'message' => $message, 'data' => $decoded];
    if ($withHeaders)
        $res['headers'] = $respHeaders;
    if ($DEBUG) {
        error_log("[callApi] <-- http {$httpCode}; message=" . ($message ?? ''));
        // évite de loguer tout le JSON potentiellement volumineux
        $keys = is_array($decoded) ? implode(',', array_slice(array_keys($decoded), 0, 12)) : '';
        error_log("[callApi] data_keys: {$keys}");
    }

    return $res;
}
function api_err_detail(array $r, string $fallback): string
{
    $detail = '';
    if (!empty($r['message']))
        $detail = $r['message'];
    elseif (is_array($r['data'] ?? null) && !empty($r['data']['serverError']))
        $detail = (string) $r['data']['serverError'];
    return $fallback . ($detail ? " : " . $detail : "");
}
function normalizePhone(string $raw): string|false
{
    $clean = preg_replace('/[^\d\+]/', '', $raw ?? '');
    if ($clean === null)
        return false;
    if (str_starts_with($clean, '+'))
        return preg_match('/^\+33[1-9]\d{8}$/', $clean) ? $clean : false;
    $digits = preg_replace('/\D+/', '', $clean);
    if ($digits === null)
        return false;
    if (strlen($digits) === 10 && $digits[0] === '0') {
        $e = '+33' . substr($digits, 1);
        return preg_match('/^\+33[1-9]\d{8}$/', $e) ? $e : false;
    }
    if (strlen($digits) === 11 && substr($digits, 0, 2) === '33') {
        $e = '+' . $digits;
        return preg_match('/^\+33[1-9]\d{8}$/', $e) ? $e : false;
    }
    if (strlen($digits) === 12 && substr($digits, 0, 4) === '0033') {
        $e = '+' . substr($digits, 2);
        return preg_match('/^\+33[1-9]\d{8}$/', $e) ? $e : false;
    }
    return false;
}
function hasGroup(array $userGroups, array $requiredNamesOrDns): bool
{
    if (!$requiredNamesOrDns)
        return true;
    $norm = array_map('strtolower', $userGroups);
    foreach ($requiredNamesOrDns as $g) {
        $g = strtolower($g);
        foreach ($norm as $ug) {
            if ($ug === $g)
                return true;
            if (str_starts_with($ug, 'cn=') && preg_match('/^cn=([^,]+)/i', $ug, $m)) {
                if (strtolower($m[1]) === $g)
                    return true;
            }
        }
    }
    return false;
}

function ad_groups_to_cn_list(array $groups): array
{
    // Retourne la liste des CN (en minuscules) à partir de DN complets ou noms simples
    $out = [];
    foreach ($groups as $g) {
        if (!is_string($g) || $g === '')
            continue;
        $v = $g;
        if (stripos($v, 'CN=') === 0 && preg_match('/^CN=([^,]+)/i', $v, $m)) {
            $v = $m[1];
        }
        $out[] = mb_strtolower(trim($v));
    }
    return array_values(array_unique($out));
}

/* ==== Helpers sélection OU (via /tree) ==== */
function extract_root_dn(string $dn): string
{
    if (preg_match_all('/DC=[^,]+/i', $dn, $m) && !empty($m[0])) {
        return implode(',', $m[0]);
    }
    return '';
}
function fetch_ou_tree(?string $baseDn = ''): array
{
    $q = '/tree?depth=6&includeLeaves=false&maxChildren=2000';
    if ($baseDn)
        $q .= '&baseDn=' . rawurlencode($baseDn);
    $r = callApi('GET', $q);
    if ($r['error'] || !is_array($r['data']))
        return [];
    return $r['data']; // { baseDn, nodes: [...] }
}
function fetch_ad_meta(): array
{
    $r = callApi('GET', '/meta/ad');
    if ($r['error'] || !is_array($r['data']))
        return [];
    return $r['data'];
}
function fetch_ad_explorer_tree(?string $baseDn = ''): array
{
    $q = '/tree?depth=6&includeLeaves=true&maxChildren=2000';
    if ($baseDn)
        $q .= '&baseDn=' . rawurlencode($baseDn);
    $r = callApi('GET', $q);
    if ($r['error'] || !is_array($r['data']))
        return [];
    return $r['data'];
}
function flatten_ou_nodes(array $treeOrNodes, string $prefix = ''): array
{
    $out = [];
    $nodes = $treeOrNodes['nodes'] ?? $treeOrNodes;
    if (!is_array($nodes))
        return $out;

    foreach ($nodes as $n) {
        $dn = (string) ($n['dn'] ?? '');
        $name = (string) ($n['name'] ?? ($dn ?: ''));
        $typ = strtolower((string) ($n['type'] ?? ''));
        $desc = (string) ($n['description'] ?? $n['desc'] ?? ''); // ⬅️ nouveau

        $isOu = $typ === 'ou' || $typ === 'domain' || str_starts_with(strtoupper($dn), 'OU=') && !str_contains(strtoupper($dn), 'DOMAIN CONTROLLER');

        $isContainer = $typ === 'container'
            || (str_starts_with(strtoupper($dn), 'CN=')
                && preg_match('/^CN=(Users|Builtin|Managed Service Accounts|Program Data|System)/i', $dn));
        $kind = $typ === 'domain' ? 'domain' : ($isOu ? 'ou' : ($isContainer ? 'container' : 'other'));

        if ($dn !== '' && in_array($kind, ['ou', 'container', 'domain'], true)) {
            $out[] = ['dn' => $dn, 'label' => trim($prefix . $name), 'kind' => $kind, 'desc' => $desc]; // ⬅️ desc
        }
        if (!empty($n['children']) && is_array($n['children'])) {
            $out = array_merge($out, flatten_ou_nodes($n['children'], $prefix . '— '));
        }
    }
    return $out;
}

function render_ad_tree_nodes(array $nodes): void
{
    if (!$nodes) {
        return;
    }
    echo '<ul class="ad-tree-list">';
    foreach ($nodes as $n) {
        $dn = htmlspecialchars((string)($n['dn'] ?? ''), ENT_QUOTES);
        $name = htmlspecialchars((string)($n['name'] ?? ($n['dn'] ?? '')), ENT_QUOTES);
        $type = strtolower((string)($n['type'] ?? 'other'));
        $typeEsc = htmlspecialchars($type, ENT_QUOTES);
        $samEsc = htmlspecialchars((string) ($n['samAccountName'] ?? ''), ENT_QUOTES);
        $desc = (string) ($n['description'] ?? '');
        $descEsc = htmlspecialchars($desc, ENT_QUOTES);
        $objectClasses = $n['objectClasses'] ?? [];
        if (!is_array($objectClasses))
            $objectClasses = [];
        $ocLower = array_map(static fn($v) => mb_strtolower((string) $v), $objectClasses);
        if (in_array('computer', $ocLower, true)) {
            // Priorité absolue : si la classe computer est présente, c'est un PC.
            $type = 'computer';
            $typeEsc = htmlspecialchars($type, ENT_QUOTES);
        } elseif ($type === 'other') {
            $dnRaw = (string) ($n['dn'] ?? '');
            $dnUp = strtoupper($dnRaw);
            if (in_array('group', $ocLower, true)) {
                $type = 'group';
            } elseif (in_array('inetorgperson', $ocLower, true)) {
                $type = 'inetorgperson';
            } elseif (in_array('computer', $ocLower, true)) {
                $type = 'computer';
            } elseif (in_array('user', $ocLower, true)) {
                $type = 'user';
            } elseif (in_array('organizationalunit', $ocLower, true) || str_starts_with($dnUp, 'OU=')) {
                $type = 'ou';
            } elseif (in_array('container', $ocLower, true) || str_starts_with($dnUp, 'CN=')) {
                $type = 'container';
            } elseif (str_starts_with($dnUp, 'DC=')) {
                $type = 'domain';
            }
            $typeEsc = htmlspecialchars($type, ENT_QUOTES);
        }
        $classesEsc = htmlspecialchars(implode(', ', array_map('strval', $objectClasses)), ENT_QUOTES);
        $labelType = $type === 'user' ? 'Utilisateur'
            : ($type === 'group' ? 'Groupe'
            : ($type === 'computer' ? 'Ordinateur'
            : ($type === 'inetorgperson' ? 'Personne'
            : ($type === 'ou' || $type === 'domain' || $type === 'container' ? 'Conteneur' : ucfirst($type)))));

        echo '<li>';
        echo '<button type="button" class="ad-node" data-dn="' . $dn . '" data-type="' . $typeEsc . '" data-name="' . $name . '" data-sam="' . $samEsc . '" data-description="' . $descEsc . '" data-classes="' . $classesEsc . '">';
        echo '<span class="ad-node-dot"></span>';
        echo '<span class="ad-node-label">' . $name . '</span>';
        echo '<span class="badge subtle">' . htmlspecialchars($labelType, ENT_QUOTES) . '</span>';
        echo '</button>';

        if (!empty($n['children']) && is_array($n['children'])) {
            render_ad_tree_nodes($n['children']);
        }
        echo '</li>';
    }
    echo '</ul>';
}

function sort_ad_tree_nodes(array $nodes, string $sortBy = 'name', string $sortDir = 'asc'): array
{
    $dir = strtolower($sortDir) === 'desc' ? -1 : 1;
    usort($nodes, function (array $a, array $b) use ($sortBy, $dir): int {
        $av = '';
        $bv = '';
        if ($sortBy === 'type') {
            $av = mb_strtolower((string) ($a['type'] ?? 'other'));
            $bv = mb_strtolower((string) ($b['type'] ?? 'other'));
        } elseif ($sortBy === 'dn') {
            $av = mb_strtolower((string) ($a['dn'] ?? ''));
            $bv = mb_strtolower((string) ($b['dn'] ?? ''));
        } else {
            $av = mb_strtolower((string) ($a['name'] ?? ($a['dn'] ?? '')));
            $bv = mb_strtolower((string) ($b['name'] ?? ($b['dn'] ?? '')));
        }
        $cmp = $av <=> $bv;
        return $cmp * $dir;
    });
    foreach ($nodes as &$n) {
        if (!empty($n['children']) && is_array($n['children'])) {
            $n['children'] = sort_ad_tree_nodes($n['children'], $sortBy, $sortDir);
        }
    }
    unset($n);
    return $nodes;
}

function tree_node_matches_query(array $n, string $q, string $typeFilter): bool
{
    $q = mb_strtolower(trim($q));
    $type = mb_strtolower((string) ($n['type'] ?? 'other'));
    $ocLower = array_map(
        static fn($v) => mb_strtolower((string) $v),
        (array) ($n['objectClasses'] ?? [])
    );

    if ($typeFilter !== '' && $typeFilter !== 'all') {
        $typeMatches = match ($typeFilter) {
            // En AD réel, beaucoup d'utilisateurs portent aussi la classe inetOrgPerson.
            // Les objets computer héritent souvent de user -> on les exclut explicitement ici.
            'user' => (
                in_array($type, ['user', 'inetorgperson'], true)
                || (
                    !in_array($type, ['computer', 'group', 'ou', 'container', 'domain'], true)
                    && in_array('computer', $ocLower, true) === false
                    && (
                        in_array('user', $ocLower, true)
                        || in_array('inetorgperson', $ocLower, true)
                    )
                )
            ),
            'inetorgperson' => $type === 'inetorgperson' || in_array('inetorgperson', $ocLower, true),
            'ou' => $type === 'ou' || in_array('organizationalunit', $ocLower, true),
            'container' => $type === 'container' || in_array('container', $ocLower, true) || in_array('builtindomain', $ocLower, true),
            'group' => $type === 'group' || in_array('group', $ocLower, true),
            'computer' => $type === 'computer' || in_array('computer', $ocLower, true),
            'domain' => $type === 'domain' || in_array('domaindns', $ocLower, true),
            default => $type === $typeFilter,
        };
        if (!$typeMatches) {
            return false;
        }
    }
    if ($q === '') {
        return true;
    }
    $hay = mb_strtolower((string) (($n['name'] ?? '') . ' ' . ($n['dn'] ?? '') . ' ' . implode(' ', (array) ($n['objectClasses'] ?? []))));
    return str_contains($hay, $q);
}

function filter_tree_with_ancestors(array $nodes, string $query, string $typeFilter): array
{
    $out = [];
    foreach ($nodes as $n) {
        $children = [];
        if (!empty($n['children']) && is_array($n['children'])) {
            $children = filter_tree_with_ancestors($n['children'], $query, $typeFilter);
        }
        $match = tree_node_matches_query($n, $query, $typeFilter);
        if ($match || !empty($children)) {
            $copy = $n;
            $copy['children'] = $children;
            $copy['hasChildren'] = !empty($children) || !empty($n['hasChildren']);
            $out[] = $copy;
        }
    }
    return $out;
}

// --- Flash messages + PRG ---
function flash_set(string $area, string $level, string $msg): void
{
    $_SESSION['_flash'] = ['area' => $area, 'level' => $level, 'msg' => $msg];
}
function flash_take(): ?array
{
    $f = $_SESSION['_flash'] ?? null;
    unset($_SESSION['_flash']);
    return $f;
}
function redirect_get(array $qs = [], ?string $tab = null, ?string $focus = null): void
{
    $url = 'intranet.php';
    if ($focus)
        $qs['af'] = $focus; // <-- paramètre lu par JS pour autoscroll
    if ($qs)
        $url .= '?' . http_build_query($qs);
    if ($tab)
        $url .= '#tab-' . $tab;
    header('Cache-Control: no-store');
    header('Location: ' . $url, true, 303); // See Other (PRG)
    exit;
}

/* ==== Anti brute-force login (rate limit) ==== */
function rl_backend_is_apcu(): bool
{
    global $LOGIN_RL_BACKEND;
    if ($LOGIN_RL_BACKEND === 'apcu')
        return function_exists('apcu_fetch');
    if ($LOGIN_RL_BACKEND === 'session')
        return false;
    // auto
    return function_exists('apcu_fetch');
}
function rl_key(string $user, string $ip): string
{
    // user normalisé pour éviter l’énumération sensible à la casse
    $u = mb_strtolower(trim($user));
    return 'rl:' . sha1($u . '|' . $ip);
}
function rl_load(string $user, string $ip): array
{
    $k = rl_key($user, $ip);
    if (rl_backend_is_apcu()) {
        $v = apcu_fetch($k);
        return is_array($v) ? $v : ['count' => 0, 'first' => time(), 'blocked_until' => 0];
    } else {
        $v = $_SESSION['_rl'][$k] ?? null;
        return is_array($v) ? $v : ['count' => 0, 'first' => time(), 'blocked_until' => 0];
    }
}
function rl_save(string $user, string $ip, array $state, int $ttl): void
{
    $k = rl_key($user, $ip);
    if (rl_backend_is_apcu()) {
        apcu_store($k, $state, $ttl);
    } else {
        $_SESSION['_rl'][$k] = $state;
    }
}
function rl_reset(string $user, string $ip): void
{
    $k = rl_key($user, $ip);
    if (rl_backend_is_apcu()) {
        apcu_delete($k);
    } else {
        unset($_SESSION['_rl'][$k]);
    }
}
/**
 * Vérifie l’état (bloqué ?), met à jour la fenêtre si expirée.
 * Retourne ['blocked'=>bool, 'wait'=>int, 'state'=>array]
 */
function rl_check(string $user, string $ip): array
{
    global $LOGIN_RL_WINDOW;
    $now = time();
    $st = rl_load($user, $ip);
    // purge fenêtre si dépassée
    if (($now - ($st['first'] ?? $now)) > $LOGIN_RL_WINDOW) {
        $st = ['count' => 0, 'first' => $now, 'blocked_until' => 0];
    }
    if (($st['blocked_until'] ?? 0) > $now) {
        return ['blocked' => true, 'wait' => ($st['blocked_until'] - $now), 'state' => $st];
    }
    return ['blocked' => false, 'wait' => 0, 'state' => $st];
}
/**
 * À appeler sur tentative avant /auth : incrémente le compteur (sans bloquer prématurément).
 * À appeler aussi sur échec /auth pour déclencher le blocage si seuil dépassé.
 * Retourne l’état à jour.
 */
function rl_touch(string $user, string $ip, bool $failed): array
{
    global $LOGIN_RL_WINDOW, $LOGIN_RL_MAX, $LOGIN_RL_BLOCK;
    $now = time();
    $st = rl_load($user, $ip);
    if (($now - ($st['first'] ?? $now)) > $LOGIN_RL_WINDOW) {
        $st = ['count' => 0, 'first' => $now, 'blocked_until' => 0];
    }
    // On compte la tentative (on incrémente toujours sur tentative, et on re-évalue sur échec)
    $st['count'] = (int) ($st['count'] ?? 0) + 1;

    // Si échec, on bloque si on a dépassé le seuil
    if ($failed && $st['count'] > $LOGIN_RL_MAX) {
        $st['blocked_until'] = $now + $LOGIN_RL_BLOCK;
    }

    // TTL de stockage = max(window, block) pour couvrir les 2 cas
    rl_save($user, $ip, $st, max($LOGIN_RL_WINDOW, $LOGIN_RL_BLOCK));
    return $st;
}

/* ==== Rate limit fichier (fenêtre glissante 30 min, blocage IP à 15 échecs, historique par IP) ==== */
function rl_file_ensure_dir(): void
{
    global $RL_FILE_DIR;
    if (!is_dir($RL_FILE_DIR)) {
        @mkdir($RL_FILE_DIR, 0750, true);
    }
}

/** Retourne le chemin du fichier historique pour une IP (nom = md5 pour éviter caractères spéciaux). */
function rl_file_path(string $ip): string
{
    global $RL_FILE_DIR;
    rl_file_ensure_dir();
    return $RL_FILE_DIR . '/' . md5($ip) . '.log';
}

/** Préfixe /64 pour IPv6 (16 caractères hex), null pour IPv4. */
function rl_ipv6_prefix_64(string $ip): ?string
{
    if (strpos($ip, ':') === false) {
        return null;
    }
    $bin = @inet_pton($ip);
    if ($bin === false || strlen($bin) !== 16) {
        return null;
    }
    return bin2hex(substr($bin, 0, 8));
}

/** Fichier des IP/prefixes bloqués. */
function rl_file_blocked_path(): string
{
    global $RL_FILE_DIR;
    rl_file_ensure_dir();
    return $RL_FILE_DIR . '/blocked.txt';
}

/** Vérifie si l’IP (ou son préfixe /64 pour IPv6) est bloquée. */
function rl_file_is_blocked(string $ip): bool
{
    $path = rl_file_blocked_path();
    if (!is_file($path)) {
        return false;
    }
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) {
        return false;
    }
    $prefix = rl_ipv6_prefix_64($ip);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        if (strpos($line, 'v6:') === 0) {
            if ($prefix !== null && $prefix === substr($line, 3, 16)) {
                return true;
            }
        } else {
            if ($line === $ip) {
                return true;
            }
        }
    }
    return false;
}

/** Ajoute l’IP à la liste des bloquées (IPv4 = IP exacte, IPv6 = préfixe /64). */
function rl_file_add_blocked(string $ip): void
{
    $path = rl_file_blocked_path();
    $prefix = rl_ipv6_prefix_64($ip);
    $entry = $prefix !== null ? 'v6:' . $prefix : $ip;
    $content = '';
    if (is_file($path)) {
        $content = file_get_contents($path);
    }
    if (strpos($content, $entry) !== false) {
        return;
    }
    file_put_contents($path, $entry . "\n", LOCK_EX | FILE_APPEND);
}

/** Enregistre un échec de connexion (uniquement en cas d’échec : captcha, mauvais user/mdp). Fichier : 1re ligne = IP, puis timestamp\tusername. */
function rl_file_log_failure(string $ip, string $username = ''): void
{
    global $RL_FILE_DIR;
    $path = rl_file_path($ip);
    $ts = gmdate('Y-m-d\TH:i:s\Z');
    $line = $ts . "\t" . $username . "\n";
    if (!is_file($path)) {
        rl_file_ensure_dir();
        file_put_contents($path, $ip . "\n" . $line, LOCK_EX);
    } else {
        file_put_contents($path, $line, LOCK_EX | FILE_APPEND);
    }
}

/** Compte les échecs dans la fenêtre glissante (dernières RL_WINDOW_SECONDS secondes). */
function rl_file_count_sliding(string $ip): int
{
    global $RL_WINDOW_SECONDS;
    $path = rl_file_path($ip);
    if (!is_file($path)) {
        return 0;
    }
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines || count($lines) < 2) {
        return 0;
    }
    $cutoff = time() - $RL_WINDOW_SECONDS;
    $count = 0;
    for ($i = 1; $i < count($lines); $i++) {
        $parts = explode("\t", $lines[$i], 2);
        $ts = strtotime($parts[0] ?? '');
        if ($ts !== false && $ts >= $cutoff) {
            $count++;
        }
    }
    return $count;
}

/* ==== Helpers DN / validations OU & expiration ==== */
function dn_is_descendant(string $parent, string $candidate): bool
{
    $p = trim($parent, " \t\n\r\0\x0B,");
    $c = trim($candidate, " \t\n\r\0\x0B,");
    if ($p === '' || $c === '' || strcasecmp($p, $c) === 0)
        return false;
    // Un enfant AD se termine par ",<DN du parent>"
    return (bool) preg_match('/,' . preg_quote($p, '/') . '$/i', $c);
}
function ou_name_is_valid(string $name): bool
{
    // Nom simple, pas de '=' ni ',' et pas d'espaces en bord
    if ($name === '' || trim($name) !== $name)
        return false;
    if (strpbrk($name, '=,') !== false)
        return false;
    return mb_strlen($name) <= 64;
}
/** Construit un ISO8601 UTC "YYYY-MM-DDTHH:MM:SSZ" depuis champs date/heure, ou null si vide */
function build_iso_expiry(?string $date, ?string $time): ?string
{
    $date = trim((string) $date);
    $time = trim((string) $time);
    if ($date === '')
        return null;
    if ($time === '')
        $time = '00:00';
    $ts = strtotime($date . ' ' . $time . ' UTC');
    return $ts ? gmdate('c', $ts) : null; // ex: 2025-01-31T00:00:00+00:00
}
/** Lit une éventuelle expiration renvoyée par l’API sous différents noms */
function user_expiry_label(?array $u): string
{
    if (empty($u))
        return '—';
    $v = $u['expiresAt'] ?? $u['accountExpiresIso'] ?? $u['accountExpires'] ?? null;
    if (!$v)
        return '—';
    if (is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2}T/', $v))
        return $v;
    return is_string($v) ? $v : '—';
}

function user_expiry_values(?array $u, string $tz = 'Europe/Paris'): array
{
    if (empty($u))
        return ['isNever' => true, 'date' => '', 'time' => '', 'iso' => ''];

    $raw = $u['expiresAt'] ?? $u['accountExpiresIso'] ?? $u['accountExpires'] ?? null;
    if (!$raw)
        return ['isNever' => true, 'date' => '', 'time' => '', 'iso' => ''];

    if (!is_string($raw) || !preg_match('/^\d{4}-\d{2}-\d{2}T/', $raw)) {
        return ['isNever' => false, 'date' => '', 'time' => '', 'iso' => (string) $raw];
    }

    try {
        $dt = new DateTime($raw);
        $dt->setTimezone(new DateTimeZone($tz));
        return ['isNever' => false, 'date' => $dt->format('Y-m-d'), 'time' => $dt->format('H:i'), 'iso' => $raw];
    } catch (Throwable $e) {
        return ['isNever' => false, 'date' => '', 'time' => '', 'iso' => (string) $raw];
    }
}


/* ================================
   DB (MySQL ou SQLite) + Tools bootstrap
=================================== */
function app_pdo(): PDO
{
    static $pdo = null;
    if ($pdo)
        return $pdo;

    $CFG = @include __DIR__ . '/config-intranet.php';
    if (!is_array($CFG)) {
        throw new RuntimeException('Config intranet absente.');
    }

    if (!empty($CFG['DB_DSN'])) {
        // MySQL (ou autre driver PDO)
        $pdo = new PDO($CFG['DB_DSN'], $CFG['DB_USER'] ?? null, $CFG['DB_PASS'] ?? null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    } else {
        // SQLite
        if (!extension_loaded('pdo_sqlite') && !extension_loaded('sqlite3')) {
            throw new RuntimeException('SQLite driver not available: please enable or install sqlite3 (pdo_sqlite).');
        }
        $path = $CFG['DB_PATH'] ?? (__DIR__ . '/intranet.sqlite');
        $isNew = !file_exists($path);
        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec("PRAGMA journal_mode=WAL;");
        $pdo->exec("PRAGMA foreign_keys=ON;");
        $GLOBALS['TOOLS_SEED_ON_EMPTY'] = $isNew;
    }

    return $pdo;
}

function tools_bootstrap(PDO $pdo): void
{
    $drv = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

    if ($drv === 'mysql') {
        // 1) Créer la table si absente
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS tools (
              id INT AUTO_INCREMENT PRIMARY KEY,
              title VARCHAR(255) NOT NULL,
              description TEXT NOT NULL,
              url TEXT NOT NULL,
              icon TEXT NOT NULL,
              group_cns JSON NOT NULL,
              sort_order INT NOT NULL DEFAULT 1000,
              instructions TEXT NOT NULL,
              login_hint_prefix VARCHAR(255) NOT NULL,
              login_hint_suffix VARCHAR(255) NOT NULL,
              show_login_hint TINYINT(1) NOT NULL DEFAULT 0,
              enabled TINYINT(1) NOT NULL DEFAULT 1,
              created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        // 2) Index (compat MySQL < 8.0 : pas de IF NOT EXISTS)
        try {
            $pdo->exec("CREATE INDEX idx_tools_enabled ON tools (enabled, sort_order)");
        } catch (Throwable $e) { /* ignore si déjà là */
        }

    } else { // sqlite (défaut)
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS tools (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              url TEXT NOT NULL,
              icon TEXT NOT NULL DEFAULT '',
              group_cns TEXT NOT NULL DEFAULT '[]',
              sort_order INTEGER NOT NULL DEFAULT 1000,
              instructions TEXT NOT NULL DEFAULT '',
              login_hint_prefix TEXT NOT NULL DEFAULT '',
              login_hint_suffix TEXT NOT NULL DEFAULT '',
              show_login_hint INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        ");
        $pdo->exec("CREATE INDEX IF NOT EXISTS idx_tools_enabled ON tools(enabled, sort_order)");
        $pdo->exec("
            CREATE TRIGGER IF NOT EXISTS trg_tools_updated
            AFTER UPDATE ON tools
            FOR EACH ROW BEGIN
              UPDATE tools SET updated_at = datetime('now') WHERE id = OLD.id;
            END;
        ");
    }

    // 3) Seed si vide uniquement lors de la première création de la base (SQLite nouvelle)
    $canSeed = $GLOBALS['TOOLS_SEED_ON_EMPTY'] ?? true;
    if ($canSeed) {
        $c = (int) $pdo->query("SELECT COUNT(*) FROM tools")->fetchColumn();
        if ($c !== 0) {
            return;
        }

        $ins = $pdo->prepare("INSERT INTO tools
            (title,description,url,icon,group_cns,sort_order,instructions,login_hint_prefix,login_hint_suffix,show_login_hint,enabled)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)");
        $ins->execute([
            'Synology DSM',
            'Interface web du serveur de fichiers.',
            'https://dsm.jbsan.fr',
            'https://jbsan.fr/site/images/dsmicon_redim_2.png',
            '[]',
            10,
            'Connexion avec votre compte AD.',
            '',
            '@jbsan.fr',
            1,
            1
        ]);
        $ins->execute([
            'Proxmox VE',
            'Plateforme de virtualisation.',
            'https://proxmox.jbsan.fr',
            'https://proxmox.jbsan.fr/pve2/images/proxmox_logo.png',
            json_encode(['ProxmoxUsers', 'ProxmoxAdmins']),
            20,
            '',
            '',
            '',
            0,
            1
        ]);
    }
}

function tools_all(PDO $pdo): array
{
    return $pdo->query("SELECT * FROM tools ORDER BY sort_order, id")->fetchAll();
}
function tools_visible_for_user(PDO $pdo, array $userCnGroups): array
{
    $rows = $pdo->query("SELECT * FROM tools WHERE enabled=1 ORDER BY sort_order, id")->fetchAll();
    $normUser = array_map('mb_strtolower', $userCnGroups);
    $out = [];
    foreach ($rows as $r) {
        $req = json_decode($r['group_cns'] ?: '[]', true);
        if (!is_array($req) || count($req) === 0) {
            $out[] = $r;
            continue;
        }
        $req = array_map('mb_strtolower', array_filter($req, 'strlen'));
        $show = false;
        foreach ($req as $cn) {
            if (in_array($cn, $normUser, true)) {
                $show = true;
                break;
            }
        }
        if ($show)
            $out[] = $r;
    }
    return $out;
}
function tools_find(PDO $pdo, int $id): ?array
{
    $st = $pdo->prepare("SELECT * FROM tools WHERE id=?");
    $st->execute([$id]);
    $r = $st->fetch();
    return $r ?: null;
}
function tools_save(PDO $pdo, array $data): void
{
    if (!empty($data['id'])) {
        $st = $pdo->prepare("UPDATE tools
            SET title=?, description=?, url=?, icon=?, group_cns=?, sort_order=?, instructions=?,
                login_hint_prefix=?, login_hint_suffix=?, show_login_hint=?, enabled=?
            WHERE id=?");
        $st->execute([
            $data['title'],
            $data['description'],
            $data['url'],
            $data['icon'],
            json_encode($data['group_cns'] ?? []),
            (int) $data['sort_order'],
            $data['instructions'],
            $data['login_hint_prefix'],
            $data['login_hint_suffix'],
            (int) !empty($data['show_login_hint']),
            (int) !empty($data['enabled']),
            (int) $data['id']
        ]);
    } else {
        $st = $pdo->prepare("INSERT INTO tools
            (title,description,url,icon,group_cns,sort_order,instructions,login_hint_prefix,login_hint_suffix,show_login_hint,enabled)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)");
        $st->execute([
            $data['title'],
            $data['description'],
            $data['url'],
            $data['icon'],
            json_encode($data['group_cns'] ?? []),
            (int) $data['sort_order'],
            $data['instructions'],
            $data['login_hint_prefix'],
            $data['login_hint_suffix'],
            (int) !empty($data['show_login_hint']),
            (int) !empty($data['enabled'])
        ]);
    }
}
function tools_delete(PDO $pdo, int $id): void
{
    $st = $pdo->prepare("DELETE FROM tools WHERE id=?");
    $st->execute([$id]);
}
function tools_move(PDO $pdo, int $id, string $dir): void
{
    // Swap simple d’order avec l’outil précédent/suivant
    $cur = tools_find($pdo, $id);
    if (!$cur)
        return;
    $cmp = $dir === 'up' ? '<' : '>';
    $ord = $dir === 'up' ? 'DESC' : 'ASC';
    $st = $pdo->prepare("SELECT id, sort_order FROM tools WHERE sort_order $cmp ? ORDER BY sort_order $ord LIMIT 1");
    $st->execute([(int) $cur['sort_order']]);
    $neigh = $st->fetch();
    if (!$neigh)
        return;
    $pdo->beginTransaction();
    $u1 = $pdo->prepare("UPDATE tools SET sort_order=? WHERE id=?");
    $u2 = $pdo->prepare("UPDATE tools SET sort_order=? WHERE id=?");
    $u1->execute([(int) $neigh['sort_order'], (int) $cur['id']]);
    $u2->execute([(int) $cur['sort_order'], (int) $neigh['id']]);
    $pdo->commit();
}

/* ================================
   Outils — charge DB + filtre par groupes AD
=================================== */
$allTools = [];
$visibleTools = [];
$hasToolsForUser = false;

try {
    if (!isset($TOOL_PDO)) {
        $TOOL_PDO = app_pdo();
        tools_bootstrap($TOOL_PDO);
    }

    $allTools = tools_all($TOOL_PDO);

    // Ne calcule les outils visibles que si l’utilisateur est connecté
    if (!empty($_SESSION['username'])) {
        // memberOf peut être null | string | array -> on force un array
        $memberOf = $_SESSION['user_info']['memberOf'] ?? [];
        if (is_string($memberOf)) {
            $memberOf = [$memberOf];
        } elseif (!is_array($memberOf)) {
            $memberOf = [];
        }

        $userCnGroups = ad_groups_to_cn_list($memberOf); // <-- toujours un array ici
        $visibleTools = tools_visible_for_user($TOOL_PDO, $userCnGroups);
        $hasToolsForUser = !empty($visibleTools);
    }
} catch (Throwable $e) {
    error_log('[tools] load error: ' . $e->getMessage());
}

/* ================================
   Flux applicatif
=================================== */
// Déconnexion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'logout' && csrf_ok($_POST['csrf'] ?? '')) {
    intra_sync_invalidate();
    header('Location: intranet.php');
    exit;
}

// Vérification clé de synchronisation pour les sessions authentifiées
if (isset($_SESSION['username'])) {
    $cookieKey = $_COOKIE[INTRANET_KEY_COOKIE] ?? '';
    $sessionKey = $_SESSION['_key'] ?? '';
    if ($sessionKey === '') {
        intra_sync_invalidate();
        header('Location: intranet.php');
        exit;
    }
    // Tolérance contrôlée: si le cookie sync est absent mais la session a une clé,
    // on resynchronise une fois (utile après certaines transitions navigateur/proxy).
    if ($cookieKey === '') {
        setcookie(INTRANET_KEY_COOKIE, $sessionKey, intra_sync_key_cookie_params($sessionLifetime));
        $cookieKey = $sessionKey;
    }
    if (!hash_equals($sessionKey, $cookieKey)) {
        intra_sync_invalidate();
        header('Location: intranet.php');
        exit;
    }
    $newKey = intra_sync_key_generate();
    $_SESSION['_key'] = $newKey;
    setcookie(INTRANET_KEY_COOKIE, $newKey, intra_sync_key_cookie_params($sessionLifetime));
}

$uiError = '';
$uiSuccess = '';
$adminMsgErr = '';
$adminMsgOk = '';
$csrf = csrf_token();

/* ---------- LOGIN (PRG) ---------- */
if (!isset($_SESSION['username']) && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    $ip = client_ip();

    // 1) Rate limit fichier (si activé) : IP ou préfixe /64 déjà bloqué ?
    if ($RL_FILE_ENABLED && rl_file_is_blocked($ip)) {
        flash_set('ui', 'err', "Trop de tentatives de connexion. Votre accès est temporairement bloqué.");
        redirect_get([], 'login');
    }

    if (!csrf_ok($_POST['csrf'] ?? '')) {
        flash_set('ui', 'err', "Session expirée, veuillez réessayer.");
        redirect_get([], 'login');
    }

    $username = trim((string) ($_POST['user'] ?? ''));

    // 2) hCaptcha (si activé)
    if ($HCAPTCHA_ENABLED && (empty($_POST['h-captcha-response']) || !verifyCaptcha($_POST['h-captcha-response'], $HCAPTCHA_SECRET, $_SERVER['REMOTE_ADDR'] ?? ''))) {
        if ($RL_FILE_ENABLED) {
            rl_file_log_failure($ip, $username);
            $count = rl_file_count_sliding($ip);
            if ($count >= $RL_BLOCK_AFTER) {
                rl_file_add_blocked($ip);
                flash_set('ui', 'err', "Trop de tentatives de connexion. Votre accès est temporairement bloqué.");
            } elseif ($count >= $RL_WARN_AFTER) {
                flash_set('ui', 'err', "Trop de tentatives de connexion.");
            } else {
                flash_set('ui', 'err', "Captcha invalide.");
            }
        } else {
            flash_set('ui', 'err', "Captcha invalide.");
        }
        redirect_get([], 'login');
    }

    $password = (string) ($_POST['password'] ?? '');
    if ($username === '' || $password === '') {
        if ($RL_FILE_ENABLED) {
            rl_file_log_failure($ip, $username);
            $count = rl_file_count_sliding($ip);
            if ($count >= $RL_BLOCK_AFTER) {
                rl_file_add_blocked($ip);
                flash_set('ui', 'err', "Trop de tentatives de connexion. Votre accès est temporairement bloqué.");
            } elseif ($count >= $RL_WARN_AFTER) {
                flash_set('ui', 'err', "Trop de tentatives de connexion.");
            } else {
                flash_set('ui', 'err', "Identifiants requis.");
            }
        } else {
            flash_set('ui', 'err', "Identifiants requis.");
        }
        redirect_get([], 'login');
    }

    // 3) Appel /auth
    $r = callApi('POST', '/auth', ['username' => $username, 'password' => $password]);

    if ($r['error'] || empty($r['data']['success'])) {
        if ($RL_FILE_ENABLED) {
            rl_file_log_failure($ip, $username);
            $count = rl_file_count_sliding($ip);
            if ($count >= $RL_BLOCK_AFTER) {
                rl_file_add_blocked($ip);
                flash_set('ui', 'err', "Trop de tentatives de connexion. Votre accès est temporairement bloqué.");
            } elseif ($count >= $RL_WARN_AFTER) {
                flash_set('ui', 'err', "Trop de tentatives de connexion.");
            } else {
                flash_set('ui', 'err', "Échec d’authentification.");
            }
        } else {
            flash_set('ui', 'err', "Échec d’authentification.");
        }
        redirect_get([], 'login');
    }

    session_regenerate_id(true);
    $_SESSION['username'] = $username;
    $_SESSION['user_info'] = $r['data']['user'] ?? [];
    $_SESSION['is_admin'] = (bool) ($r['data']['isAdmin'] ?? false);
    $_SESSION['mustChangePassword'] = (bool) ($r['data']['mustChangePassword'] ?? false);
    $newKey = intra_sync_key_generate();
    $_SESSION['_key'] = $newKey;
    setcookie(INTRANET_KEY_COOKIE, $newKey, intra_sync_key_cookie_params($sessionLifetime));
    flash_set('ui', 'ok', "Connecté.");
    redirect_get([], 'profil');
}

/* ---------- refresh user si connecté ---------- */
if (isset($_SESSION['username'])) {
    $info = callApi('GET', '/user/' . rawurlencode($_SESSION['username']));
    if (!$info['error'] && is_array($info['data'])) {
        $_SESSION['user_info'] = $info['data'];
    } elseif ($info['httpCode'] === 404) {
        flash_set('ui', 'err', "Votre compte n’existe plus.");
        session_unset();
        session_destroy();
        redirect_get([], 'login');
    }
}

/* ---------- ACTIONS PROFIL ---------- */
if (isset($_SESSION['username']) && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'updateProfile') {
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        $uiError = "Session expirée.";
    } else {
        $dn = (string) ($_SESSION['user_info']['dn'] ?? '');
        if ($dn === '') {
            $uiError = "DN introuvable.";
        } else {
            // Récupère les champs (utiliser les NOMS réels du formulaire)
// + garde des flags de présence pour ne supprimer QUE si le champ était soumis
            $mail = trim((string) ($_POST['mail'] ?? ''));         // <-- au lieu de 'email'
            $site = trim((string) ($_POST['site'] ?? ''));         // <-- au lieu de 'site_web'
            $addr = trim((string) ($_POST['adresse'] ?? ''));
            $sn = trim((string) ($_POST['nom'] ?? ''));
            $gn = trim((string) ($_POST['prenom'] ?? ''));
            $tel = trim((string) ($_POST['telephone'] ?? ''));

            // IMPORTANT : pas de champ description côté utilisateur
// $desc = null; // on ignore description côté user

            // Flags de présence (pour ne pas toucher aux attributs absents du formulaire)
            $present = [
                'mail' => array_key_exists('mail', $_POST),
                'givenName' => array_key_exists('prenom', $_POST),
                'sn' => array_key_exists('nom', $_POST),
                'telephoneNumber' => array_key_exists('telephone', $_POST),
                'wWWHomePage' => array_key_exists('site', $_POST),
                'streetAddress' => array_key_exists('adresse', $_POST),
            ];

            // Contrôles simples
            if ($present['mail'] && $mail !== '' && !filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                $uiError = "Email invalide.";
            }

            $telNorm = null;
            if ($present['telephoneNumber'] && $tel !== '') {
                $telNorm = normalizePhone($tel);
                if ($telNorm === false) {
                    $uiError = "Téléphone invalide (FR).";
                }
            }

            if (!$uiError) {
                // État courant (pour savoir quoi supprimer proprement)
                $cur = $_SESSION['user_info'] ?? [];
                $has = [
                    'mail' => !empty($cur['mail']),
                    'givenName' => !empty($cur['givenName']),
                    'sn' => !empty($cur['sn']),
                    'telephoneNumber' => !empty($cur['telephoneNumber']),
                    'wWWHomePage' => !empty($cur['wwwhomepage']),
                    'streetAddress' => !empty($cur['streetAddress']),
                    // 'description' retiré côté user
                ];

                $mods = [];

                // Pour chaque attribut : on NE touche que s'il était présent dans le POST
                if ($present['mail']) {
                    if ($mail !== '')
                        $mods['mail'] = $mail;
                    elseif ($has['mail'])
                        $mods['mail'] = '';
                }
                if ($present['sn']) {
                    if ($sn !== '')
                        $mods['sn'] = $sn;
                    elseif ($has['sn'])
                        $mods['sn'] = '';
                }
                if ($present['givenName']) {
                    if ($gn !== '')
                        $mods['givenName'] = $gn;
                    elseif ($has['givenName'])
                        $mods['givenName'] = '';
                }
                if ($present['telephoneNumber']) {
                    if ($tel === '') {
                        if ($has['telephoneNumber'])
                            $mods['telephoneNumber'] = '';
                    } elseif ($telNorm !== false && $telNorm !== null) {
                        $mods['telephoneNumber'] = $telNorm;
                    }
                }
                if ($present['wWWHomePage']) {
                    if ($site !== '')
                        $mods['wWWHomePage'] = $site;
                    elseif ($has['wWWHomePage'])
                        $mods['wWWHomePage'] = '';
                }
                if ($present['streetAddress']) {
                    if ($addr !== '')
                        $mods['streetAddress'] = $addr;
                    elseif ($has['streetAddress'])
                        $mods['streetAddress'] = '';
                }

                // NE PAS gérer 'description' ici (réservé à l’admin)

                if (empty($mods)) {
                    flash_set('ui', 'ok', "Aucune modification à appliquer.");
                    redirect_get([], 'profil');
                } else {
                    $payload = ['dn' => $dn, 'modifications' => $mods];
                    $r = callApi('POST', '/user/updateProfile', $payload);
                    if ($r['error']) {
                        $uiError = api_err_detail($r, "Échec de mise à jour");
                    } else {
                        flash_set('ui', 'ok', "Profil mis à jour.");
                        redirect_get([], 'profil');
                    }
                }
            }
        }
    }
}

/* ---------- ACTIONS MDP (PRG) ---------- */
if (isset($_SESSION['username']) && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'changepw') {
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        flash_set('ui', 'err', "Session expirée.");
        redirect_get([], 'profil');
    }
    $cur = (string) ($_POST['current_password'] ?? '');
    $new = (string) ($_POST['new_password'] ?? '');
    $conf = (string) ($_POST['confirm_password'] ?? '');
    if ($cur === '' || $new === '' || $conf === '') {
        flash_set('ui', 'err', "Tous les champs sont requis.");
        redirect_get([], 'profil');
    }
    if ($new !== $conf) {
        flash_set('ui', 'err', "Les mots de passe ne correspondent pas.");
        redirect_get([], 'profil');
    }
    $r = callApi('POST', '/user/changePassword', ['username' => $_SESSION['username'], 'currentPassword' => $cur, 'newPassword' => $new]);
    if ($r['error']) {
        flash_set('ui', 'err', api_err_detail($r, "Impossible de changer le mot de passe"));
    } else {
        $_SESSION['mustChangePassword'] = false;
        flash_set('ui', 'ok', "Mot de passe changé.");
    }
    redirect_get([], 'profil');
}

$is_admin = !empty($_SESSION['is_admin']);
$userInfo = $_SESSION['user_info'] ?? [];
$memberOf = $userInfo['memberOf'] ?? [];
$memberOf = is_array($memberOf) ? $memberOf : ($memberOf ? [$memberOf] : []);
$userCnGroups = ad_groups_to_cn_list($memberOf);

// Récupère les listes depuis la config (peuvent être vides)
$ADM_USER_GROUPS = $CONFIG['ADM_USER_GROUPS'] ?? [];
$ADM_DOMAIN_GROUPS = $CONFIG['ADM_DOMAIN_GROUPS'] ?? [];

// Normalisation douce si la config a été saisie en chaîne "g1,g2"
if (is_string($ADM_USER_GROUPS))
    $ADM_USER_GROUPS = array_values(array_filter(array_map('trim', explode(',', $ADM_USER_GROUPS)), 'strlen'));
if (is_string($ADM_DOMAIN_GROUPS))
    $ADM_DOMAIN_GROUPS = array_values(array_filter(array_map('trim', explode(',', $ADM_DOMAIN_GROUPS)), 'strlen'));

// Règle demandée : si la liste est vide => seul is_admin passe.
// Sinon => is_admin OU membre d’un des groupes passe.
$canBy = function (array $required) use ($is_admin, $userCnGroups): bool {
    if (count($required) === 0) {
        return $is_admin; // liste vide => admin natif uniquement
    }
    return $is_admin || hasGroup($userCnGroups, $required);
};

$canUserAdmin = $canBy($ADM_USER_GROUPS);
$canDomainAdmin = $canBy($ADM_DOMAIN_GROUPS);

// Endpoint AJAX local pour détails explorateur (évite d'exposer le secret API au navigateur)
if (
    isset($_GET['ajax'])
    && $_GET['ajax'] === 'explorer_object'
    && isset($_SESSION['username'])
    && $canDomainAdmin
) {
    header('Content-Type: application/json; charset=utf-8');
    $dn = trim((string) ($_GET['dn'] ?? ''));
    if ($dn === '') {
        http_response_code(400);
        echo json_encode(['error' => 'dn requis']);
        exit;
    }
    $r = callApi('GET', '/explorer/object?dn=' . rawurlencode($dn));
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, 'Erreur de lecture objet AD')]);
        exit;
    }
    echo json_encode($r['data'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (
    isset($_GET['ajax'])
    && $_GET['ajax'] === 'search_groups'
    && isset($_SESSION['username'])
    && $canDomainAdmin
) {
    header('Content-Type: application/json; charset=utf-8');
    $q = trim((string) ($_GET['q'] ?? ''));
    $scope = trim((string) ($_GET['scope'] ?? 'all'));
    $endpoint = '/explorer/group-search?q=' . rawurlencode($q === '' ? '*' : $q) . '&scope=' . rawurlencode($scope) . '&max=50';
    $r = callApi('GET', $endpoint);
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, 'Erreur de recherche de groupes')]);
        exit;
    }
    $rows = [];
    foreach ((array) (($r['data']['results'] ?? $r['data']) ?? []) as $g) {
        $rows[] = [
            'dn' => (string) ($g['dn'] ?? ''),
            'name' => (string) ($g['name'] ?? ''),
            'sam' => (string) ($g['sam'] ?? ''),
        ];
    }
    echo json_encode(['groups' => $rows], JSON_UNESCAPED_UNICODE);
    exit;
}

if (
    isset($_GET['ajax'])
    && $_GET['ajax'] === 'user_groups'
    && isset($_SESSION['username'])
    && $canDomainAdmin
) {
    header('Content-Type: application/json; charset=utf-8');
    $user = trim((string) ($_GET['user'] ?? ''));
    if ($user === '') {
        http_response_code(400);
        echo json_encode(['error' => 'user requis']);
        exit;
    }
    $r = callApi('GET', '/explorer/user-groups?user=' . rawurlencode($user));
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, 'Erreur de lecture des groupes utilisateur')]);
        exit;
    }
    echo json_encode($r['data'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (
    isset($_GET['ajax'])
    && $_GET['ajax'] === 'search_users'
    && isset($_SESSION['username'])
    && $canDomainAdmin
) {
    header('Content-Type: application/json; charset=utf-8');
    $q = trim((string) ($_GET['q'] ?? ''));
    $r = callApi('GET', '/explorer/user-search?q=' . rawurlencode($q === '' ? '*' : $q) . '&max=50');
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, 'Erreur de recherche utilisateurs')]);
        exit;
    }
    echo json_encode($r['data'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (
    isset($_GET['ajax'])
    && $_GET['ajax'] === 'group_members'
    && isset($_SESSION['username'])
    && $canDomainAdmin
) {
    header('Content-Type: application/json; charset=utf-8');
    $group = trim((string) ($_GET['group'] ?? ''));
    if ($group === '') {
        http_response_code(400);
        echo json_encode(['error' => 'group requis']);
        exit;
    }
    $r = callApi('GET', '/explorer/group-members?group=' . rawurlencode($group));
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, 'Erreur de lecture des membres du groupe')]);
        exit;
    }
    echo json_encode($r['data'], JSON_UNESCAPED_UNICODE);
    exit;
}


/* ================================
   Données d’affichage
=================================== */
$is_admin = !empty($_SESSION['is_admin']);
$mustChange = !empty($_SESSION['mustChangePassword']);
$userInfo = $_SESSION['user_info'] ?? [];
$clientIp = client_ip();
$groups = [];
if (!empty($userInfo['memberOf']))
    $groups = is_array($userInfo['memberOf']) ? $userInfo['memberOf'] : [$userInfo['memberOf']];
$given = $userInfo['givenName'] ?? '';
$sn = $userInfo['sn'] ?? '';
$mail = $userInfo['mail'] ?? '';
$site = $userInfo['wwwhomepage'] ?? '';
$addr = $userInfo['streetAddress'] ?? '';
$tel = $userInfo['telephoneNumber'] ?? '';
$desc = $userInfo['description'] ?? '';
$forcePwMode = isset($_SESSION['username']) && $mustChange;

/* ================================
   Admin — traitement opérations (PRG)
=================================== */
/* Précharger options OU (sélection) pour create/move + arbre complet pour l'explorateur AD */
$ouOptions = [];
$adTree = [];
$adMeta = [];
$explorerQuery = trim((string) ($_GET['exq'] ?? ''));
$explorerTypeFilter = in_array((string) ($_GET['extype'] ?? 'all'), ['all', 'user', 'group', 'computer', 'ou', 'container', 'inetorgperson', 'domain'], true)
    ? (string) ($_GET['extype'] ?? 'all')
    : 'all';
$explorerTreeSortBy = in_array((string) ($_GET['tree_sort'] ?? 'dn'), ['name', 'type', 'dn'], true)
    ? (string) ($_GET['tree_sort'] ?? 'dn')
    : 'dn';
$explorerTreeSortDir = in_array((string) ($_GET['tree_dir'] ?? 'asc'), ['asc', 'desc'], true)
    ? (string) ($_GET['tree_dir'] ?? 'asc')
    : 'asc';
if ($is_admin) {
    $adMeta = fetch_ad_meta();
    $explorerBaseDn = trim((string) ($adMeta['baseDn'] ?? ''));
    $tree = $explorerBaseDn !== '' ? fetch_ad_explorer_tree($explorerBaseDn) : fetch_ad_explorer_tree('');
    $adTree = $tree;
    if (!empty($adTree['nodes']) && is_array($adTree['nodes'])) {
        $adTree['nodes'] = sort_ad_tree_nodes($adTree['nodes'], $explorerTreeSortBy, $explorerTreeSortDir);
        if ($explorerQuery !== '' || $explorerTypeFilter !== 'all') {
            $adTree['nodes'] = filter_tree_with_ancestors($adTree['nodes'], $explorerQuery, $explorerTypeFilter);
        }
    }
    $ouOptions = flatten_ou_nodes($tree);
    if (!$ouOptions) {
        $tree2 = fetch_ou_tree($explorerBaseDn);
        $ouOptions = flatten_ou_nodes($tree2);
    }
    if ($explorerBaseDn !== '') {
        $hasRoot = false;
        foreach ($ouOptions as $opt) {
            if (strcasecmp((string) ($opt['dn'] ?? ''), $explorerBaseDn) === 0) {
                $hasRoot = true;
                break;
            }
        }
        if (!$hasRoot) {
            array_unshift($ouOptions, [
                'dn' => $explorerBaseDn,
                'label' => 'Racine',
                'kind' => 'domain',
                'desc' => 'BaseDn actif'
            ]);
        } else {
            foreach ($ouOptions as &$opt) {
                if (strcasecmp((string) ($opt['dn'] ?? ''), $explorerBaseDn) === 0) {
                    $opt['label'] = 'Racine';
                    break;
                }
            }
            unset($opt);
        }
    }
}

if ($is_admin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_action'])) {
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        flash_set('login', 'err', "Session expirée.");
        redirect_get([], 'login');
    }

    $act = $_POST['admin_action'];

    // actions “Administration utilisateurs” (+ recherche groupes fiche user + gestion outils)
    $USER_ADMIN_ACTIONS = [
        'create_user',
        'clone_user',
        'admin_reset_pw',
        'admin_update_user',
        'enable_user',
        'disable_user',
        'unlock_user',
        'rename_user_cn',
        'move_user_ou',
        'set_user_groups',
        'set_group_members',
        'delete_user',
        'bulk_users',
        'tool_save',
        'tool_delete',
        'tool_move'
    ];

    // actions “Administration domaine”
    $DOMAIN_ADMIN_ACTIONS = [
        'create_ou',
        'update_ou',
        'delete_ou',
        'create_group',
        'delete_group',
        'search_groups_global'
    ];

    if (in_array($act, $USER_ADMIN_ACTIONS, true) && !$canUserAdmin) {
        flash_set('admin', 'err', "Droits insuffisants (admin utilisateurs requis).");
        redirect_get([], 'profil');
    }
    if (in_array($act, $DOMAIN_ADMIN_ACTIONS, true) && !$canDomainAdmin) {
        flash_set('admin', 'err', "Droits insuffisants (admin domaine requis).");
        redirect_get([], 'profil');
    }

    // Toujours préparer la sélection persistée pour rester sur le bon utilisateur après redirection
    $persistSam = trim((string) ($_POST['persist_selected_sam'] ?? ''));
    $qsSel = $persistSam !== '' ? ['select_sam' => $persistSam] : [];

    // --- Créer utilisateur ---
    if ($act === 'create_user') {
        $ouDn = trim((string) ($_POST['ouDn'] ?? ''));
        $cn = trim((string) ($_POST['cn'] ?? ''));
        $sam = trim((string) ($_POST['sam'] ?? ''));
        $gn = trim((string) ($_POST['givenName'] ?? ''));
        $snv = trim((string) ($_POST['sn'] ?? ''));
        $upn = trim((string) ($_POST['userPrincipalName'] ?? ''));
        $mailn = trim((string) ($_POST['mail'] ?? ''));
        $pwd = (string) ($_POST['password'] ?? '');
        $ena = isset($_POST['enabled']) && $_POST['enabled'] == '1';

        // Nouveaux champs
        $desc = trim((string) ($_POST['description'] ?? ''));
        $expNever = !empty($_POST['exp_never']);
        $expDateRaw = trim((string) ($_POST['exp_date'] ?? ''));
        $expTimeRaw = trim((string) ($_POST['exp_time'] ?? ''));
        $expIso = build_iso_expiry($expDateRaw, $expTimeRaw);

        if ($mailn !== '' && !filter_var($mailn, FILTER_VALIDATE_EMAIL)) {
            flash_set('admin', 'err', "Email invalide.");
            redirect_get([], 'admin-users', 'create_user');

        }
        if (!$expNever && ($expDateRaw !== '' || $expTimeRaw !== '') && !$expIso) {
            flash_set('admin', 'err', "Date/heure d’expiration invalide.");
            redirect_get([], 'admin-users', 'create_user');
        }

        $payload = [
            'ouDn' => $ouDn,
            'cn' => $cn,
            'sam' => $sam,
            'givenName' => $gn,
            'sn' => $snv,
            'userPrincipalName' => $upn,
            'mail' => $mailn,
            'password' => $pwd,
            'enabled' => $ena
        ];
        if ($desc !== '')
            $payload['description'] = $desc;

        $r = callApi('POST', '/admin/createUser', $payload);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Création échouée"));
            redirect_get([], 'admin-users', 'create_user');
        }

        // Forcer le changement de mot de passe au 1er logon (optionnel)
        if (!empty($_POST['must_change_at_first_login'])) {
            $rc = callApi('POST', '/admin/changePassword', [
                'username' => $sam,
                'newPassword' => $pwd,
                'mustChangeAtNextLogon' => true
            ]);
            if ($rc['error']) {
                flash_set('admin', 'err', api_err_detail($rc, "Utilisateur créé, mais impossible d'exiger le changement de mot de passe au premier logon"));
                redirect_get([], 'admin-users', 'create_user');
            }
        }

        // Expiration du compte (nouvel endpoint)
        if ($expNever) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'never' => true]);
        } elseif ($expIso) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'expiresAt' => $expIso, 'never' => false]);
        }

        $dnMsg = htmlspecialchars($r['data']['dn'] ?? '');
        $msg = "Utilisateur créé (DN: {$dnMsg}).";
        if (!empty($_POST['must_change_at_first_login']))
            $msg .= " (changement de mot de passe requis au premier logon)";
        flash_set('admin', 'ok', $msg);
        redirect_get([], 'admin-users', 'create_user');
    }

    // --- Cloner utilisateur (copie attributs + nouveau compte) ---
    if ($act === 'clone_user') {
        $source = trim((string) ($_POST['clone_source_sam'] ?? ''));
        $ouDn = trim((string) ($_POST['clone_ouDn'] ?? ''));
        $cn = trim((string) ($_POST['clone_cn'] ?? ''));
        $sam = trim((string) ($_POST['clone_sam'] ?? ''));
        $gn = trim((string) ($_POST['clone_givenName'] ?? ''));
        $snv = trim((string) ($_POST['clone_sn'] ?? ''));
        $upn = trim((string) ($_POST['clone_userPrincipalName'] ?? ''));
        $mailn = trim((string) ($_POST['clone_mail'] ?? ''));
        $pwd = (string) ($_POST['clone_password'] ?? '');
        $mustChange = !empty($_POST['clone_must_change_at_first_login']);
        $applyGroups = !empty($_POST['clone_apply_groups']);
        $cloneGroupsRaw = (string) ($_POST['clone_groups_raw'] ?? '');
        $cloneGroupsJson = (string) ($_POST['clone_groups_json'] ?? '');
        $cloneExpNever = !empty($_POST['clone_exp_never']);
        $cloneExpDate = trim((string) ($_POST['clone_exp_date'] ?? ''));
        $cloneExpTime = trim((string) ($_POST['clone_exp_time'] ?? ''));
        $cloneExpIso = build_iso_expiry($cloneExpDate, $cloneExpTime);

        if ($source === '' || $ouDn === '' || $cn === '' || $sam === '' || $gn === '' || $snv === '' || $upn === '' || $pwd === '') {
            flash_set('admin', 'err', "Clonage: champs requis manquants.");
            redirect_get([], 'explorer');
        }
        if ($mailn !== '' && !filter_var($mailn, FILTER_VALIDATE_EMAIL)) {
            flash_set('admin', 'err', "Clonage: email invalide.");
            redirect_get([], 'explorer');
        }
        if (!$cloneExpNever && ($cloneExpDate !== '' || $cloneExpTime !== '') && !$cloneExpIso) {
            flash_set('admin', 'err', "Clonage: date/heure d’expiration invalide.");
            redirect_get([], 'explorer');
        }

        $srcInfo = callApi('GET', '/user/' . rawurlencode($source));
        if ($srcInfo['error'] || !is_array($srcInfo['data'])) {
            flash_set('admin', 'err', api_err_detail($srcInfo, "Clonage: impossible de lire l’utilisateur source"));
            redirect_get([], 'explorer');
        }
        $src = $srcInfo['data'];

        $createPayload = [
            'ouDn' => $ouDn,
            'cn' => $cn,
            'sam' => $sam,
            'givenName' => $gn,
            'sn' => $snv,
            'userPrincipalName' => $upn,
            'mail' => $mailn,
            'password' => $pwd,
            'enabled' => true,
        ];
        if (!empty($src['description'])) {
            $desc = is_array($src['description']) ? implode("\n", $src['description']) : (string) $src['description'];
            if (trim($desc) !== '')
                $createPayload['description'] = $desc;
        }

        $create = callApi('POST', '/admin/createUser', $createPayload);
        if ($create['error']) {
            flash_set('admin', 'err', api_err_detail($create, "Clonage: création échouée"));
            redirect_get([], 'explorer');
        }

        if ($mustChange) {
            callApi('POST', '/admin/changePassword', [
                'username' => $sam,
                'newPassword' => $pwd,
                'mustChangeAtNextLogon' => true
            ]);
        }
        if ($cloneExpNever) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'never' => true]);
        } elseif ($cloneExpIso) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'expiresAt' => $cloneExpIso, 'never' => false]);
        }

        $newDn = (string) ($create['data']['dn'] ?? '');
        if ($newDn !== '') {
            $mods = [];
            $copyMap = [
                'telephoneNumber' => $src['telephoneNumber'] ?? '',
                'streetAddress' => $src['streetAddress'] ?? '',
                'wWWHomePage' => $src['wwwhomepage'] ?? '',
            ];
            foreach ($copyMap as $k => $v) {
                if (is_array($v))
                    $v = implode('; ', $v);
                $v = trim((string) $v);
                if ($v !== '')
                    $mods[$k] = $v;
            }
            if (!empty($mods)) {
                callApi('POST', '/user/updateProfile', ['dn' => $newDn, 'modifications' => $mods]);
            }
        }

        $groupErrors = 0;
        if ($applyGroups) {
            $groupTargets = [];
            $decoded = json_decode($cloneGroupsJson, true);
            if (is_array($decoded)) {
                foreach ($decoded as $g) {
                    if (is_array($g)) {
                        $v = trim((string) ($g['dn'] ?? ''));
                    } else {
                        $v = trim((string) $g);
                    }
                    if ($v !== '') {
                        $groupTargets[] = $v;
                    }
                }
            }
            $raw = trim($cloneGroupsRaw);
            if (empty($groupTargets) && $raw !== '') {
                $parts = preg_split('/[\r\n,;]+/', $raw) ?: [];
                foreach ($parts as $p) {
                    $v = trim((string) $p);
                    if ($v !== '') {
                        $groupTargets[] = $v;
                    }
                }
            } else {
                $srcGroups = $src['memberOf'] ?? [];
                if (is_string($srcGroups) && trim($srcGroups) !== '') {
                    $srcGroups = [$srcGroups];
                } elseif (!is_array($srcGroups)) {
                    $srcGroups = [];
                }
                foreach ($srcGroups as $g) {
                    $v = trim((string) $g);
                    if ($v !== '') {
                        $groupTargets[] = $v;
                    }
                }
            }
            $groupTargets = array_values(array_unique($groupTargets));
            $gr = callApi('POST', '/explorer/user-groups/set', ['user' => $sam, 'groups' => $groupTargets]);
            if (!empty($gr['error'])) {
                $groupErrors = count($groupTargets);
            } else {
                $groupErrors = 0;
            }
        }

        $msg = "Utilisateur cloné avec succès.";
        if ($applyGroups) {
            if ($groupErrors > 0) {
                $msg .= " (appartenance groupes: {$groupErrors} échec(s)).";
            } else {
                $msg .= " (appartenance groupes appliquée).";
            }
        }
        flash_set('admin', 'ok', $msg);
        redirect_get([], 'explorer');
    }

    // --- Reset mdp (admin) ---
    if ($act === 'admin_reset_pw') {
        $sam = trim((string) ($_POST['sam_reset'] ?? ''));
        $new = (string) ($_POST['new_password'] ?? '');
        $must = !empty($_POST['must_change']);

        if ($sam === '' || $new === '') {
            flash_set('admin', 'err', "Champs requis.");
            redirect_get($qsSel, 'admin-users');
        }

        $r = callApi('POST', '/admin/changePassword', [
            'username' => $sam,
            'newPassword' => $new,
            'mustChangeAtNextLogon' => $must
        ]);
        if ($r['error']) {
            flash_set('admin-users', 'err', api_err_detail($r, "Échec reset mot de passe"));
        } else {
            $msg = "Mot de passe réinitialisé pour " . htmlspecialchars($sam) . ".";
            if ($must)
                $msg .= " (changement requis au prochain logon)";
            flash_set('admin', 'ok', $msg);
        }
        redirect_get($qsSel, 'admin-users', 'password_reset');
    }

    // --- Update attributs ---
    if ($act === 'admin_update_user') {
        $sam = trim((string) ($_POST['sam_mod'] ?? ''));
        $mailn = trim((string) ($_POST['mail_mod'] ?? ''));
        $gn = trim((string) ($_POST['givenName_mod'] ?? ''));
        $snv = trim((string) ($_POST['sn_mod'] ?? ''));
        $telm = trim((string) ($_POST['tel_mod'] ?? ''));
        $addr2 = trim((string) ($_POST['addr_mod'] ?? ''));
        $site2 = trim((string) ($_POST['site_mod'] ?? ''));
        $descMod = trim((string) ($_POST['desc_mod'] ?? ''));

        // Expiration (nouveau)
        $expNeverM = !empty($_POST['exp_never_mod']);
        $expDateM = trim((string) ($_POST['exp_date_mod'] ?? ''));
        $expTimeM = trim((string) ($_POST['exp_time_mod'] ?? ''));
        $wantSetExpiry = (!$expNeverM && ($expDateM !== '' || $expTimeM !== ''));
        $expIsoM = build_iso_expiry($expDateM, $expTimeM);

        if ($mailn !== '' && !filter_var($mailn, FILTER_VALIDATE_EMAIL)) {
            flash_set('admin', 'err', "Email invalide.");
            redirect_get($qsSel, 'admin-users', 'user_update');
        }

        $telNorm = null;
        if ($telm !== '') {
            $telNorm = normalizePhone($telm);
            if ($telNorm === false) {
                flash_set('admin', 'err', "Téléphone invalide.");
                redirect_get($qsSel, 'admin-users', 'user_update');
            }
        }

        if ($descMod !== '' && mb_strlen($descMod) > 1024) {
            flash_set('admin', 'err', "Description trop longue (max 1024 caractères).");
            redirect_get($qsSel, 'admin-users', 'user_update');
        }

        if ($wantSetExpiry && !$expIsoM) {
            flash_set('admin', 'err', "Date/heure d’expiration invalide.");
            redirect_get($qsSel, 'admin-users', 'user_update');
        }

        // DN + état courant
        $dn = trim((string) ($_POST['dn'] ?? ''));
        $u = callApi('GET', '/user/' . rawurlencode($sam));
        if ($u['error']) {
            flash_set('admin', 'err', "Utilisateur introuvable.");
            redirect_get($qsSel, 'admin-users', 'user_update');
        }
        $cur = $u['data'];
        if ($dn === '')
            $dn = (string) ($cur['dn'] ?? '');
        if ($dn === '') {
            flash_set('admin', 'err', "DN introuvable.");
            redirect_get($qsSel, 'admin-users', 'user_update');
        }

        $has = [
            'mail' => !empty($cur['mail']),
            'givenName' => !empty($cur['givenName']),
            'sn' => !empty($cur['sn']),
            'telephoneNumber' => !empty($cur['telephoneNumber']),
            'wWWHomePage' => !empty($cur['wwwhomepage']),
            'streetAddress' => !empty($cur['streetAddress']),
            'description' => !empty($cur['description']),
        ];

        $mods = [];
        if ($mailn !== '')
            $mods['mail'] = $mailn;
        elseif ($has['mail'])
            $mods['mail'] = '';
        if ($gn !== '')
            $mods['givenName'] = $gn;
        elseif ($has['givenName'])
            $mods['givenName'] = '';
        if ($snv !== '')
            $mods['sn'] = $snv;
        elseif ($has['sn'])
            $mods['sn'] = '';
        if ($addr2 !== '')
            $mods['streetAddress'] = $addr2;
        elseif ($has['streetAddress'])
            $mods['streetAddress'] = '';
        if ($site2 !== '')
            $mods['wWWHomePage'] = $site2;
        elseif ($has['wWWHomePage'])
            $mods['wWWHomePage'] = '';
        if ($telm === '') {
            if ($has['telephoneNumber'])
                $mods['telephoneNumber'] = '';
        } elseif ($telNorm !== false && $telNorm !== null) {
            $mods['telephoneNumber'] = $telNorm;
        }

        if ($descMod !== '')
            $mods['description'] = $descMod;
        elseif ($has['description'])
            $mods['description'] = '';

        if (empty($mods) && !$expNeverM && !$wantSetExpiry) {
            flash_set('admin', 'ok', "Aucune modification à appliquer.");
            redirect_get($qsSel, 'admin-users', 'user_update');
        }

        if (!empty($mods)) {
            $payload = ['dn' => $dn, 'modifications' => $mods];
            $r = callApi('POST', '/user/updateProfile', $payload);
            if ($r['error']) {
                flash_set('admin', 'err', api_err_detail($r, "Mise à jour échouée"));
                redirect_get($qsSel, 'admin-users', 'user_update');
            }
        }

        // Expiration (nouvel endpoint)
        if ($expNeverM) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'never' => true]);
        } elseif ($wantSetExpiry && $expIsoM) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'expiresAt' => $expIsoM, 'never' => false]);
        }

        flash_set('admin', 'ok', "Utilisateur mis à jour.");
        redirect_get($qsSel, 'admin-users', 'user_update');
    }

    // --- Définir la liste finale des groupes utilisateur (nouveau flux unifié) ---
    if ($act === 'set_user_groups') {
        $user = trim((string) ($_POST['user_for_groups'] ?? ''));
        $groupsJson = (string) ($_POST['groups_json'] ?? '[]');
        if ($user === '') {
            flash_set('admin', 'err', "Utilisateur requis.");
            redirect_get($qsSel, 'admin-users');
        }
        $decoded = json_decode($groupsJson, true);
        $groups = [];
        if (is_array($decoded)) {
            foreach ($decoded as $g) {
                if (is_array($g)) {
                    $dn = trim((string) ($g['dn'] ?? ''));
                    if ($dn !== '') {
                        $groups[] = $dn;
                    }
                } else {
                    $dn = trim((string) $g);
                    if ($dn !== '') {
                        $groups[] = $dn;
                    }
                }
            }
        }
        $r = callApi('POST', '/explorer/user-groups/set', ['user' => $user, 'groups' => array_values(array_unique($groups))]);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Mise à jour des groupes échouée"));
        } else {
            $added = (int) ($r['data']['addedCount'] ?? 0);
            $removed = (int) ($r['data']['removedCount'] ?? 0);
            flash_set('admin', 'ok', "Groupes mis à jour (ajoutés: {$added}, retirés: {$removed}).");
        }
        redirect_get($qsSel, 'explorer');
    }

    // --- Définir la liste finale des membres d'un groupe ---
    if ($act === 'set_group_members') {
        $group = trim((string) ($_POST['group_for_members'] ?? ''));
        $membersJson = (string) ($_POST['members_json'] ?? '[]');
        if ($group === '') {
            flash_set('admin', 'err', "Groupe requis.");
            redirect_get([], 'explorer');
        }
        $decoded = json_decode($membersJson, true);
        $members = [];
        if (is_array($decoded)) {
            foreach ($decoded as $m) {
                if (is_array($m)) {
                    $v = trim((string) ($m['dn'] ?? ($m['sam'] ?? '')));
                } else {
                    $v = trim((string) $m);
                }
                if ($v !== '') {
                    $members[] = $v;
                }
            }
        }
        $r = callApi('POST', '/explorer/group-members/set', ['group' => $group, 'members' => array_values(array_unique($members))]);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Mise à jour des membres échouée"));
        } else {
            $added = (int) ($r['data']['addedCount'] ?? 0);
            $removed = (int) ($r['data']['removedCount'] ?? 0);
            flash_set('admin', 'ok', "Membres mis à jour (ajoutés: {$added}, retirés: {$removed}).");
        }
        redirect_get([], 'explorer');
    }

    // --- Supprimer utilisateur (JSON, pas dans l'URL) ---
    if ($act === 'delete_user') {
        $id = trim((string) ($_POST['del_id'] ?? ''));
        if ($id === '') {
            flash_set('admin', 'err', "Identifiant requis.");
            redirect_get($qsSel, 'admin-users');
        }

        // L'API attend { user: "<sAM OU DN>" } en POST
        $payload = ['user' => $id];
        $r = callApi('POST', '/admin/deleteUser', $payload);

        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Suppression échouée"));
        } else {
            flash_set('admin', 'ok', "Utilisateur supprimé.");
        }
        redirect_get([], 'admin-users', 'users_list');
    }

    // --- Activer/Désactiver ---
    if ($act === 'enable_user' || $act === 'disable_user') {
        $user = trim((string) ($_POST['sam_toggle'] ?? ''));
        if ($user === '') {
            flash_set('admin', 'err', "Utilisateur requis.");
            redirect_get($qsSel, 'admin-users');
        }
        $ep = $act === 'enable_user' ? '/admin/enableUser' : '/admin/disableUser';
        $r = callApi('POST', $ep, ['user' => $user]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, "Échec de modification d’état"));
        else
            flash_set('admin', 'ok', $act === 'enable_user' ? "Utilisateur activé." : "Utilisateur désactivé.");
        redirect_get($qsSel, 'admin-users', 'security');
    }

    // --- Déverrouiller ---
    if ($act === 'unlock_user') {
        $user = trim((string) ($_POST['sam_unlock'] ?? ''));
        if ($user === '') {
            flash_set('admin', 'err', "Utilisateur requis.");
            redirect_get($qsSel, 'admin-users');
        }
        $r = callApi('POST', '/admin/unlockUser', ['user' => $user]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, "Échec du déverrouillage"));
        else
            flash_set('admin', 'ok', "Compte déverrouillé (si verrouillé).");
        redirect_get($qsSel, 'admin-users', 'security');
    }

    // --- Renommer CN ---
    if ($act === 'rename_user_cn') {
        $user = trim((string) ($_POST['sam_for_rename'] ?? ''));
        $newCn = trim((string) ($_POST['new_cn'] ?? ''));
        if ($user === '' || $newCn === '') {
            flash_set('admin', 'err', "Utilisateur et nouveau CN requis.");
            redirect_get($qsSel, 'admin-users');
        }
        $r = callApi('POST', '/admin/renameUserCn', ['user' => $user, 'newCn' => $newCn]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, "Échec du renommage"));
        else
            flash_set('admin', 'ok', "CN renommé.");
        redirect_get($qsSel, 'admin-users', 'rename_cn');
    }

    // --- Déplacer d’OU ---
    if ($act === 'move_user_ou') {
        $user = trim((string) ($_POST['sam_for_move'] ?? ''));
        $newOu = trim((string) ($_POST['new_ou_dn'] ?? ''));
        if ($user === '' || $newOu === '') {
            flash_set('admin', 'err', "Utilisateur et OU cible requis.");
            redirect_get($qsSel, 'admin-domain');
        }
        $r = callApi('POST', '/admin/moveUser', ['user' => $user, 'newOuDn' => $newOu]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, "Échec du déplacement"));
        else
            flash_set('admin', 'ok', "Utilisateur déplacé.");
        redirect_get($qsSel, 'admin-domain', 'move_user');
    }

    // --- OU: créer ---
    if ($act === 'create_ou') {
        $parent = trim((string) ($_POST['ou_parent_dn'] ?? ''));
        $name = trim((string) ($_POST['ou_name'] ?? ''));
        $desc = trim((string) ($_POST['ou_desc'] ?? ''));
        $protRaw = $_POST['ou_protected'] ?? null; // "1" si cochée

        if ($parent === '' || $name === '' || !ou_name_is_valid($name)) {
            flash_set('admin', 'err', "Parent et nom d'OU valides sont requis (sans '=' ni ',').");
            redirect_get([], 'admin-domain', 'ou_manage');
        }

        $payload = [
            'ParentDn' => $parent,
            'Name' => $name,
        ];
        if ($desc !== '')
            $payload['Description'] = $desc;
        if ($protRaw !== null && $protRaw !== '')
            $payload['Protected'] = ($protRaw === '1');

        $r = callApi('POST', '/admin/ou/create', $payload);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Création de l'OU échouée"));
        } else {
            flash_set('admin', 'ok', "OU créée (DN: " . htmlspecialchars($r['data']['dn'] ?? '') . ").");
        }
        redirect_get([], 'admin-domain', 'ou_manage');
    }

    // --- OU: mise à jour (rename/description/protection) ---
    if ($act === 'update_ou') {
        $dn = trim((string) ($_POST['ou_dn'] ?? ''));
        $newNm = trim((string) ($_POST['ou_new_name'] ?? ''));
        $desc = trim((string) ($_POST['ou_desc_mod'] ?? ''));
        $currentName = trim((string) ($_POST['ou_current_name'] ?? ''));
        $currentDesc = trim((string) ($_POST['ou_current_desc'] ?? ''));
        $protSel = $_POST['ou_protected_mod'] ?? ''; // "", "1", "0"
        $descClear = !empty($_POST['ou_desc_clear']);
        $newParent = trim((string) ($_POST['ou_new_parent'] ?? '')); // ⬅️ NOUVEAU

        if ($dn === '') {
            flash_set('admin', 'err', "OU source requise.");
            redirect_get([], 'admin-domain', 'ou_manage');
        }

        $payload = ['OuDn' => $dn];
        if ($newNm !== '' && strcasecmp($newNm, $currentName) !== 0) {
            if (!ou_name_is_valid($newNm)) {
                flash_set('admin', 'err', "Nom d'OU invalide.");
                redirect_get([], 'admin-domain', 'ou_manage');
            }
            $payload['NewName'] = $newNm;
        }

        // Description: "" = supprimer, null = ne pas toucher, string = définir
        if ($descClear)
            $payload['Description'] = "";
        elseif ($desc !== '' && $desc !== $currentDesc)
            $payload['Description'] = $desc;

        // Protection tri-état
        if ($protSel === '1')
            $payload['Protected'] = true;
        elseif ($protSel === '0')
            $payload['Protected'] = false;

        // ⬅️ Support du déplacement (si renseigné)
        if ($newParent !== '') {
            $payload['NewParentDn'] = $newParent;
        }

        $ru = callApi('POST', '/admin/ou/update', $payload);
        if ($ru['error']) {
            flash_set('admin', 'err', api_err_detail($ru, "MAJ OU échouée"));
            redirect_get([], 'admin-domain', 'ou_manage');
        }
        flash_set('admin', 'ok', "OU mise à jour.");
        redirect_get([], 'admin-domain', 'ou_manage');
    }

    // --- OU: suppression ---
    if ($act === 'delete_ou') {
        $dn = trim((string) ($_POST['ou_del_dn'] ?? ''));
        if ($dn === '') {
            flash_set('admin', 'err', "DN d'OU requis.");
            redirect_get([], 'admin-domain', 'ou_manage');
        }

        // NB: POST requis par l'API, pas de "force" ici
        $r = callApi('POST', '/admin/ou/delete', ['OuDn' => $dn]);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Suppression OU échouée"));
        } else {
            flash_set('admin', 'ok', "OU supprimée.");
        }
        redirect_get([], 'admin-domain', 'ou_manage');
    }

    // --- Créer un groupe ---
    if ($act === 'create_group') {
        $ouDn = trim((string) ($_POST['group_ouDn'] ?? ''));
        $cn = trim((string) ($_POST['group_cn'] ?? ''));
        $sam = trim((string) ($_POST['group_sam'] ?? '')); // optionnel

        if ($ouDn === '' || $cn === '') {
            flash_set('admin', 'err', "OU et CN sont requis.");
            redirect_get([], 'admin-domain');
        }

        $payload = ['ouDn' => $ouDn, 'cn' => $cn];
        if ($sam !== '')
            $payload['sam'] = $sam;

        $r = callApi('POST', '/admin/createGroup', $payload);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Création du groupe échouée"));
        } else {
            $newDn = htmlspecialchars($r['data']['dn'] ?? '');
            flash_set('admin', 'ok', "Groupe créé (DN: {$newDn}).");
        }
        // Revenir sur l'onglet admin avec la recherche positionnée sur le nom du groupe
        redirect_get(['gq' => ($cn ?: '*')], 'admin-domain');
    }

    // --- Supprimer un groupe ---
    if ($act === 'delete_group') {
        $id = trim((string) ($_POST['group_del_id'] ?? ''));
        if ($id === '') {
            flash_set('admin', 'err', "Identifiant du groupe requis.");
            redirect_get([], 'admin-domain');
        }
        // Si DN fourni (contient CN=/DC=), on l'envoie tel quel ; sinon on suppose sAM
        $payload = (stripos($id, 'CN=') !== false || stripos($id, 'DC=') !== false)
            ? ['dn' => $id]
            : ['group' => $id];

        $r = callApi('DELETE', '/admin/deleteGroup', $payload);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, "Suppression du groupe échouée"));
        } else {
            flash_set('admin', 'ok', "Groupe supprimé.");
        }
        redirect_get([], 'admin-domain');
    }

    // --- Recherche groupes (carte globale) ---
    if ($act === 'search_groups_global') {
        $q = trim((string) ($_POST['group_query'] ?? ''));
        $gq = ($q === '' ? '*' : $q);
        $gp = max(1, (int) ($_POST['gpG'] ?? 1));
        $gps = max(1, (int) ($_POST['gpsG'] ?? 50));
        redirect_get(['gqG' => $gq, 'gpG' => $gp, 'gpsG' => $gps], 'admin-domain');
    }

    // --- Tools: créer / mettre à jour ---
    if ($act === 'tool_save') {
        // S'assurer qu'on a bien un PDO vivant
        if (!($TOOL_PDO ?? null) instanceof PDO) {
            try {
                $TOOL_PDO = app_pdo();
                tools_bootstrap($TOOL_PDO);
            } catch (Throwable $e) {
                flash_set('admin', 'err', 'Base outils indisponible : ' . $e->getMessage());
                redirect_get([], 'tools'); // PRG
            }
        }
        $id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
        $title = trim((string) ($_POST['title'] ?? ''));
        $url = trim((string) ($_POST['url'] ?? ''));
        if ($title === '' || $url === '') {
            flash_set('admin', 'err', "Titre et URL sont requis.");
            redirect_get([], 'tools');
        }
        $data = [
            'id' => $id,
            'title' => $title,
            'description' => (string) ($_POST['description'] ?? ''),
            'url' => $url,
            'icon' => (string) ($_POST['icon'] ?? ''),
            'group_cns' => array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['group_cns'] ?? ''))), 'strlen')),
            'sort_order' => (int) ($_POST['sort_order'] ?? 1000),
            'instructions' => (string) ($_POST['instructions'] ?? ''),
            'login_hint_prefix' => (string) ($_POST['login_hint_prefix'] ?? ''),
            'login_hint_suffix' => (string) ($_POST['login_hint_suffix'] ?? ''),
            'show_login_hint' => !empty($_POST['show_login_hint']),
            'enabled' => !empty($_POST['enabled']),
        ];
        try {
            tools_save($TOOL_PDO, $data);
            flash_set('admin', 'ok', $id ? 'Outil mis à jour.' : 'Outil créé.');
        } catch (Throwable $e) {
            flash_set('admin', 'err', 'Erreur enregistrement: ' . $e->getMessage());
        }
        redirect_get([], 'tools');
    }

    // --- Tools: suppression ---
    if ($act === 'tool_delete') {
        // S'assurer qu'on a bien un PDO vivant
        if (!($TOOL_PDO ?? null) instanceof PDO) {
            try {
                $TOOL_PDO = app_pdo();
                tools_bootstrap($TOOL_PDO);
            } catch (Throwable $e) {
                flash_set('admin', 'err', 'Base outils indisponible : ' . $e->getMessage());
                redirect_get([], 'tools'); // PRG
            }
        }

        $id = (int) ($_POST['id'] ?? 0);
        if (!$id) {
            flash_set('admin', 'err', 'ID manquant.');
            redirect_get([], 'tools');
        }
        try {
            tools_delete($TOOL_PDO, $id);
            flash_set('admin', 'ok', 'Outil supprimé.');
        } catch (Throwable $e) {
            flash_set('admin', 'err', 'Erreur suppression: ' . $e->getMessage());
        }
        redirect_get([], 'tools');
    }

    // --- Tools: réordonner (up/down) ---
    if ($act === 'tool_move') {
        // S'assurer qu'on a bien un PDO vivant
        if (!($TOOL_PDO ?? null) instanceof PDO) {
            try {
                $TOOL_PDO = app_pdo();
                tools_bootstrap($TOOL_PDO);
            } catch (Throwable $e) {
                flash_set('admin', 'err', 'Base outils indisponible : ' . $e->getMessage());
                redirect_get([], 'tools'); // PRG
            }
        }

        $id = (int) ($_POST['id'] ?? 0);
        $dir = ($_POST['dir'] ?? '') === 'up' ? 'up' : 'down';
        if (!$id) {
            flash_set('admin', 'err', 'ID manquant.');
            redirect_get([], 'tools');
        }
        try {
            tools_move($TOOL_PDO, $id, $dir);
        } catch (Throwable $e) {
            flash_set('admin', 'err', 'Erreur tri: ' . $e->getMessage());
        }
        redirect_get([], 'tools');
    }

    // --- Actions en masse sur utilisateurs ---
    if ($act === 'bulk_users') {
        // Sélection persistée éventuelle
        $persistSam = trim((string) ($_POST['persist_selected_sam'] ?? ''));
        $qsSel = $persistSam !== '' ? ['select_sam' => $persistSam] : [];

        $ids = $_POST['sel'] ?? [];
        if (!is_array($ids) || count($ids) === 0) {
            flash_set('admin', 'err', "Sélection vide.");
            redirect_get($qsSel, 'admin-users', 'users_list');
        }
        $action = trim((string) ($_POST['bulk_action'] ?? ''));
        $moveOu = trim((string) ($_POST['bulk_move_ou'] ?? ''));

        $ok = 0;
        $ko = 0;
        foreach ($ids as $user) {
            $user = trim((string) $user);
            if ($user === '') {
                $ko++;
                continue;
            }

            switch ($action) {
                case 'enable':
                    $r = callApi('POST', '/admin/enableUser', ['user' => $user]);
                    break;
                case 'disable':
                    $r = callApi('POST', '/admin/disableUser', ['user' => $user]);
                    break;
                case 'unlock':
                    $r = callApi('POST', '/admin/unlockUser', ['user' => $user]);
                    break;
                case 'delete':
                    $r = callApi('POST', '/admin/deleteUser', ['user' => $user]);
                    break;
                case 'move':
                    if ($moveOu === '') {
                        $ko++;
                        continue 2;
                    }
                    $r = callApi('POST', '/admin/moveUser', ['user' => $user, 'newOuDn' => $moveOu]);
                    break;
                default:
                    flash_set('admin', 'err', "Action invalide.");
                    redirect_get($qsSel, 'admin-users', 'users_list');
            }
            if (!empty($r['error']))
                $ko++;
            else
                $ok++;
        }

        $msg = "Action « $action » : $ok ok, $ko échec(s).";
        if ($ko > 0)
            flash_set('admin', 'err', $msg);
        else
            flash_set('admin', 'ok', $msg);
        redirect_get($qsSel, 'admin-users', 'users_list');
    }


}

/* ================================
   Admin — sélection via liste (GET)
=================================== */
if ($is_admin) {
    // Recherche groupes — carte globale
    if (isset($_GET['gqG'])) {
        $groupQueryGlobal = trim((string) $_GET['gqG']);
        $gpG = max(1, (int) ($_GET['gpG'] ?? 1));
        $gpsG = max(1, (int) ($_GET['gpsG'] ?? 50));
        $endpoint = '/groups?page=' . $gpG . '&pageSize=' . $gpsG;
        if ($groupQueryGlobal !== '' && $groupQueryGlobal !== '*') {
            $endpoint .= '&search=' . rawurlencode($groupQueryGlobal);
        }
        $gr = callApi('GET', $endpoint, null, true);
        if (!$gr['error']) {
            $groupResultsGlobal = is_array($gr['data']) ? $gr['data'] : [];
            $groupsHasMoreGlobal = !empty($gr['headers']['x-has-more']) && strtolower($gr['headers']['x-has-more']) === 'true';
        } else {
            $adminMsgErr = $adminMsgErr ?: api_err_detail($gr, "Recherche groupes (globale) échouée");
        }
    }

}

/* ---------- Récupération du flash pour affichage ---------- */
if ($f = flash_take()) {
    if ($f['area'] === 'admin') {
        if ($f['level'] === 'ok')
            $adminMsgOk = $f['msg'];
        if ($f['level'] === 'err')
            $adminMsgErr = $f['msg'];
    } else {
        if ($f['level'] === 'ok')
            $uiSuccess = $f['msg'];
        if ($f['level'] === 'err')
            $uiError = $f['msg'];
    }
}
/* ================================
   HTML
=================================== */
?>
<!doctype html>
<html lang="fr">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo isset($_SESSION['username']) ? 'Intranet' : 'Connexion'; ?></title>
    <?php if (!isset($_SESSION['username']) && $HCAPTCHA_ENABLED): ?>
        <script src="https://hcaptcha.com/1/api.js" async defer></script>
    <?php endif; ?>
    <style>
        :root {
            --bg: #0f172a;
            --card: #111827;
            --muted: #1f2937;
            --text: #e5e7eb;
            --sub: #9ca3af;
            --primary: #3b82f6;
            --primary-700: #1d4ed8;
            --border: #334155
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            background: linear-gradient(180deg, #0b1220, #0f172a 40%, #0b1220);
            color: var(--text);
            font: 16px/1.4 system-ui, Segoe UI, Roboto, Arial, sans-serif;
            min-height: 100vh
        }

        a { color: var(--primary); text-decoration: none; }
        a:hover { color: var(--primary-hover); text-decoration: underline; }

        .container { max-width: 1120px; margin: 0 auto; padding: 28px 24px; }

        .nav {
            display: flex;
            gap: 4px;
            align-items: center;
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 6px 10px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-card);
        }

        .nav .brand {
            padding: 10px 20px 10px 14px;
            font-weight: 700;
            font-size: 1.05rem;
            letter-spacing: -0.02em;
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-soft);
            padding: 10px 16px;
            border-radius: var(--radius);
            cursor: pointer;
            font: 500 14px/1 'Plus Jakarta Sans', system-ui, sans-serif;
            transition: color .15s, background .15s;
        }
        .tab-btn:hover { color: var(--text); background: var(--muted); }
        .tab-btn.active { color: var(--text); background: var(--muted); }

        .content {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 32px 28px;
            box-shadow: var(--shadow-card);
        }

        .grid { display: grid; gap: 24px; }
        .grid-2 { grid-template-columns: 1fr 1fr; }
        @media (max-width: 960px) { .grid-2 { grid-template-columns: 1fr; } }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 22px 24px;
            box-shadow: var(--shadow-card);
        }

        h1, h2, h3, h4 { margin: 0 0 1rem; font-weight: 600; letter-spacing: -0.02em; }
        h2 { font-size: 1.35rem; }
        h3 { font-size: 1.1rem; color: var(--text-soft); }
        h4 { font-size: 1rem; color: var(--sub); }

        .label {
            display: block;
            margin: 12px 0 6px;
            color: var(--sub);
            font-size: 13px;
            font-weight: 500;
        }

        .input, select {
            width: 100%;
            background: var(--muted);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 12px 14px;
            font: 15px/1.4 'Plus Jakarta Sans', system-ui, sans-serif;
            outline: none;
            transition: border-color .15s, box-shadow .15s;
        }
        .input:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--border-focus);
        }

        .btn {
            background: var(--primary);
            color: #fff;
            border: none;
            border-radius: var(--radius);
            padding: 12px 20px;
            font: 600 14px/1 'Plus Jakarta Sans', system-ui, sans-serif;
            cursor: pointer;
            transition: background .15s, transform .05s;
        }
        .btn:hover { background: var(--primary-hover); }
        .btn:active { transform: scale(0.98); }
        .btn.sm { padding: 8px 14px; font-size: 13px; border-radius: 10px; }

        .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
        .right { margin-left: auto; }

        .alert { padding: 14px 16px; border-radius: var(--radius); margin: 12px 0; }
        .alert.ok { background: rgba(34, 197, 94, .1); border: 1px solid rgba(34, 197, 94, .3); }
        .alert.err { background: rgba(239, 68, 68, .1); border: 1px solid rgba(239, 68, 68, .3); }

        .tools {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .tool {
            display: flex;
            gap: 14px;
            align-items: flex-start;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 16px 18px;
            transition: border-color .15s, background .15s;
        }
        .tool:hover { background: var(--card-hover); }

        .tool img {
            width: 44px; height: 44px;
            object-fit: contain;
            border-radius: 10px;
            background: var(--muted);
        }

        .small { font-size: 13px; color: var(--sub); line-height: 1.45; }

        .badge {
            padding: 6px 12px;
            border-radius: 999px;
            background: var(--muted);
            color: var(--sub);
            font-size: 12px;
            font-weight: 500;
        }

        .hr { height: 1px; background: var(--border); margin: 20px 0; }
        .center { max-width: 440px; margin: 48px auto; }

        .table { width: 100%; border-collapse: collapse; font-size: 14px; }
        .table th, .table td {
            border: 1px solid var(--border);
            padding: 12px 14px;
            text-align: left;
            vertical-align: middle;
        }
        .table th {
            background: var(--muted);
            color: var(--sub);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .04em;
        }
        .table .actions { display: flex; gap: 8px; flex-wrap: wrap; }

        .pagination { display: flex; gap: 12px; align-items: center; margin-top: 12px; }
        .inline { display: inline-block; }

        .pulse-focus {
            outline: 2px solid var(--primary);
            box-shadow: 0 0 0 6px var(--border-focus);
            border-radius: var(--radius-lg);
        }

        .toast {
            position: fixed;
            left: 50%;
            transform: translateX(-50%);
            bottom: 24px;
            z-index: 9999;
            min-width: 300px;
            max-width: 90vw;
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 14px 18px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            backdrop-filter: blur(12px);
            transition: opacity .25s, transform .25s;
        }
        .toast.hide { opacity: 0; transform: translateX(-50%) translateY(12px); }
        .toast.ok { border-color: rgba(34, 197, 94, .4); }
        .toast.err { border-color: rgba(239, 68, 68, .4); }
        .toast small { color: var(--sub); display: block; margin-top: 6px; font-size: 12px; }

        .link { color: var(--primary); font-weight: 500; }
        .link:hover { color: var(--primary-hover); }
        .page-subtitle { color: var(--sub); font-size: 14px; margin: -0.5rem 0 1.25rem; font-weight: 400; }

        /* Explorateur AD */
        .ad-explorer { display:grid; grid-template-columns:minmax(360px, 42%) minmax(0, 1fr); gap:16px; align-items:start; }
        .ad-tree-card { min-width:0; }
        .ad-details-card { min-width:0; }
        .ad-tree { max-height:540px; overflow:auto; padding:8px; border-radius:12px; background:#020617; border:1px solid var(--border); }
        .ad-tree-list { list-style:none; margin:0; padding-left:4px; }
        .ad-tree-list > li { margin:0; }
        .ad-tree-list ul { margin-left:14px; padding-left:8px; border-left:1px dashed rgba(148,163,184,.35); }
        .ad-node { width:100%; text-align:left; background:none; border:none; color:inherit; padding:4px 6px; border-radius:8px; cursor:pointer; display:flex; align-items:center; gap:6px; font-size:14px; }
        .ad-node:hover { background:#111827; }
        .ad-node.selected { background:#1d4ed8; color:#e5e7eb; }
        .ad-node-dot { width:7px; height:7px; border-radius:999px; background:#4b5563; flex-shrink:0; }
        .ad-node-label { flex:1 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .badge.subtle { background:rgba(30,64,175,.12); color:#93c5fd; border:1px solid rgba(59,130,246,.35); }
        .ad-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
        .ad-kv { display:grid; grid-template-columns:minmax(120px, 180px) minmax(0, 1fr); gap:8px; margin-top:8px; }
        .ad-kv code { white-space:pre-wrap; word-break:break-word; }
        .modal-backdrop { position:fixed; inset:0; background:rgba(2,6,23,.8); z-index:9000; display:none; align-items:center; justify-content:center; padding:16px; }
        .modal-card { width:min(780px, 96vw); max-height:90vh; overflow:auto; background:var(--bg-elevated); border:1px solid var(--border); border-radius:12px; box-shadow:var(--shadow); padding:16px; }
        .modal-head { display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:12px; }
        .modal-head h3 { margin:0; }
        @media (max-width: 1100px) {
            .ad-explorer { grid-template-columns:1fr; }
        }
    </style>
    <script>
        // Seul indicateur côté client conservé (déjà visible à l'écran si actif) :
        const FORCE_PW_MODE = <?= $forcePwMode ? 'true' : 'false' ?>;
        const ADMIN_FOCUS = "<?= htmlspecialchars($_GET['af'] ?? '', ENT_QUOTES) ?>";

        function allowedTabsFromDOM() {
            if (FORCE_PW_MODE) return ['profil']; // en mode "changement de mdp", on force
            return Array.from(document.querySelectorAll('.tab-btn[data-tab]'))
                .map(b => b.getAttribute('data-tab'));
        }

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.style.display = 'none');
            const el = document.getElementById('tab-' + tab);
            if (el) el.style.display = 'block';
        }

        function setActive(tab) {
            const ok = allowedTabsFromDOM();
            const target = ok.includes(tab) ? tab : ok[0];
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            const btn = document.querySelector('.tab-btn[data-tab="' + target + '"]');
            if (btn) btn.classList.add('active');
            showTab(target);
        }

        document.addEventListener('click', (e) => {
            const b = e.target.closest('.tab-btn[data-tab]');
            if (!b) return;
            const tab = b.getAttribute('data-tab');
            const ok = allowedTabsFromDOM();
            const target = ok.includes(tab) ? tab : ok[0];
            history.replaceState(null, '', '#tab-' + target);
            setActive(target);
        });

        document.addEventListener('DOMContentLoaded', () => {
            // Choix initial robuste
            let hashTab = (location.hash || '').replace('#tab-', '');
            const ok = allowedTabsFromDOM();
            if (!ok.includes(hashTab)) {
                // défaut côté serveur, sans exposer d'état sensible
                <?php
                $def = isset($_SESSION['username'])
                    ? (($is_admin ?? false) && !empty($_GET['select_sam'] ?? '') ? 'admin' : 'profil')
                    : 'login';
                ?>
                hashTab = '<?= $def ?>';
                history.replaceState(null, '', '#tab-' + hashTab);
            }
            setActive(hashTab);

            // Auto-focus (après action admin)
            if (hashTab === 'admin' && ADMIN_FOCUS) {
                const target = document.querySelector('[data-focus="' + ADMIN_FOCUS + '"]');
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    target.classList.add('pulse-focus');
                    setTimeout(() => target.classList.remove('pulse-focus'), 1500);
                }
            }

            // Toast auto-hide
            const toast = document.getElementById('toast');
            if (toast && toast.dataset.show === '1') {
                setTimeout(() => toast.classList.add('hide'), 10000);
                toast.addEventListener('click', () => toast.classList.add('hide'));
            }

            // --- Admin: helpers "bulk" ---
            const selAll = document.getElementById('sel-all');
            if (selAll) {
                selAll.addEventListener('change', () => {
                    document.querySelectorAll('input[name="sel[]"]').forEach(cb => cb.checked = selAll.checked);
                });
            }
            const bulkSelect = document.getElementById('bulk-action');
            const bulkOuWrap = document.getElementById('bulk-ou-wrap');
            if (bulkSelect && bulkOuWrap) {
                const toggleOu = () => {
                    bulkOuWrap.style.display = (bulkSelect.value === 'move') ? 'block' : 'none';
                };
                bulkSelect.addEventListener('change', toggleOu);
                toggleOu();
            }

            // Explorateur AD : sélection de nœud et panneau de détails + actions contextuelles
            const adTree = document.getElementById('ad-tree');
            const adDetails = document.getElementById('ad-details');
            const adActions = document.getElementById('ad-actions');
            const explorerModal = document.getElementById('explorer-modal');
            const modalTitle = document.getElementById('explorer-modal-title');
            const modalBody = document.getElementById('explorer-modal-body');
            let selectedNode = null;
            let selectedObjectDetails = null;
            if (adTree && adDetails) {
                adTree.addEventListener('click', (e) => {
                    const node = e.target.closest('.ad-node');
                    if (!node) return;
                    adTree.querySelectorAll('.ad-node').forEach(n => n.classList.remove('selected'));
                    node.classList.add('selected');
                    selectedNode = node;
                    const dn = node.getAttribute('data-dn') || '';
                    const rawType = node.getAttribute('data-type') || '';
                    const name = node.getAttribute('data-name') || '';
                    const desc = node.getAttribute('data-description') || '';
                    const classes = node.getAttribute('data-classes') || '';
                    const type = normalizeNodeType(rawType, classes, dn);
                    const typeLabel = type === 'user' ? 'Utilisateur'
                        : (type === 'group' ? 'Groupe'
                        : (type === 'computer' ? 'Ordinateur'
                        : (type === 'inetorgperson' ? 'Personne'
                        : (type === 'ou' || type === 'domain' || type === 'container' ? 'Conteneur' : (type || 'Objet')))));
                    adDetails.innerHTML =
                        '<div class=\"ad-kv\"><div class=\"small\">Type</div><div><strong>' + escapeHtml(typeLabel) + '</strong></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Nom</div><div><code>' + escapeHtml(name || dn) + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">DN complet</div><div><code>' + escapeHtml(dn) + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Classes LDAP</div><div><code>' + escapeHtml(classes || '-') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Description</div><div>' + escapeHtml(desc || '—') + '</div></div>' +
                        '<div class=\"small\" style=\"margin-top:10px;opacity:.85\">Chargement des détails avancés...</div>';
                    renderExplorerActions(type, dn, name);
                    loadExplorerObjectDetails(dn, type, name);
                });
            }

            function normalizeNodeType(rawType, classes, dn) {
                const c = String(classes || '').toLowerCase();
                // Priorité absolue : classe computer => PC
                if (c.includes('computer')) return 'computer';
                const t = String(rawType || '').trim().toLowerCase();
                if (t && t !== 'other') return t;
                const dnU = String(dn || '').toUpperCase();
                if (c.includes('group')) return 'group';
                if (c.includes('inetorgperson')) return 'inetorgperson';
                if (c.includes('user')) return 'user';
                if (c.includes('organizationalunit') || dnU.startsWith('OU=')) return 'ou';
                if (c.includes('container') || dnU.startsWith('CN=')) return 'container';
                if (dnU.startsWith('DC=')) return 'domain';
                return 'other';
            }

            function loadExplorerObjectDetails(dn, fallbackType, fallbackName) {
                selectedObjectDetails = null;
                fetch('intranet.php?ajax=explorer_object&dn=' + encodeURIComponent(dn), {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                })
                    .then(r => r.json())
                    .then(data => {
                        if (!data || data.error) {
                            adDetails.innerHTML += '<div class=\"small\" style=\"margin-top:8px;color:#fca5a5\">Détails avancés indisponibles.</div>';
                            return;
                        }
                        selectedObjectDetails = data;
                        renderExplorerObjectDetails(data, fallbackType, fallbackName, dn);
                    })
                    .catch(() => {
                        adDetails.innerHTML += '<div class=\"small\" style=\"margin-top:8px;color:#fca5a5\">Détails avancés indisponibles.</div>';
                    });
            }

            function renderExplorerObjectDetails(data, fallbackType, fallbackName, dn) {
                const type = normalizeNodeType(data.type || fallbackType, (data.objectClasses || []).join(','), dn);
                const a = data.attributes || {};
                const typeLabel = type === 'user' ? 'Utilisateur'
                    : (type === 'group' ? 'Groupe'
                    : (type === 'computer' ? 'Ordinateur'
                    : (type === 'inetorgperson' ? 'Personne'
                    : (type === 'ou' || type === 'domain' || type === 'container' ? 'Conteneur' : (type || 'Objet')))));

                let html =
                    '<div class=\"ad-kv\"><div class=\"small\">Type</div><div><strong>' + escapeHtml(typeLabel) + '</strong></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">Nom</div><div><code>' + escapeHtml(a.name || a.cn || fallbackName || dn) + '</code></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">DN complet</div><div><code>' + escapeHtml(data.dn || dn) + '</code></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">Classes LDAP</div><div><code>' + escapeHtml((data.objectClasses || []).join(', ') || '-') + '</code></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">Description</div><div>' + escapeHtml(a.description || '—') + '</div></div>';

                if (type === 'ou') {
                    const locked = !!data.protectedOu;
                    html += '<div class=\"ad-kv\"><div class=\"small\">Protection OU</div><div>' +
                        (locked ? '🔒 Protégée' : '🔓 Non protégée') + '</div></div>';
                }

                if (type === 'user' || type === 'inetorgperson') {
                    html +=
                        '<div class=\"ad-kv\"><div class=\"small\">sAMAccountName</div><div><code>' + escapeHtml(a.samAccountName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">UPN</div><div><code>' + escapeHtml(a.userPrincipalName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Email</div><div>' + escapeHtml(a.mail || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Téléphone</div><div>' + escapeHtml(a.telephoneNumber || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Adresse</div><div>' + escapeHtml(a.streetAddress || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Site</div><div>' + escapeHtml(a.website || '—') + '</div></div>';
                }

                if (type === 'computer') {
                    const ips = Array.isArray(a.ipAddresses) ? a.ipAddresses : [];
                    html +=
                        '<div class=\"ad-kv\"><div class=\"small\">Nom DNS</div><div><code>' + escapeHtml(a.dnsHostName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">IP</div><div><code>' + escapeHtml(ips.length ? ips.join(', ') : '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Système</div><div>' + escapeHtml(a.operatingSystem || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Version OS</div><div>' + escapeHtml(a.operatingSystemVersion || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Dernier bind machine</div><div><code>' + escapeHtml(a.lastBindAtUtc || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Ajouté le</div><div><code>' + escapeHtml(a.createdAtUtc || a.whenCreated || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Dernier utilisateur connecté</div><div><code>' + escapeHtml(a.lastUserConnected || 'non disponible AD standard') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">Géré par</div><div><code>' + escapeHtml(a.managedBy || '—') + '</code></div></div>';
                }

                const memberOf = Array.isArray(a.memberOf) ? a.memberOf : [];
                if (memberOf.length > 0) {
                    const rows = memberOf.slice(0, 20).map(dn => {
                        const label = shortDnLabel(dn);
                        return '<div><strong>' + escapeHtml(label) + '</strong><div class=\"small\" style=\"opacity:.75\"><code>' + escapeHtml(dn) + '</code></div></div>';
                    }).join('');
                    html += '<div class=\"ad-kv\"><div class=\"small\">Membre de</div><div>' +
                        rows +
                        (memberOf.length > 20 ? '<div class=\"small\">... (' + (memberOf.length - 20) + ' autres)</div>' : '') +
                        '</div></div>';
                }
                adDetails.innerHTML = html;
                renderExplorerActions(type, data.dn || dn, a.samAccountName || fallbackName || dn);
            }

            function renderExplorerActions(type, dn, name) {
                if (!adActions) return;
                const isContainer = ['ou', 'container', 'domain'].includes(type);
                const isUser = ['user', 'inetorgperson'].includes(type);
                const isGroup = type === 'group';
                const buttons = [];
                if (isContainer) {
                    buttons.push(btn('Créer un utilisateur', "openExplorerModal('create_user')"));
                    buttons.push(btn('Créer une OU', "openExplorerModal('create_ou')"));
                    buttons.push(btn('Créer un groupe', "openExplorerModal('create_group')"));
                }
                if (type === 'ou') {
                    buttons.push(btn('Modifier OU', "openExplorerModal('update_ou')"));
                    buttons.push(btn('Supprimer OU', "openExplorerModal('delete_ou')"));
                }
                if (isUser) {
                    buttons.push(btn('Modifier utilisateur', "openExplorerModal('admin_update_user')"));
                    buttons.push(btn('Groupes utilisateur', "openExplorerModal('set_user_groups')"));
                    buttons.push(btn('Activer', "openExplorerModal('enable_user')"));
                    buttons.push(btn('Désactiver', "openExplorerModal('disable_user')"));
                    buttons.push(btn('Déverrouiller', "openExplorerModal('unlock_user')"));
                    buttons.push(btn('Réinitialiser mot de passe', "openExplorerModal('admin_reset_pw')"));
                    buttons.push(btn('Renommer CN', "openExplorerModal('rename_user_cn')"));
                    buttons.push(btn('Déplacer', "openExplorerModal('move_user_ou')"));
                    buttons.push(btn('Copier utilisateur', "openExplorerModal('clone_user')"));
                    buttons.push(btn('Supprimer utilisateur', "openExplorerModal('delete_user')"));
                }
                if (isGroup) {
                    buttons.push(btn('Membres du groupe', "openExplorerModal('set_group_members')"));
                    buttons.push(btn('Supprimer groupe', "openExplorerModal('delete_group')"));
                }
                adActions.innerHTML = buttons.length ? buttons.join('') : '<div class=\"small\">Aucune action disponible pour ce type.</div>';
            }

            function btn(label, onclickCode) {
                return '<button type=\"button\" class=\"btn sm\" onclick=\"' + onclickCode + '\">' + escapeHtml(label) + '</button>';
            }

            window.closeExplorerModal = function closeExplorerModal() {
                if (!explorerModal) return;
                explorerModal.style.display = 'none';
                modalBody.innerHTML = '';
            };
            window.openExplorerModal = function openExplorerModal(action) {
                if (!selectedNode || !explorerModal || !modalBody || !modalTitle) return;
                const dn = selectedNode.getAttribute('data-dn') || '';
                const name = selectedNode.getAttribute('data-name') || '';
                const type = selectedNode.getAttribute('data-type') || '';
                const sam = selectedNode.getAttribute('data-sam') || '';
                const userId = sam || dn || name;
                const csrf = <?= json_encode($csrf) ?>;
                const baseDn = <?= json_encode((string) ($adMeta['baseDn'] ?? '')) ?>;
                const ouOptionsHtml = <?= json_encode(implode('', array_map(function($opt){ return '<option value=\"'.htmlspecialchars((string)$opt['dn'], ENT_QUOTES).'\">'.htmlspecialchars((string)$opt['label'], ENT_QUOTES).'</option>'; }, $ouOptions))) ?>;
                modalTitle.textContent = 'Action: ' + action;
                const hidden = '<input type=\"hidden\" name=\"csrf\" value=\"' + escapeHtml(csrf) + '\"><input type=\"hidden\" name=\"admin_action\" value=\"' + escapeHtml(action) + '\">';

                let formBody = '<div class=\"small\" style=\"margin-bottom:8px\">Objet: <code>' + escapeHtml(name || dn) + '</code></div>';
                if (action === 'create_ou') {
                    formBody += hidden + '<input type=\"hidden\" name=\"ou_parent_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<label class=\"label\">Nom OU</label><input class=\"input\" name=\"ou_name\" required>' +
                        '<label class=\"label\">Description</label><input class=\"input\" name=\"ou_desc\">' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">Protéger</label><input type=\"checkbox\" name=\"ou_protected\" value=\"1\"></div>';
                } else if (action === 'update_ou') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const currentOuName = sa.ou || sa.name || name || '';
                    const currentOuDesc = sa.description || '';
                    formBody += hidden + '<input type=\"hidden\" name=\"ou_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<input type=\"hidden\" name=\"ou_current_name\" value=\"' + escapeHtml(currentOuName) + '\">' +
                        '<input type=\"hidden\" name=\"ou_current_desc\" value=\"' + escapeHtml(currentOuDesc) + '\">' +
                        '<label class=\"label\">Nom OU</label><input class=\"input\" name=\"ou_new_name\" value=\"' + escapeHtml(currentOuName) + '\">' +
                        '<label class=\"label\">Description</label><input class=\"input\" name=\"ou_desc_mod\" value=\"' + escapeHtml(currentOuDesc) + '\">' +
                        '<label class=\"label\">Nouveau parent (optionnel)</label><select class=\"input\" name=\"ou_new_parent\"><option value=\"\">— inchangé —</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">Protection</label><select class=\"input\" name=\"ou_protected_mod\"><option value=\"\">Ne pas changer</option><option value=\"1\">Activer</option><option value=\"0\">Désactiver</option></select>';
                } else if (action === 'delete_ou') {
                    formBody += hidden + '<input type=\"hidden\" name=\"ou_del_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">Suppression d’OU non vide/protégée bloquée côté API.</div>';
                } else if (action === 'create_user') {
                    formBody += hidden +
                        '<label class=\"label\">OU cible</label><select class=\"input\" name=\"ouDn\" required><option value=\"\">— choisir —</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">CN</label><input class=\"input\" name=\"cn\" required>' +
                        '<label class=\"label\">sAMAccountName</label><input class=\"input\" name=\"sam\" required>' +
                        '<label class=\"label\">Prénom</label><input class=\"input\" name=\"givenName\" required>' +
                        '<label class=\"label\">Nom</label><input class=\"input\" name=\"sn\" required>' +
                        '<label class=\"label\">UPN</label><input class=\"input\" name=\"userPrincipalName\" required>' +
                        '<label class=\"label\">Email</label><input class=\"input\" name=\"mail\" type=\"email\">' +
                        '<label class=\"label\">Mot de passe initial</label><input class=\"input\" name=\"password\" type=\"password\" required>' +
                        '<label class=\"label\">Expiration du compte</label>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" type=\"date\" name=\"exp_date\" style=\"max-width:220px\"><input class=\"input\" type=\"time\" name=\"exp_time\" style=\"max-width:160px\"><label class=\"label\" style=\"margin:0 6px 0 10px\">Jamais</label><input type=\"checkbox\" name=\"exp_never\" value=\"1\" checked></div>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">Forcer changement à la première connexion</label><input type=\"checkbox\" name=\"must_change_at_first_login\" value=\"1\"></div>';
                } else if (action === 'create_group') {
                    formBody += hidden +
                        '<label class=\"label\">OU cible</label><select class=\"input\" name=\"group_ouDn\" required><option value=\"\">— choisir —</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">CN groupe</label><input class=\"input\" name=\"group_cn\" required>' +
                        '<label class=\"label\">sAM (optionnel)</label><input class=\"input\" name=\"group_sam\">';
                } else if (action === 'enable_user' || action === 'disable_user') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_toggle\" value=\"' + escapeHtml(userId) + '\">';
                } else if (action === 'unlock_user') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_unlock\" value=\"' + escapeHtml(userId) + '\">';
                } else if (action === 'admin_reset_pw') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_reset\" value=\"' + escapeHtml(userId) + '\">' +
                        '<label class=\"label\">Nouveau mot de passe</label><input class=\"input\" name=\"new_password\" type=\"password\" required>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">Forcer changement au prochain logon</label><input type=\"checkbox\" name=\"must_change\" value=\"1\"></div>';
                } else if (action === 'admin_update_user') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const descValue = Array.isArray(sa.description) ? (sa.description[0] || '') : (sa.description || '');
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<label class=\"label\">Utilisateur (sAM)</label><input class=\"input\" name=\"sam_mod\" value=\"' + escapeHtml(sa.samAccountName || userId) + '\" required>' +
                        '<label class=\"label\">Email</label><input class=\"input\" name=\"mail_mod\" type=\"email\" value=\"' + escapeHtml(sa.mail || '') + '\">' +
                        '<label class=\"label\">Prénom</label><input class=\"input\" name=\"givenName_mod\" value=\"' + escapeHtml(sa.givenName || '') + '\">' +
                        '<label class=\"label\">Nom</label><input class=\"input\" name=\"sn_mod\" value=\"' + escapeHtml(sa.sn || '') + '\">' +
                        '<label class=\"label\">Téléphone</label><input class=\"input\" name=\"tel_mod\" value=\"' + escapeHtml(sa.telephoneNumber || '') + '\">' +
                        '<label class=\"label\">Adresse</label><input class=\"input\" name=\"addr_mod\" value=\"' + escapeHtml(sa.streetAddress || '') + '\">' +
                        '<label class=\"label\">Site web</label><input class=\"input\" name=\"site_mod\" value=\"' + escapeHtml(sa.wWWHomePage || '') + '\">' +
                        '<label class=\"label\">Description</label><textarea class=\"input\" name=\"desc_mod\" rows=\"3\" maxlength=\"1024\">' + escapeHtml(descValue) + '</textarea>' +
                        '<label class=\"label\">Expiration du compte</label>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" type=\"date\" name=\"exp_date_mod\" style=\"max-width:220px\"><input class=\"input\" type=\"time\" name=\"exp_time_mod\" style=\"max-width:160px\"><label class=\"label\" style=\"margin:0 6px 0 10px\">Jamais expirer</label><input type=\"checkbox\" name=\"exp_never_mod\" value=\"1\"></div>';
                } else if (action === 'rename_user_cn') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_for_rename\" value=\"' + escapeHtml(userId) + '\">' +
                        '<label class=\"label\">Nouveau CN</label><input class=\"input\" name=\"new_cn\" required>';
                } else if (action === 'move_user_ou') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_for_move\" value=\"' + escapeHtml(userId) + '\">' +
                        '<label class=\"label\">OU cible</label><select class=\"input\" name=\"new_ou_dn\" required><option value=\"\">— choisir —</option>' + ouOptionsHtml + '</select>';
                } else if (action === 'delete_user') {
                    formBody += hidden + '<input type=\"hidden\" name=\"del_id\" value=\"' + escapeHtml(userId) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">Suppression définitive de l’utilisateur.</div>';
                } else if (action === 'delete_group') {
                    formBody += hidden + '<input type=\"hidden\" name=\"group_del_id\" value=\"' + escapeHtml(dn) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">Suppression définitive du groupe.</div>';
                } else if (action === 'clone_user') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const srcSam = sa.samAccountName || userId;
                    const srcGn = sa.givenName || '';
                    const srcSn = sa.sn || '';
                    const srcMail = sa.mail || '';
                    const srcUpn = sa.userPrincipalName || '';
                    const srcGroups = Array.isArray(sa.memberOf) ? sa.memberOf : [];
                    const srcGroupsJson = JSON.stringify(srcGroups.map(dn => ({ dn })));
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"clone_source_sam\" value=\"' + escapeHtml(srcSam) + '\">' +
                        '<label class=\"label\">OU cible</label><select class=\"input\" name=\"clone_ouDn\" required><option value=\"\">— choisir —</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">CN</label><input class=\"input\" name=\"clone_cn\" required>' +
                        '<label class=\"label\">sAMAccountName</label><input class=\"input\" name=\"clone_sam\" required>' +
                        '<label class=\"label\">Prénom</label><input class=\"input\" name=\"clone_givenName\" value=\"' + escapeHtml(srcGn) + '\" required>' +
                        '<label class=\"label\">Nom</label><input class=\"input\" name=\"clone_sn\" value=\"' + escapeHtml(srcSn) + '\" required>' +
                        '<label class=\"label\">UPN</label><input class=\"input\" name=\"clone_userPrincipalName\" value=\"' + escapeHtml(srcUpn) + '\" required>' +
                        '<label class=\"label\">Email</label><input class=\"input\" name=\"clone_mail\" type=\"email\" value=\"' + escapeHtml(srcMail) + '\">' +
                        '<label class=\"label\">Mot de passe initial</label><input class=\"input\" name=\"clone_password\" type=\"password\" required>' +
                        '<label class=\"label\">Expiration du compte</label>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" type=\"date\" name=\"clone_exp_date\" style=\"max-width:220px\"><input class=\"input\" type=\"time\" name=\"clone_exp_time\" style=\"max-width:160px\"><label class=\"label\" style=\"margin:0 6px 0 10px\">Jamais</label><input type=\"checkbox\" name=\"clone_exp_never\" value=\"1\" checked></div>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">Appliquer appartenance aux groupes</label><input type=\"checkbox\" name=\"clone_apply_groups\" value=\"1\" checked></div>' +
                        '<input type=\"hidden\" name=\"clone_groups_json\" value=\'' + escapeHtml(srcGroupsJson) + '\'>' +
                        '<input type=\"hidden\" name=\"clone_groups_raw\" value=\"\">' +
                        '<div id=\"clone-groups-selected\" class=\"small\" style=\"margin:8px 0\"></div>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" id=\"clone-group-query\" placeholder=\"Rechercher un groupe\"><button type=\"button\" class=\"btn sm\" id=\"clone-group-search-btn\">Rechercher</button></div>' +
                        '<div id=\"clone-group-results\" class=\"small\" style=\"margin-top:8px\"></div>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">Forcer changement à la première connexion</label><input type=\"checkbox\" name=\"clone_must_change_at_first_login\" value=\"1\"></div>';
                } else if (action === 'set_user_groups') {
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"user_for_groups\" value=\"' + escapeHtml(userId) + '\">' +
                        '<input type=\"hidden\" name=\"groups_json\" value=\"[]\">' +
                        '<div class=\"small\">Gérez la liste finale des groupes de cet utilisateur, puis cliquez sur Exécuter.</div>' +
                        '<div id=\"user-groups-selected\" class=\"small\" style=\"margin:8px 0\"></div>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" id=\"user-group-query\" placeholder=\"Rechercher un groupe\"><button type=\"button\" class=\"btn sm\" id=\"user-group-search-btn\">Rechercher</button></div>' +
                        '<div id=\"user-group-results\" class=\"small\" style=\"margin-top:8px\"></div>';
                } else if (action === 'set_group_members') {
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"group_for_members\" value=\"' + escapeHtml(dn) + '\">' +
                        '<input type=\"hidden\" name=\"members_json\" value=\"[]\">' +
                        '<div class=\"small\">Gérez la liste finale des membres de ce groupe, puis cliquez sur Exécuter.</div>' +
                        '<div id=\"group-members-selected\" class=\"small\" style=\"margin:8px 0\"></div>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" id=\"group-member-query\" placeholder=\"Rechercher un utilisateur\"><button type=\"button\" class=\"btn sm\" id=\"group-member-search-btn\">Rechercher</button></div>' +
                        '<div id=\"group-member-results\" class=\"small\" style=\"margin-top:8px\"></div>';
                } else {
                    return;
                }

                modalBody.innerHTML =
                    '<form method=\"post\" onsubmit=\"return confirm(\'Confirmer cette action AD ?\')\">' +
                    formBody +
                    '<div class=\"row\" style=\"justify-content:flex-end; gap:8px; margin-top:12px\">' +
                    '<button type=\"button\" class=\"btn\" onclick=\"closeExplorerModal()\">Annuler</button>' +
                    '<button type=\"submit\" class=\"btn\">Exécuter</button>' +
                    '</div></form>';
                if (action === 'create_user') {
                    const s = modalBody.querySelector('select[name=\"ouDn\"]');
                    if (s) s.value = dn || baseDn || '';
                } else if (action === 'create_group') {
                    const s = modalBody.querySelector('select[name=\"group_ouDn\"]');
                    if (s) s.value = dn || baseDn || '';
                } else if (action === 'move_user_ou') {
                    const s = modalBody.querySelector('select[name=\"new_ou_dn\"]');
                    if (s) s.value = baseDn || '';
                } else if (action === 'clone_user') {
                    const s = modalBody.querySelector('select[name=\"clone_ouDn\"]');
                    if (s) s.value = baseDn || '';
                    initCloneGroupsEditor();
                } else if (action === 'set_user_groups') {
                    initUserGroupsEditor(userId);
                } else if (action === 'set_group_members') {
                    initGroupMembersEditor(dn);
                } else if (action === 'admin_update_user') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const never = !!(sa.accountNeverExpires);
                    const dateInput = modalBody.querySelector('input[name=\"exp_date_mod\"]');
                    const timeInput = modalBody.querySelector('input[name=\"exp_time_mod\"]');
                    const neverInput = modalBody.querySelector('input[name=\"exp_never_mod\"]');
                    if (neverInput) neverInput.checked = never;
                    const rawUtc = sa.accountExpiresUtc || sa.accountExpires || '';
                    if (!never && rawUtc && dateInput && timeInput) {
                        const dt = new Date(rawUtc);
                        if (!Number.isNaN(dt.getTime())) {
                            const p2 = (n) => String(n).padStart(2, '0');
                            dateInput.value = dt.getFullYear() + '-' + p2(dt.getMonth() + 1) + '-' + p2(dt.getDate());
                            timeInput.value = p2(dt.getHours()) + ':' + p2(dt.getMinutes());
                        }
                    }
                } else if (action === 'update_ou') {
                    const s = modalBody.querySelector('select[name=\"ou_new_parent\"]');
                    if (s) s.value = '';
                }
                explorerModal.style.display = 'flex';
            };

            function initCloneGroupsEditor() {
                const hidden = modalBody.querySelector('input[name=\"clone_groups_json\"]');
                const selectedWrap = modalBody.querySelector('#clone-groups-selected');
                const resultsWrap = modalBody.querySelector('#clone-group-results');
                const qInput = modalBody.querySelector('#clone-group-query');
                const btn = modalBody.querySelector('#clone-group-search-btn');
                if (!hidden || !selectedWrap || !resultsWrap || !qInput || !btn) return;

                let selected = [];
                try {
                    const decoded = JSON.parse(hidden.value || '[]');
                    if (Array.isArray(decoded)) {
                        selected = decoded
                            .map(v => (typeof v === 'string' ? { dn: v, name: '' } : v))
                            .filter(v => v && v.dn);
                    }
                } catch (_) { }

                const sync = () => {
                    hidden.value = JSON.stringify(selected.map(v => ({ dn: v.dn, name: v.name || '' })));
                    if (selected.length === 0) {
                        selectedWrap.innerHTML = '<div class=\"small\">Aucun groupe sélectionné.</div>';
                        return;
                    }
                    selectedWrap.innerHTML = selected.map((g, i) =>
                        '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-rm=\"' + i + '\">Retirer</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(g.dn || '') + '</span></div>'
                    ).join('');
                    selectedWrap.querySelectorAll('button[data-rm]').forEach(b => {
                        b.addEventListener('click', () => {
                            const idx = parseInt(b.getAttribute('data-rm') || '-1', 10);
                            if (idx >= 0) {
                                selected.splice(idx, 1);
                                sync();
                            }
                        });
                    });
                };

                const search = () => {
                    const q = (qInput.value || '').trim();
                    const endpoint = 'intranet.php?ajax=search_groups&q=' + encodeURIComponent(q || '*');
                    fetch(endpoint, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                        .then(r => r.json())
                        .then(data => {
                            const rows = Array.isArray(data?.groups) ? data.groups : [];
                            if (!rows.length) {
                                resultsWrap.innerHTML = '<div class=\"small\">Aucun groupe trouvé.</div>';
                                return;
                            }
                            resultsWrap.innerHTML = rows.map((g, i) => {
                                const dn = String(g.dn || '');
                                const exists = selected.some(s => s.dn.toLowerCase() === dn.toLowerCase());
                                return '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-add=\"' + i + '\" ' + (exists ? 'disabled' : '') + '>Ajouter</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(dn) + '</span></div>';
                            }).join('');
                            resultsWrap.querySelectorAll('button[data-add]').forEach(b => {
                                b.addEventListener('click', () => {
                                    const idx = parseInt(b.getAttribute('data-add') || '-1', 10);
                                    if (idx >= 0 && rows[idx]) {
                                        const dn = String(rows[idx].dn || '');
                                        if (dn && !selected.some(s => s.dn.toLowerCase() === dn.toLowerCase())) {
                                            selected.push({ dn, name: String(rows[idx].name || rows[idx].sam || '') });
                                            sync();
                                            search();
                                        }
                                    }
                                });
                            });
                        })
                        .catch(() => {
                            resultsWrap.innerHTML = '<div class=\"small\" style=\"color:#fca5a5\">Recherche groupes indisponible.</div>';
                        });
                };

                btn.addEventListener('click', search);
                qInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        search();
                    }
                });
                sync();
            }

            function shortDnLabel(dn) {
                const raw = String(dn || '');
                const first = raw.split(',')[0] || raw;
                return first.replace(/^(CN|OU)=/i, '') || raw;
            }

            function prettyGroupLabel(g) {
                const name = String(g?.name || '').trim();
                const sam = String(g?.sam || '').trim();
                const dn = String(g?.dn || '').trim();
                if (name && sam) return `${name} (${sam})`;
                if (name) return name;
                if (sam) return sam;
                return shortDnLabel(dn);
            }

            function initUserGroupsEditor(userId) {
                const hidden = modalBody.querySelector('input[name=\"groups_json\"]');
                const selectedWrap = modalBody.querySelector('#user-groups-selected');
                const resultsWrap = modalBody.querySelector('#user-group-results');
                const qInput = modalBody.querySelector('#user-group-query');
                const btn = modalBody.querySelector('#user-group-search-btn');
                if (!hidden || !selectedWrap || !resultsWrap || !qInput || !btn) return;

                let selected = [];

                const sync = () => {
                    hidden.value = JSON.stringify(selected.map(v => ({ dn: v.dn, name: v.name || '', sam: v.sam || '' })));
                    if (selected.length === 0) {
                        selectedWrap.innerHTML = '<div class=\"small\">Aucun groupe sélectionné.</div>';
                        return;
                    }
                    selectedWrap.innerHTML = selected.map((g, i) =>
                        '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-rm=\"' + i + '\">Retirer</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(g.dn || '') + '</span></div>'
                    ).join('');
                    selectedWrap.querySelectorAll('button[data-rm]').forEach(b => {
                        b.addEventListener('click', () => {
                            const idx = parseInt(b.getAttribute('data-rm') || '-1', 10);
                            if (idx >= 0) {
                                selected.splice(idx, 1);
                                sync();
                            }
                        });
                    });
                };

                const search = () => {
                    const q = (qInput.value || '').trim();
                    const endpoint = 'intranet.php?ajax=search_groups&q=' + encodeURIComponent(q || '*') + '&scope=all';
                    fetch(endpoint, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                        .then(r => r.json())
                        .then(data => {
                            const rows = Array.isArray(data?.groups) ? data.groups : [];
                            if (!rows.length) {
                                resultsWrap.innerHTML = '<div class=\"small\">Aucun groupe trouvé.</div>';
                                return;
                            }
                            resultsWrap.innerHTML = rows.map((g, i) => {
                                const dn = String(g.dn || '');
                                const exists = selected.some(s => s.dn.toLowerCase() === dn.toLowerCase());
                                return '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-add=\"' + i + '\" ' + (exists ? 'disabled' : '') + '>Ajouter</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(dn) + '</span></div>';
                            }).join('');
                            resultsWrap.querySelectorAll('button[data-add]').forEach(b => {
                                b.addEventListener('click', () => {
                                    const idx = parseInt(b.getAttribute('data-add') || '-1', 10);
                                    if (idx >= 0 && rows[idx]) {
                                        const dn = String(rows[idx].dn || '');
                                        if (dn && !selected.some(s => s.dn.toLowerCase() === dn.toLowerCase())) {
                                            selected.push({ dn, name: String(rows[idx].name || ''), sam: String(rows[idx].sam || '') });
                                            sync();
                                            search();
                                        }
                                    }
                                });
                            });
                        })
                        .catch(() => {
                            resultsWrap.innerHTML = '<div class=\"small\" style=\"color:#fca5a5\">Recherche groupes indisponible.</div>';
                        });
                };

                fetch('intranet.php?ajax=user_groups&user=' + encodeURIComponent(userId), {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                })
                    .then(r => r.json())
                    .then(data => {
                        const groups = Array.isArray(data?.groups) ? data.groups : [];
                        selected = groups
                            .map(g => ({ dn: String(g.dn || ''), name: String(g.name || ''), sam: String(g.sam || '') }))
                            .filter(g => g.dn);
                        sync();
                    })
                    .catch(() => {
                        selected = [];
                        sync();
                    });

                btn.addEventListener('click', search);
                qInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        search();
                    }
                });
            }

            function prettyUserLabel(u) {
                const name = String(u?.name || '').trim();
                const sam = String(u?.sam || '').trim();
                const upn = String(u?.upn || '').trim();
                if (name && sam) return `${name} (${sam})`;
                if (name) return name;
                if (sam) return sam;
                if (upn) return upn;
                return shortDnLabel(String(u?.dn || ''));
            }

            function initGroupMembersEditor(groupDn) {
                const hidden = modalBody.querySelector('input[name=\"members_json\"]');
                const selectedWrap = modalBody.querySelector('#group-members-selected');
                const resultsWrap = modalBody.querySelector('#group-member-results');
                const qInput = modalBody.querySelector('#group-member-query');
                const btn = modalBody.querySelector('#group-member-search-btn');
                if (!hidden || !selectedWrap || !resultsWrap || !qInput || !btn) return;

                let selected = [];

                const sync = () => {
                    hidden.value = JSON.stringify(selected.map(v => ({ dn: v.dn, name: v.name || '', sam: v.sam || '', upn: v.upn || '' })));
                    if (selected.length === 0) {
                        selectedWrap.innerHTML = '<div class=\"small\">Aucun membre sélectionné.</div>';
                        return;
                    }
                    selectedWrap.innerHTML = selected.map((u, i) =>
                        '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-rm=\"' + i + '\">Retirer</button><code>' + escapeHtml(prettyUserLabel(u)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(u.dn || '') + '</span></div>'
                    ).join('');
                    selectedWrap.querySelectorAll('button[data-rm]').forEach(b => {
                        b.addEventListener('click', () => {
                            const idx = parseInt(b.getAttribute('data-rm') || '-1', 10);
                            if (idx >= 0) {
                                selected.splice(idx, 1);
                                sync();
                            }
                        });
                    });
                };

                const search = () => {
                    const q = (qInput.value || '').trim();
                    fetch('intranet.php?ajax=search_users&q=' + encodeURIComponent(q || '*'), {
                        credentials: 'same-origin',
                        headers: { 'X-Requested-With': 'XMLHttpRequest' }
                    })
                        .then(r => r.json())
                        .then(data => {
                            const rows = Array.isArray(data?.results) ? data.results : [];
                            if (!rows.length) {
                                resultsWrap.innerHTML = '<div class=\"small\">Aucun utilisateur trouvé.</div>';
                                return;
                            }
                            resultsWrap.innerHTML = rows.map((u, i) => {
                                const dn = String(u.dn || '');
                                const exists = selected.some(s => s.dn.toLowerCase() === dn.toLowerCase());
                                return '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-add=\"' + i + '\" ' + (exists ? 'disabled' : '') + '>Ajouter</button><code>' + escapeHtml(prettyUserLabel(u)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(dn) + '</span></div>';
                            }).join('');
                            resultsWrap.querySelectorAll('button[data-add]').forEach(b => {
                                b.addEventListener('click', () => {
                                    const idx = parseInt(b.getAttribute('data-add') || '-1', 10);
                                    if (idx >= 0 && rows[idx]) {
                                        const dn = String(rows[idx].dn || '');
                                        if (dn && !selected.some(s => s.dn.toLowerCase() === dn.toLowerCase())) {
                                            selected.push({ dn, name: String(rows[idx].name || ''), sam: String(rows[idx].sam || ''), upn: String(rows[idx].upn || '') });
                                            sync();
                                            search();
                                        }
                                    }
                                });
                            });
                        })
                        .catch(() => {
                            resultsWrap.innerHTML = '<div class=\"small\" style=\"color:#fca5a5\">Recherche utilisateurs indisponible.</div>';
                        });
                };

                fetch('intranet.php?ajax=group_members&group=' + encodeURIComponent(groupDn), {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                })
                    .then(r => r.json())
                    .then(data => {
                        const members = Array.isArray(data?.members) ? data.members : [];
                        selected = members
                            .map(u => ({ dn: String(u.dn || ''), name: String(u.name || ''), sam: String(u.sam || ''), upn: String(u.upn || '') }))
                            .filter(u => u.dn);
                        sync();
                    })
                    .catch(() => {
                        selected = [];
                        sync();
                    });

                btn.addEventListener('click', search);
                qInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        search();
                    }
                });
            }

            function escapeHtml(str) {
                return String(str).replace(/[&<>"']/g, function (m) {
                    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m];
                });
            }
        });
    </script>
</head>

<!-- FLASH / NOTIFS GLOBALES (entre nav et content) -->
<?php
$toastMsg = '';
$toastLevel = '';
if ($uiError) {
    $toastMsg = $uiError;
    $toastLevel = 'err';
} elseif ($adminMsgErr) {
    $toastMsg = $adminMsgErr;
    $toastLevel = 'err';
} elseif ($uiSuccess) {
    $toastMsg = $uiSuccess;
    $toastLevel = 'ok';
} elseif ($adminMsgOk) {
    $toastMsg = $adminMsgOk;
    $toastLevel = 'ok';
}
?>
<?php if ($toastMsg): ?>
    <div id="toast" class="toast <?= $toastLevel ?>" data-show="1" role="status" aria-live="polite">
        <?= htmlspecialchars($toastMsg) ?>
        <small>(Cliquer pour fermer)</small>
    </div>
<?php else: ?>
    <div id="toast" class="toast hide" data-show="0"></div>
<?php endif; ?>


<body>
    <div class="container">

        <div class="nav">
            <div class="brand">Intranet</div>
            <?php if (!isset($_SESSION['username'])): ?>
                <button class="tab-btn active" data-tab="login" onclick="setActive('login')">Connexion</button>
                <span class="badge" style="margin-left:8px">Portail d’accès</span>
            <?php else: ?>
                <?php if ($forcePwMode): ?>
                    <!-- Mode forcé: pas d’onglets ni déconnexion -->
                    <?php if ($SHOW_CLIENT_IP): ?>
                        <div class="row" style="margin-left:auto; gap:8px; align-items:center">
                            <span class="badge">IP: <?= htmlspecialchars($clientIp) ?></span>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <button class="tab-btn" data-tab="profil" onclick="setActive('profil')">Mon profil</button>

                    <?php if ($hasToolsForUser): ?>
                        <button class="tab-btn" data-tab="outils" onclick="setActive('outils')">Mes outils</button>
                    <?php endif; ?>

                    <?php if ($canUserAdmin): ?>
                        <button class="tab-btn" data-tab="tools" onclick="setActive('tools')">Gestion outils</button>
                        <button class="tab-btn" data-tab="admin-users" onclick="setActive('admin-users')">Liste utilisateurs</button>
                    <?php endif; ?>
                    <?php if ($canDomainAdmin): ?>
                        <button class="tab-btn" data-tab="explorer" onclick="setActive('explorer')">Explorateur AD</button>
                        <button class="tab-btn" data-tab="admin-domain" onclick="setActive('admin-domain')">Admin domaine</button>
                    <?php endif; ?>

                    <div class="row" style="margin-left:auto; gap:8px; align-items:center">
                        <?php if ($SHOW_CLIENT_IP): ?>
                            <span class="badge">IP: <?= htmlspecialchars($clientIp) ?></span>
                        <?php endif; ?>
                        <form method="post" class="inline">
                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                            <input type="hidden" name="action" value="logout">
                            <button class="tab-btn">Déconnexion</button>
                        </form>
                    </div>
                <?php endif; ?>

            <?php endif; ?>
        </div>

        <div class="content">

            <?php if ($forcePwMode): ?>
                <div class="card center" style="max-width:520px">
                    <h2>Changement de mot de passe requis</h2>
                    <p class="page-subtitle" style="color:var(--sub)">Pour des raisons de sécurité, vous devez définir un nouveau mot de passe avant de continuer.</p>
                    <form method="post" autocomplete="off" novalidate>
                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="action" value="changepw">
                        <label class="label" for="current_password">Mot de passe actuel</label>
                        <input class="input" id="current_password" name="current_password" type="password" required>

                        <label class="label" for="new_password">Nouveau mot de passe</label>
                        <input class="input" id="new_password" name="new_password" type="password" required>

                        <label class="label" for="confirm_password">Confirmer</label>
                        <input class="input" id="confirm_password" name="confirm_password" type="password" required>

                        <div style="margin-top:12px">
                            <button class="btn" type="submit">Changer</button>
                        </div>
                    </form>
                </div>

            <?php else: ?>

                <!-- LOGIN -->
                <div id="tab-login" class="tab" style="display:none">
                    <div class="card center">
                        <h2>Connexion</h2>
                        <p class="page-subtitle">Utilisez vos identifiants du domaine pour accéder au portail.</p>
                        <form method="post" autocomplete="off" novalidate>
                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                            <input type="hidden" name="action" value="login">
                            <label class="label" for="user">Identifiant</label>
                            <input class="input" id="user" name="user" type="text" required>
                            <label class="label" for="password">Mot de passe</label>
                            <input class="input" id="password" name="password" type="password" required>
                            <?php if ($HCAPTCHA_ENABLED): ?>
                            <div style="margin:14px 0" class="h-captcha"
                                data-sitekey="<?= htmlspecialchars($HCAPTCHA_SITEKEY) ?>"></div>
                            <?php endif; ?>
                            <button class="btn" type="submit">Se connecter</button>
                        </form>
                        <?php if (!empty($FORGOT_ENABLED)): ?>
                            <div class="hr"></div>
                            <a class="link" href="forgot_password.php">Mot de passe oublié ?</a>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- PROFIL -->
                <div id="tab-profil" class="tab" style="display:none">
                    <?php if (isset($_SESSION['username'])): ?>

                        <div class="row" style="margin-bottom:8px">
                            <h2 style="margin:0">Bonjour <?= htmlspecialchars($given ?: $_SESSION['username']) ?> 👋</h2>
                            <span class="right badge">Connecté</span>
                            <?php if ($mustChange): ?><span class="badge" style="background:#7f1d1d;color:#fecaca">Changement de
                                    mot de passe requis</span><?php endif; ?>
                        </div>

                        <div class="grid grid-2">
                            <div class="card">
                                <h3>Informations du profil</h3>
                                <form method="post" autocomplete="off" novalidate>
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                    <input type="hidden" name="action" value="updateProfile">
                                    <label class="label" for="prenom">Prénom</label>
                                    <input class="input" id="prenom" name="prenom" type="text"
                                        value="<?= htmlspecialchars($given) ?>">
                                    <label class="label" for="nom">Nom</label>
                                    <input class="input" id="nom" name="nom" type="text" value="<?= htmlspecialchars($sn) ?>">
                                    <label class="label" for="mail">Email</label>
                                    <input class="input" id="mail" name="mail" type="email"
                                        value="<?= htmlspecialchars($mail) ?>">
                                    <label class="label" for="site">Site web</label>
                                    <input class="input" id="site" name="site" type="text"
                                        value="<?= htmlspecialchars($site) ?>">
                                    <label class="label" for="adresse">Adresse</label>
                                    <input class="input" id="adresse" name="adresse" type="text"
                                        value="<?= htmlspecialchars($addr) ?>">
                                    <label class="label" for="telephone">Téléphone</label>
                                    <input class="input" id="telephone" name="telephone" type="text"
                                        value="<?= htmlspecialchars($tel) ?>">
                                    <div class="small">Format FR accepté : +336XXXXXXXX ou 06XXXXXXXX</div>
                                    <div style="margin-top:12px"><button class="btn" type="submit">Mettre à jour</button></div>
                                </form>
                                <div class="hr"></div>
                                <h3>Groupes</h3>
                                <?php if ($groups): ?>
                                    <ul class="small"><?php foreach ($groups as $g): ?>
                                            <li><?= htmlspecialchars($g) ?></li><?php endforeach; ?>
                                    </ul>
                                <?php else: ?>
                                    <div class="small">Aucun groupe trouvé.</div>
                                <?php endif; ?>
                            </div>

                            <div class="card">
                                <h3>Changer de mot de passe</h3>
                                <form method="post" autocomplete="off" novalidate>
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                    <input type="hidden" name="action" value="changepw">
                                    <label class="label" for="current_password">Mot de passe actuel</label>
                                    <input class="input" id="current_password" name="current_password" type="password" required>
                                    <label class="label" for="new_password">Nouveau mot de passe</label>
                                    <input class="input" id="new_password" name="new_password" type="password" required>
                                    <label class="label" for="confirm_password">Confirmer</label>
                                    <input class="input" id="confirm_password" name="confirm_password" type="password" required>
                                    <div style="margin-top:12px"><button class="btn" type="submit">Changer</button></div>
                                </form>
                                <?php if ($mustChange): ?>
                                    <div class="small" style="margin-top:10px;color:#fca5a5">Vous devez d’abord changer le mot de
                                        passe.</div><?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- OUTILS -->
                <div id="tab-outils" class="tab" style="display:none">
                    <?php if (isset($_SESSION['username'])): ?>
                        <h2>Mes outils</h2>

                        <?php if (!$hasToolsForUser): ?>
                            <div class="card">
                                <div class="small">Aucun outil disponible pour votre compte.</div>
                            </div>
                        <?php else: ?>
                            <div class="tools">
                                <?php
                                $loginBase = $userInfo['userPrincipalName'] ?? $_SESSION['username'];
                                foreach ($visibleTools as $t):
                                    $toolId = (int) ($t['id'] ?? 0);
                                    $title = $t['title'] ?? '';
                                    $desc = $t['description'] ?? '';
                                    $url = $t['url'] ?? '#';
                                    $icon = $t['icon'] ?? '';
                                    $inst = $t['instructions'] ?? '';
                                    $instSafe = null;
                                    $hintP = $t['login_hint_prefix'] ?? '';
                                    $hintS = $t['login_hint_suffix'] ?? '';
                                    $showH = !empty($t['show_login_hint']);
                                    $loginHint = trim($hintP . $loginBase . $hintS);
                                    ?>
                                    <div class="tool">
                                        <?php if ($icon): ?><img src="<?= htmlspecialchars($icon) ?>" alt=""><?php endif; ?>
                                        <div>
                                            <div style="font-weight:700;font-size:15px"><?= htmlspecialchars($title) ?></div>
                                            <?php if ($desc): ?>
                                                <div class="small" style="margin-top:2px;opacity:.85">
                                                    <?= htmlspecialchars($desc) ?>
                                                </div>
                                            <?php endif; ?>
                                            <?php if ($showH && ($hintP || $hintS)): ?>
                                                <div class="small" style="margin-top:6px">
                                                    Identifiant attendu&nbsp;:
                                                    <code><?= htmlspecialchars($hintP) ?><strong><?= htmlspecialchars($loginBase) ?></strong><?= htmlspecialchars($hintS) ?></code>
                                                </div>
                                            <?php endif; ?>
                                            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
                                                <a class="btn" style="padding:8px 12px" target="_blank" rel="noopener noreferrer"
                                                    href="<?= htmlspecialchars($url) ?>">Ouvrir</a>
                                                <?php if ($inst): ?>
                                                    <?php
                                                    // Autoriser un HTML riche mais sur whitelist stricte.
                                                    $instSafe = sanitize_tool_instructions_html((string) $inst);
                                                    ?>
                                                    <?php if (!empty($instSafe)): ?>
                                                        <button
                                                            type="button"
                                                            class="btn"
                                                            style="padding:6px 10px;background:transparent;border:1px solid var(--border,#1f2937);color:var(--sub,#9ca3af);font-size:12px"
                                                            onclick="(function(id,btn){var el=document.getElementById(id);if(!el)return;var open=el.getAttribute('data-open')==='1';el.setAttribute('data-open',open?'0':'1');el.style.display=open?'none':'block';btn.innerText=open?'Instructions':'Masquer les instructions';})('tool-inst-<?= $toolId ?>', this);">
                                                            Instructions
                                                        </button>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </div>
                                            <?php if (!empty($instSafe)): ?>
                                                <div id="tool-inst-<?= $toolId ?>"
                                                    data-open="0"
                                                    style="display:none;margin-top:8px;padding:10px 12px;border-radius:10px;border:1px solid #1f2937;background:#020617;max-width:100%;overflow-x:auto">
                                                    <div class="small" style="font-weight:600;margin-bottom:4px;opacity:.9">
                                                        Instructions
                                                    </div>
                                                    <div class="small" style="opacity:.92;line-height:1.6">
                                                        <?= $instSafe ?>
                                                    </div>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>

                <!-- GESTION OUTILS (Admin utilisateurs) -->
                <div id="tab-tools" class="tab" style="display:none">
                    <?php if ($canUserAdmin): ?>
                        <div class="grid grid-2">
                            <!-- Liste -->
                            <div class="card">
                                <h3>Outils — Liste</h3>
                                <?php
                                try {
                                    $adminTools = tools_all($TOOL_PDO);
                                } catch (Throwable $e) {
                                    $adminTools = [];
                                }
                                if (!$adminTools): ?>
                                    <div class="small">Aucun outil configuré.</div>
                                <?php else: ?>
                                    <table class="table">
                                        <tr>
                                            <th>#</th>
                                            <th>Titre</th>
                                            <th>Groupes (CN)</th>
                                            <th>Ordre</th>
                                            <th>État</th>
                                            <th>Actions</th>
                                        </tr>
                                        <?php foreach ($adminTools as $t): ?>
                                            <tr>
                                                <td><?= (int) $t['id'] ?></td>
                                                <td><?= htmlspecialchars($t['title']) ?></td>
                                                <td class="small">
                                                    <?php $g = json_decode($t['group_cns'] ?? '[]', true);
                                                    echo $g && is_array($g) ? htmlspecialchars(implode(', ', $g)) : '— (tous)'; ?>
                                                </td>
                                                <td><?= (int) $t['sort_order'] ?></td>
                                                <td><?= !empty($t['enabled']) ? '<span class="badge" style="background:#14532d;color:#bbf7d0">Actif</span>' : '<span class="badge" style="background:#7f1d1d;color:#fecaca">Inactif</span>' ?>
                                                </td>
                                                <td class="actions">
                                                    <form method="post" class="inline">
                                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                        <input type="hidden" name="admin_action" value="tool_move">
                                                        <input type="hidden" name="id" value="<?= (int) $t['id'] ?>">
                                                        <button class="btn sm" name="dir" value="up">↑</button>
                                                        <button class="btn sm" name="dir" value="down">↓</button>
                                                    </form>
                                                    <a class="btn sm" href="?edit_tool_id=<?= (int) $t['id'] ?>#tab-tools">Éditer</a>
                                                    <form method="post" class="inline"
                                                        onsubmit="return confirm('Supprimer cet outil ?')">
                                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                        <input type="hidden" name="admin_action" value="tool_delete">
                                                        <input type="hidden" name="id" value="<?= (int) $t['id'] ?>">
                                                        <button class="btn sm">Supprimer</button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </table>
                                <?php endif; ?>
                            </div>

                            <!-- Formulaire add/edit -->
                            <div class="card">
                                <?php
                                $editId = isset($_GET['edit_tool_id']) ? (int) $_GET['edit_tool_id'] : 0;
                                $editTool = $editId ? tools_find($TOOL_PDO, $editId) : null;
                                ?>
                                <h3><?= $editTool ? 'Modifier l’outil #' . (int) $editId : 'Ajouter un outil' ?></h3>
                                <form method="post">
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                    <input type="hidden" name="admin_action" value="tool_save">
                                    <input type="hidden" name="id" value="<?= (int) ($editTool['id'] ?? 0) ?>">

                                    <label class="label">Titre</label>
                                    <input class="input" name="title" required
                                        value="<?= htmlspecialchars($editTool['title'] ?? '') ?>">

                                    <label class="label">Description</label>
                                    <input class="input" name="description"
                                        value="<?= htmlspecialchars($editTool['description'] ?? '') ?>">

                                    <label class="label">URL</label>
                                    <input class="input" name="url" required
                                        value="<?= htmlspecialchars($editTool['url'] ?? '') ?>">

                                    <label class="label">Icône (URL)</label>
                                    <input class="input" name="icon" value="<?= htmlspecialchars($editTool['icon'] ?? '') ?>">

                                    <label class="label">Groupes AD autorisés (CN, séparés par des virgules)</label>
                                    <input class="input" name="group_cns" placeholder="ex: ProxmoxUsers,ProxmoxAdmins" value="<?php
                                    $g = $editTool ? (json_decode($editTool['group_cns'] ?? '[]', true) ?: []) : [];
                                    echo htmlspecialchars(implode(',', $g));
                                    ?>">

                                    <label class="label">Ordre d’affichage (entier)</label>
                                    <input class="input" type="number" name="sort_order"
                                        value="<?= (int) ($editTool['sort_order'] ?? 1000) ?>">

                                    <label class="label">Instructions (HTML ou texte brut)</label>
                                    <textarea class="input" name="instructions" rows="4"
                                        placeholder="Ex. :&#10;- Pré-requis de connexion&#10;- Étapes à suivre&#10;Vous pouvez utiliser un sous-ensemble de HTML (&lt;p&gt;, &lt;strong&gt;, &lt;ul&gt;, &lt;li&gt;, &lt;a&gt;...)."><?= htmlspecialchars($editTool['instructions'] ?? '') ?></textarea>
                                    <div class="small" style="margin-top:4px;opacity:.8">
                                        Contenu riche autorisé : un sous-ensemble de HTML sera rendu tel quel pour l’utilisateur
                                        (pas de scripts, uniquement texte et mise en forme).
                                    </div>

                                    <div class="grid" style="grid-template-columns:1fr 1fr; gap:8px">
                                        <div>
                                            <label class="label">Préfixe identifiant</label>
                                            <input class="input" name="login_hint_prefix"
                                                value="<?= htmlspecialchars($editTool['login_hint_prefix'] ?? '') ?>">
                                        </div>
                                        <div>
                                            <label class="label">Suffixe identifiant</label>
                                            <input class="input" name="login_hint_suffix"
                                                value="<?= htmlspecialchars($editTool['login_hint_suffix'] ?? '') ?>">
                                        </div>
                                    </div>

                                    <div class="row" style="margin-top:8px">
                                        <label class="label" style="margin:0">Afficher l’indication d’identifiant</label>
                                        <input type="checkbox" name="show_login_hint" value="1"
                                            <?= !empty($editTool['show_login_hint']) ? 'checked' : '' ?>>
                                        <label class="label" style="margin-left:16px;margin:0">Activer</label>
                                        <input type="checkbox" name="enabled" value="1" <?= !empty($editTool['enabled']) ? 'checked' : '' ?>>
                                    </div>

                                    <div style="margin-top:10px"><button class="btn"
                                            type="submit"><?= $editTool ? 'Mettre à jour' : 'Créer' ?></button></div>
                                </form>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- ADMINISTRATION -->
                <!-- ADMIN — UTILISATEURS -->
                <div id="tab-admin-users" class="tab" style="display:none">
                    <?php if ($canUserAdmin): ?>

                        <!-- Recherche avancée utilisateurs -->
                        <div class="card" data-focus="users_search">
                            <h3>Recherche utilisateurs</h3>
                            <form method="get" class="grid" style="grid-template-columns:repeat(6,1fr);gap:8px">
                                <input type="hidden" name="ps" value="<?= (int) $DEFAULT_PAGE_SIZE ?>">
                                <input type="hidden" name="p" value="<?= (int) ($_GET['p'] ?? 1) ?>">

                                <div><label class="label">Prénom</label><input class="input" name="q_gn"
                                        value="<?= htmlspecialchars($_GET['q_gn'] ?? '') ?>"></div>
                                <div><label class="label">Nom</label><input class="input" name="q_sn"
                                        value="<?= htmlspecialchars($_GET['q_sn'] ?? '') ?>"></div>
                                <div><label class="label">Email</label><input class="input" name="q_mail"
                                        value="<?= htmlspecialchars($_GET['q_mail'] ?? '') ?>"></div>
                                <div><label class="label">Téléphone</label><input class="input" name="q_tel"
                                        value="<?= htmlspecialchars($_GET['q_tel'] ?? '') ?>"></div>
                                <div><label class="label">Site</label><input class="input" name="q_site"
                                        value="<?= htmlspecialchars($_GET['q_site'] ?? '') ?>"></div>
                                <div><label class="label">Description</label><input class="input" name="q_desc"
                                        value="<?= htmlspecialchars($_GET['q_desc'] ?? '') ?>"></div>

                                <div class="row" style="align-items:end">
                                    <div>
                                        <label class="label">isAdmin</label>
                                        <select class="input" name="q_admin">
                                            <?php $qa = $_GET['q_admin'] ?? ''; ?>
                                            <option value="" <?= $qa === '' ? 'selected' : '' ?>>(peu importe)</option>
                                            <option value="1" <?= $qa === '1' ? 'selected' : '' ?>>Oui</option>
                                            <option value="0" <?= $qa === '0' ? 'selected' : '' ?>>Non</option>
                                        </select>
                                    </div>
                                </div>

                                <div class="row" style="align-items:end">
                                    <div style="width:100%">
                                        <label class="label">OU</label>
                                        <?php if (!empty($ouOptions)): ?>
                                            <select class="input" name="q_ou">
                                                <option value="">(toutes)</option>
                                                <?php
                                                $qou = (string) ($_GET['q_ou'] ?? '');
                                                foreach ($ouOptions as $opt):
                                                    $dn = (string) $opt['dn'];
                                                    $sel = ($qou && strcasecmp($qou, $dn) === 0) ? ' selected' : '';
                                                    ?>
                                                    <option value="<?= htmlspecialchars($dn) ?>" <?= $sel ?>>
                                                        <?= htmlspecialchars($opt['label']) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        <?php else: ?>
                                            <input class="input" name="q_ou" placeholder="OU=...,DC=...,DC=...">
                                        <?php endif; ?>
                                    </div>
                                </div>

                                <div style="grid-column:1/-1" class="row">
                                    <div style="flex:1">
                                        <label class="label">Recherche globale (utilise * pour tout lister)</label>
                                        <input class="input" name="uq" placeholder="ex: dupont, 06*, *@domaine, *"
                                            value="<?= htmlspecialchars($_GET['uq'] ?? '') ?>">
                                    </div>
                                    <div>
                                        <label class="label">&nbsp;</label>
                                        <button class="btn" type="submit"
                                            onclick="history.replaceState(null,'','#tab-admin-users')">Rechercher</button>
                                    </div>
                                </div>
                            </form>
                            <div class="small">Par défaut la liste est vide. Saisissez au moins un critère, ou “*” pour tout
                                afficher.</div>
                        </div>

                        <!-- Fiche utilisateur sélectionné : AU-DESSUS des formulaires généraux -->
                        <?php /* Bloc legacy supprimé: gestion détaillée utilisateur par formulaires inline. */ ?>

                    <!-- Liste des utilisateurs (VIDE par défaut si pas de recherche) -->
                    <div class="card" style="margin-top:16px" data-focus="users_list">
                        <h3>Liste des utilisateurs</h3>

                        <?php
                        // pagination + recherche globale (facultative : * pour tout)
                        $p = max(1, (int) ($_GET['p'] ?? 1));
                        $ps = max(1, (int) ($_GET['ps'] ?? $DEFAULT_PAGE_SIZE));
                        $uq = trim((string) ($_GET['uq'] ?? ''));

                        $filtersPresent = ($uq !== '') || array_filter([
                            $_GET['q_gn'] ?? '',
                            $_GET['q_sn'] ?? '',
                            $_GET['q_mail'] ?? '',
                            $_GET['q_tel'] ?? '',
                            $_GET['q_site'] ?? '',
                            $_GET['q_desc'] ?? '',
                            $_GET['q_admin'] ?? '',
                            $_GET['q_ou'] ?? '',
                        ], fn($v) => trim((string) $v) !== '');

                        $users = [];
                        $hasMore = false;

                        if ($filtersPresent) {
                            $endpoint = '/users?page=' . $p . '&pageSize=' . $ps;
                            // Ne pousse pas search='*' côté API
                            if ($uq !== '' && $uq !== '*') {
                                $endpoint .= '&search=' . rawurlencode($uq);
                            }

                            $resp = callApi('GET', $endpoint, null, true);

                            // 1) Charger d'abord les résultats
                            $users = (!$resp['error'] && is_array($resp['data'])) ? $resp['data'] : [];
                            $hasMore = !empty($resp['headers']['x-has-more'])
                                && strtolower($resp['headers']['x-has-more']) === 'true';

                            // 2) Filtre "recherche globale" côté PHP (fallback/renfort)
                            if ($uq !== '' && $uq !== '*') {
                                $needle = mb_strtolower($uq);
                                $hasWildcard = strpbrk($needle, '*?') !== false;

                                $toRegex = function (string $pat) {
                                    $pat = preg_quote($pat, '/');
                                    $pat = str_replace(['\*', '\?'], ['.*', '.'], $pat);
                                    return '/' . $pat . '/iu';
                                };
                                $re = $hasWildcard ? $toRegex($needle) : null;

                                $fields = [
                                    'sAMAccountName',
                                    'userPrincipalName',
                                    'givenName',
                                    'sn',
                                    'mail',
                                    'telephoneNumber',
                                    'wwwhomepage',
                                    'description',
                                    'dn'
                                ];

                                $users = array_values(array_filter($users, function ($u) use ($fields, $needle, $hasWildcard, $re) {
                                    foreach ($fields as $k) {
                                        $v = $u[$k] ?? '';
                                        if (is_array($v))
                                            $v = implode(' ', $v);
                                        $val = mb_strtolower((string) $v);
                                        if ($hasWildcard ? preg_match($re, $val) : str_contains($val, $needle)) {
                                            return true;
                                        }
                                    }
                                    return false;
                                }));
                            }

                            // 3) Autres filtres (prénom, nom, etc.)
                            $want = [
                                'gn' => mb_strtolower(trim((string) ($_GET['q_gn'] ?? ''))),
                                'sn' => mb_strtolower(trim((string) ($_GET['q_sn'] ?? ''))),
                                'mail' => mb_strtolower(trim((string) ($_GET['q_mail'] ?? ''))),
                                'tel' => mb_strtolower(trim((string) ($_GET['q_tel'] ?? ''))),
                                'site' => mb_strtolower(trim((string) ($_GET['q_site'] ?? ''))),
                                'desc' => mb_strtolower(trim((string) ($_GET['q_desc'] ?? ''))),
                                'adm' => trim((string) ($_GET['q_admin'] ?? '')), // '','0','1'
                                'ou' => trim((string) ($_GET['q_ou'] ?? '')),
                            ];

                            $users = array_values(array_filter($users, function ($u) use ($want) {
                                $ok = true;
                                if ($want['gn'] !== '')
                                    $ok = $ok && str_contains(mb_strtolower((string) ($u['givenName'] ?? '')), $want['gn']);
                                if ($want['sn'] !== '')
                                    $ok = $ok && str_contains(mb_strtolower((string) ($u['sn'] ?? '')), $want['sn']);
                                if ($want['mail'] !== '')
                                    $ok = $ok && str_contains(mb_strtolower((string) ($u['mail'] ?? '')), $want['mail']);
                                if ($want['tel'] !== '')
                                    $ok = $ok && str_contains(mb_strtolower((string) ($u['telephoneNumber'] ?? '')), $want['tel']);
                                if ($want['site'] !== '')
                                    $ok = $ok && str_contains(mb_strtolower((string) ($u['wwwhomepage'] ?? '')), $want['site']);
                                if ($want['desc'] !== '')
                                    $ok = $ok && str_contains(mb_strtolower((string) ($u['description'] ?? '')), $want['desc']);
                                if ($want['adm'] !== '')
                                    $ok = $ok && (bool) !empty($u['isAdmin']) === ($want['adm'] === '1');
                                if ($want['ou'] !== '')
                                    $ok = $ok && isset($u['dn']) && dn_is_descendant($want['ou'], (string) $u['dn']);
                                return $ok;
                            }));
                        }
                        ?>

                        <?php if (!$filtersPresent): ?>
                            <div class="small">La liste est vide tant qu’aucune recherche n’est effectuée (utilisez « * » pour
                                tout afficher).</div>
                        <?php elseif (!$users): ?>
                            <div class="small">Aucun utilisateur trouvé.</div>
                        <?php else: ?>

                            <!-- FORMULAIRE D'ACTION DE MASSE (isolé, pas d'imbrication) -->
                            <form id="bulkForm" method="post">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="bulk_users">

                                <div class="row" style="gap:8px; margin:8px 0">
                                    <select class="input" id="bulk-action" name="bulk_action" style="max-width:220px">
                                        <option value="disable">Désactiver</option>
                                        <option value="enable">Activer</option>
                                        <option value="unlock">Déverrouiller</option>
                                        <option value="delete">Supprimer</option>
                                        <option value="move">Déplacer vers une OU…</option>
                                    </select>

                                    <div id="bulk-ou-wrap" style="display:none; max-width:520px; width:100%">
                                        <div class="row" style="gap:8px">
                                            <label class="label" style="margin:0">OU cible</label>
                                            <?php if (!empty($ouOptions)): ?>
                                                <select class="input" name="bulk_move_ou" style="flex:1">
                                                    <option value="">— Choisir une OU —</option>
                                                    <?php foreach ($ouOptions as $opt): ?>
                                                        <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                            <?= htmlspecialchars($opt['label']) ?>
                                                        </option>
                                                    <?php endforeach; ?>
                                                </select>
                                            <?php else: ?>
                                                <input class="input" name="bulk_move_ou" placeholder="OU=...,DC=...,DC=..."
                                                    style="flex:1">
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <button class="btn" type="submit" onclick="history.replaceState(null,'','#tab-admin-users')">
                                        Appliquer à la sélection
                                    </button>
                                </div>
                            </form>
                            <!-- /FORMULAIRE D'ACTION DE MASSE -->

                            <table class="table">
                                <tr>
                                    <th style="width:36px">
                                        <input id="sel-all" type="checkbox" title="Tout sélectionner">
                                    </th>
                                    <th>sAM</th>
                                    <th>Prénom</th>
                                    <th>Nom</th>
                                    <th>Email</th>
                                    <th>Tél</th>
                                    <th>isAdmin</th>
                                    <th>État</th>
                                    <th style="width:360px">Actions</th>
                                </tr>

                                <?php foreach ($users as $u):
                                    $sam = htmlspecialchars($u['sAMAccountName'] ?? '');
                                    $gn = htmlspecialchars($u['givenName'] ?? '');
                                    $snv = htmlspecialchars($u['sn'] ?? '');
                                    $em = htmlspecialchars($u['mail'] ?? '');
                                    $ph = htmlspecialchars($u['telephoneNumber'] ?? '');
                                    $disabled = !empty($u['disabled']);
                                    $isAdm = !empty($u['isAdmin']);
                                    $state = $disabled
                                        ? '<span class="badge" style="background:#7f1d1d;color:#fecaca">Désactivé</span>'
                                        : '<span class="badge" style="background:#14532d;color:#bbf7d0">Actif</span>';
                                    $link = '?exq=' . urlencode($sam) . '&extype=user#tab-explorer';
                                    ?>
                                    <tr>
                                        <!-- NB: associe explicitement la case au formulaire bulk -->
                                        <td><input type="checkbox" form="bulkForm" name="sel[]" value="<?= $sam ?>"></td>
                                        <td><?= $sam ?></td>
                                        <td><?= $gn ?></td>
                                        <td><?= $snv ?></td>
                                        <td><?= $em ?></td>
                                        <td><?= $ph ?></td>
                                        <td><?= $isAdm ? '<span class="badge">Oui</span>' : '<span class="badge">Non</span>' ?></td>
                                        <td><?= $state ?></td>
                                        <td class="actions">
                                            <a class="btn sm" href="<?= $link ?>">Explorer AD</a>

                                            <?php if ($disabled): ?>
                                                <form method="post" class="inline">
                                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                    <input type="hidden" name="admin_action" value="enable_user">
                                                    <input type="hidden" name="persist_selected_sam" value="<?= htmlspecialchars($sam) ?>">
                                                    <input type="hidden" name="sam_toggle" value="<?= htmlspecialchars($sam) ?>">
                                                    <button class="btn sm" type="submit">Activer</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" class="inline">
                                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                    <input type="hidden" name="admin_action" value="disable_user">
                                                    <input type="hidden" name="persist_selected_sam" value="<?= htmlspecialchars($sam) ?>">
                                                    <input type="hidden" name="sam_toggle" value="<?= htmlspecialchars($sam) ?>">
                                                    <button class="btn sm" type="submit">Désactiver</button>
                                                </form>
                                            <?php endif; ?>

                                            <form method="post" class="inline" title="Efface le verrouillage si présent.">
                                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                <input type="hidden" name="admin_action" value="unlock_user">
                                                <input type="hidden" name="persist_selected_sam" value="<?= htmlspecialchars($sam) ?>">
                                                <input type="hidden" name="sam_unlock" value="<?= htmlspecialchars($sam) ?>">
                                                <button class="btn sm" type="submit">Déverrouiller</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </table>

                            <div class="pagination">
                                <?php if ($p > 1): ?>
                                    <a class="btn"
                                        href="<?= htmlspecialchars(preg_replace('/([?#].*)?$/', '', $_SERVER['REQUEST_URI'])) ?>?<?= http_build_query(array_merge($_GET, ['p' => $p - 1])) ?>#tab-admin-users">Précédent</a>
                                <?php endif; ?>
                                <span class="small">Page <?= $p ?></span>
                                <?php if ($hasMore): ?>
                                    <a class="btn"
                                        href="<?= htmlspecialchars(preg_replace('/([?#].*)?$/', '', $_SERVER['REQUEST_URI'])) ?>?<?= http_build_query(array_merge($_GET, ['p' => $p + 1])) ?>#tab-admin-users">Suivant</a>
                                <?php endif; ?>
                            </div>

                        <?php endif; ?>
                    </div>

                    <!-- Formulaires UTILISATEURS legacy supprimés (doublon avec modales Explorateur AD). -->

                <?php endif; ?>
            </div>

            <!-- EXPLORATEUR AD (arbre) -->
            <div id="tab-explorer" class="tab" style="display:none">
                <?php if ($canDomainAdmin): ?>
                    <h2>Explorateur Active Directory</h2>
                    <p class="page-subtitle" style="margin-bottom:16px">
                        Exploration complète du périmètre AD autorisé (BaseDn): OU, conteneurs, groupes, utilisateurs, inetOrgPerson, ordinateurs.
                    </p>
                    <div class="small" style="margin-bottom:12px">
                        BaseDn actif :
                        <code><?= htmlspecialchars((string) ($adMeta['baseDn'] ?? ($adTree['explorerBaseDn'] ?? $adTree['baseDn'] ?? 'inconnu'))) ?></code>
                    </div>
                    <form method="get" class="row" style="gap:8px; margin-bottom:12px; align-items:end">
                        <div style="min-width:300px;flex:1">
                            <label class="label">Recherche objet AD (nom, DN, classe)</label>
                            <input class="input" name="exq" value="<?= htmlspecialchars($explorerQuery) ?>" placeholder="ex: DUPONT, PC-01, OU=Support, group">
                        </div>
                        <div>
                            <label class="label">Type recherché</label>
                            <select class="input" name="extype">
                                <option value="all" <?= $explorerTypeFilter === 'all' ? 'selected' : '' ?>>Tous</option>
                                <option value="user" <?= $explorerTypeFilter === 'user' ? 'selected' : '' ?>>Utilisateur</option>
                                <option value="inetorgperson" <?= $explorerTypeFilter === 'inetorgperson' ? 'selected' : '' ?>>Personne</option>
                                <option value="computer" <?= $explorerTypeFilter === 'computer' ? 'selected' : '' ?>>Ordinateur</option>
                                <option value="group" <?= $explorerTypeFilter === 'group' ? 'selected' : '' ?>>Groupe</option>
                                <option value="ou" <?= $explorerTypeFilter === 'ou' ? 'selected' : '' ?>>OU</option>
                                <option value="container" <?= $explorerTypeFilter === 'container' ? 'selected' : '' ?>>Conteneur</option>
                                <option value="domain" <?= $explorerTypeFilter === 'domain' ? 'selected' : '' ?>>Domaine</option>
                            </select>
                        </div>
                        <div>
                            <label class="label">Trier par</label>
                            <select class="input" name="tree_sort">
                                <option value="name" <?= $explorerTreeSortBy === 'name' ? 'selected' : '' ?>>Nom</option>
                                <option value="type" <?= $explorerTreeSortBy === 'type' ? 'selected' : '' ?>>Type</option>
                                <option value="dn" <?= $explorerTreeSortBy === 'dn' ? 'selected' : '' ?>>DN</option>
                            </select>
                        </div>
                        <div>
                            <label class="label">Ordre</label>
                            <select class="input" name="tree_dir">
                                <option value="asc" <?= $explorerTreeSortDir === 'asc' ? 'selected' : '' ?>>Croissant</option>
                                <option value="desc" <?= $explorerTreeSortDir === 'desc' ? 'selected' : '' ?>>Décroissant</option>
                            </select>
                        </div>
                        <div>
                            <button class="btn" type="submit" onclick="history.replaceState(null,'','#tab-explorer')">Rechercher / Trier</button>
                        </div>
                    </form>
                    <div class="ad-explorer">
                        <div class="card ad-tree-card">
                            <h3 style="margin-top:0">Arborescence</h3>
                            <div class="ad-tree" id="ad-tree">
                                <?php
                                $nodes = [];
                                if (!empty($adTree) && is_array($adTree)) {
                                    $nodes = $adTree['nodes'] ?? [];
                                }
                                if ($nodes) {
                                    $baseDnNode = (string) ($adMeta['baseDn'] ?? ($adTree['explorerBaseDn'] ?? $adTree['baseDn'] ?? ''));
                                    if ($baseDnNode !== '') {
                                        $root = [[
                                            'name' => 'Racine',
                                            'dn' => $baseDnNode,
                                            'type' => 'domain',
                                            'hasChildren' => true,
                                            'children' => $nodes,
                                            'description' => 'BaseDn actif',
                                            'objectClasses' => ['domainDNS'],
                                        ]];
                                        render_ad_tree_nodes($root);
                                    } else {
                                        render_ad_tree_nodes($nodes);
                                    }
                                } else {
                                    if ($explorerQuery !== '' || $explorerTypeFilter !== 'all') {
                                        echo '<div class="small">Aucun objet ne correspond aux filtres courants. Ajustez la recherche ou le type.</div>';
                                    } else {
                                        echo '<div class="small">Arborescence indisponible (échec de /tree). Vérifiez la connectivité API/LDAP.</div>';
                                    }
                                }
                                ?>
                            </div>
                        </div>
                        <div class="card ad-details-card">
                            <h3 style="margin-top:0">Détails de l’objet</h3>
                            <div id="ad-details" class="small">
                                Sélectionnez un objet dans l’arborescence pour afficher ses informations (DN, type, chemins).
                            </div>
                            <div id="ad-actions" class="ad-actions">
                                <div class="small">Sélectionnez un objet pour afficher les actions disponibles.</div>
                            </div>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="card">
                        <div class="small">Accès réservé aux administrateurs du domaine.</div>
                    </div>
                <?php endif; ?>
            </div>
            <div id="explorer-modal" class="modal-backdrop" onclick="if(event.target===this) closeExplorerModal()">
                <div class="modal-card">
                    <div class="modal-head">
                        <h3 id="explorer-modal-title">Action</h3>
                        <button type="button" class="btn sm" onclick="closeExplorerModal()">Fermer</button>
                    </div>
                    <div id="explorer-modal-body"></div>
                </div>
            </div>

            <!-- ADMIN — DOMAINE -->
            <div id="tab-admin-domain" class="tab" style="display:none">
                <?php if ($canDomainAdmin): ?>
                    <p class="page-subtitle" style="margin-bottom:20px">Gestion des unités d’organisation (OU), des groupes et de la protection des OU. Vous pouvez créer, modifier, déplacer ou supprimer des OU (vides et non protégées), et gérer les groupes (création, suppression, ajout/retrait de membres).</p>

                    <!-- Groupes — Recherche & Gestion (globale) + OU -->
                    <div class="grid grid-2" style="margin-top:0">
                        <!-- Groupes — Recherche & Gestion (globale) -->
                        <div class="card" data-focus="groups_global">
                            <h3>Groupes — Recherche & Gestion</h3>

                            <form method="post" class="row" style="gap:8px">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="search_groups_global">
                                <input type="hidden" name="gpG" value="<?= htmlspecialchars((string) ($_GET['gpG'] ?? 1)) ?>">
                                <input type="hidden" name="gpsG"
                                    value="<?= htmlspecialchars((string) ($_GET['gpsG'] ?? 50)) ?>">
                                <input class="input" name="group_query"
                                    placeholder="Rechercher un groupe (utilisez * pour tout lister)"
                                    value="<?= htmlspecialchars($groupQueryGlobal ?: ($_GET['gqG'] ?? '')) ?>">
                                <button class="btn sm" type="submit">Rechercher</button>
                            </form>

                            <?php if ($groupQueryGlobal !== '' || isset($_GET['gqG'])): ?>
                                <div class="small" style="margin-top:8px">
                                    Résultats pour
                                    <code><?= htmlspecialchars($groupQueryGlobal ?: ($_GET['gqG'] ?? '')) ?></code>
                                    — page <?= (int) ($_GET['gpG'] ?? 1) ?> (<?= (int) ($_GET['gpsG'] ?? 50) ?>/page)
                                </div>
                                <?php if (!empty($groupResultsGlobal)): ?>
                                    <table class="table" style="margin-top:8px">
                                        <tr>
                                            <th>CN</th>
                                            <th>sAM</th>
                                            <th>DN</th>
                                        </tr>
                                        <?php foreach ($groupResultsGlobal as $g): ?>
                                            <tr>
                                                <td><?= htmlspecialchars($g['name'] ?? '') ?></td>
                                                <td><?= htmlspecialchars($g['sam'] ?? '') ?></td>
                                                <td><code><?= htmlspecialchars($g['dn'] ?? '') ?></code></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </table>
                                <?php else: ?>
                                    <div class="small" style="margin-top:8px">Aucun groupe trouvé.</div>
                                <?php endif; ?>
                            <?php endif; ?>

                            <div class="hr"></div>

                            <h4>Créer un groupe</h4>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="create_group">
                                <label class="label">OU de création</label>
                                <?php if (!empty($ouOptions)): ?>
                                    <select class="input" name="group_ouDn" required>
                                        <option value="">— Choisir une OU —</option>
                                        <?php foreach ($ouOptions as $opt): ?>
                                            <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                <?= htmlspecialchars($opt['label']) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                <?php else: ?>
                                    <input class="input" name="group_ouDn" placeholder="OU=...,DC=...,DC=..." required>
                                <?php endif; ?>
                                <label class="label">CN du groupe</label>
                                <input class="input" name="group_cn" placeholder="Mon Groupe" required>
                                <label class="label">sAMAccountName (optionnel)</label>
                                <input class="input" name="group_sam" placeholder="MonGroupe">
                                <div style="margin-top:10px"><button class="btn" type="submit">Créer le groupe</button>
                                </div>
                            </form>

                            <div class="hr"></div>

                            <h4>Supprimer un groupe</h4>
                            <form method="post" onsubmit="return confirm('Confirmer la suppression du groupe ?')">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="delete_group">
                                <label class="label">Identifiant (DN ou sAM)</label>
                                <input class="input" name="group_del_id" placeholder="CN=...,OU=...,DC=...  ou  NomCourtGroupe"
                                    required>
                                <div style="margin-top:10px"><button class="btn" type="submit">Supprimer le groupe</button>
                                </div>
                            </form>
                        </div>

                        <!-- OU — Gestion -->
                        <!-- OU — Gestion -->
                        <div class="card" data-focus="ou_manage" style="grid-column:1/-1">
                            <h3>OU — Gestion</h3>

                            <?php
                            // Map DN -> meta pour remplissage instantané
                            $ouByDn = [];
                            foreach ($ouOptions as $opt)
                                $ouByDn[strtoupper($opt['dn'])] = $opt;
                            $selOuDn = trim((string) ($_GET['ouSel'] ?? ''));
                            $selMeta = $selOuDn ? ($ouByDn[strtoupper($selOuDn)] ?? null) : null;
                            ?>

                            <form method="get" class="row" style="gap:8px; align-items:end">
                                <!-- conserve l’ancre -->
                                <input type="hidden" name="af" value="ou_manage">
                                <div style="flex:1">
                                    <label class="label">Sélectionner une OU</label>
                                    <select class="input" name="ouSel" onchange="this.form.submit()">
                                        <option value="">— Choisir —</option>
                                        <?php foreach ($ouOptions as $opt):
                                            if (($opt['kind'] ?? '') !== 'ou')
                                                continue; // on ne travaille que sur des OU
                                            $dn = (string) $opt['dn'];
                                            $sel = ($selOuDn && strcasecmp($selOuDn, $dn) === 0) ? ' selected' : '';
                                            ?>
                                            <option value="<?= htmlspecialchars($dn) ?>" <?= $sel ?>>
                                                <?= htmlspecialchars($opt['label']) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <?php if ($selMeta): ?>
                                    <span class="badge">DN sélectionné&nbsp;:
                                        <code><?= htmlspecialchars($selOuDn) ?></code></span>
                                <?php endif; ?>
                            </form>

                            <?php if (!$selMeta): ?>
                                <div class="small" style="margin-top:8px">Choisissez une OU pour voir et appliquer des actions.
                                </div>
                            <?php else: ?>
                                <div class="hr"></div>

                                <div class="small" style="opacity:.9">
                                    <div><strong>OU :</strong> <?= htmlspecialchars($selMeta['label'] ?? '') ?></div>
                                    <div style="margin-top:4px"><strong>Description actuelle :</strong>
                                        <?= ($selMeta['desc'] ?? '') !== '' ? nl2br(htmlspecialchars($selMeta['desc'])) : '—' ?>
                                    </div>
                                </div>

                                <div class="grid grid-2" style="margin-top:10px">
                                    <!-- Mettre à jour l’OU (rename / move / desc / protected) -->
                                    <div class="card">
                                        <h4>Modifier l’OU sélectionnée</h4>
                                        <form method="post">
                                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                            <input type="hidden" name="admin_action" value="update_ou">
                                            <input type="hidden" name="ou_dn" value="<?= htmlspecialchars($selOuDn) ?>">

                                            <label class="label">Nouveau nom (facultatif)</label>
                                            <input class="input" name="ou_new_name" placeholder="Nouveau nom">

                                            <label class="label">Nouveau parent (facultatif)</label>
                                            <select class="input" name="ou_new_parent">
                                                <option value="">— Ne pas déplacer —</option>
                                                <?php foreach ($ouOptions as $opt):
                                                    // on peut déplacer dans une OU ou container de destination
                                                    if (!in_array($opt['kind'] ?? '', ['ou', 'container', 'domain'], true))
                                                        continue;
                                                    // éviter de proposer le DN actuel comme parent
                                                    if (strcasecmp($opt['dn'], $selOuDn) === 0)
                                                        continue;
                                                    ?>
                                                    <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                        <?= htmlspecialchars($opt['label']) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>

                                            <label class="label">Description</label>
                                            <input class="input" name="ou_desc_mod"
                                                value="<?= htmlspecialchars($selMeta['desc'] ?? '') ?>"
                                                placeholder="Laisser vide pour ne pas modifier">
                                            <div class="row" style="margin-top:6px">
                                                <input type="checkbox" id="ou_desc_clear" name="ou_desc_clear" value="1">
                                                <label for="ou_desc_clear" class="label" style="margin:0">Vider la
                                                    description</label>
                                            </div>

                                            <label class="label">Protection de l’OU</label>
                                            <select class="input" name="ou_protected_mod">
                                                <option value="">— Ne pas changer —</option>
                                                <option value="1">Protéger (empêche la suppression par l’API)</option>
                                                <option value="0">Ne pas protéger</option>
                                            </select>

                                            <div style="margin-top:10px"><button class="btn" type="submit">Enregistrer</button>
                                            </div>
                                        </form>
                                    </div>

                                    <!-- Supprimer l’OU -->
                                    <div class="card">
                                        <h4>Supprimer l’OU sélectionnée</h4>
                                        <form method="post" onsubmit="return confirm('Supprimer définitivement cette OU ?')">
                                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                            <input type="hidden" name="admin_action" value="delete_ou">
                                            <input type="hidden" name="ou_del_dn" value="<?= htmlspecialchars($selOuDn) ?>">
                                            <div class="small">DN : <code><?= htmlspecialchars($selOuDn) ?></code></div>
                                            <div class="row" style="margin-top:6px">
                                                <label class="label" style="margin:0">Forcer la suppression récursive
                                                    (dangereux)</label>
                                                <input type="checkbox" name="ou_del_force" value="1">
                                            </div>
                                            <div style="margin-top:10px"><button class="btn" type="submit">Supprimer
                                                    l’OU</button></div>
                                        </form>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <div class="hr"></div>

                            <!-- Créer une OU (inchangé, mais on filtre visuellement les cibles valides) -->
                            <h4>Créer une OU</h4>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="create_ou">
                                <label class="label">Parent</label>
                                <?php if (!empty($ouOptions)): ?>
                                    <select class="input" name="ou_parent_dn" required>
                                        <option value="">— Choisir —</option>
                                        <?php foreach ($ouOptions as $opt):
                                            if (!in_array($opt['kind'] ?? '', ['ou', 'container', 'domain'], true))
                                                continue; ?>
                                            <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                <?= htmlspecialchars($opt['label']) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                <?php else: ?>
                                    <input class="input" name="ou_parent_dn" placeholder="OU=...,DC=...,DC=..." required>
                                <?php endif; ?>
                                <label class="label">Nom de l'OU</label>
                                <input class="input" name="ou_name" placeholder="Ex: Comptabilité" required>
                                <label class="label">Description (optionnel)</label>
                                <input class="input" name="ou_desc" placeholder="Description">
                                <div class="row" style="margin-top:6px">
                                    <label class="label" style="margin:0">Protéger l’OU (empêche la suppression par l’API)</label>
                                    <input type="checkbox" name="ou_protected" value="1">
                                </div>
                                <div style="margin-top:10px"><button class="btn" type="submit">Créer l’OU</button></div>
                            </form>
                        </div>

                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
    <footer style="margin-top:24px;padding:8px 16px;font-size:12px;opacity:.65;text-align:center;">
        ADSelfService intranet PHP v<?= htmlspecialchars($APP_VERSION, ENT_QUOTES, 'UTF-8') ?>
    </footer>
</body>

</html>