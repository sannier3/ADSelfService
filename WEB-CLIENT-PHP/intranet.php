<?php
// intranet.php — Auth, profile, tools, administration
// ADSelfService intranet version (keep in sync with GitHub releases)
$APP_VERSION = '1.00.00';
// Prefer pickers over free typing for groups & OUs (via /groups and /tree)
// Production: do not expose PHP errors to the client (server log only).
// Local diagnostics: error_reporting(E_ALL); ini_set('display_errors', '1');
error_reporting(0);

/* ================================
   Config — PHP files
   - config-intranet.php          (custom, required)
   - config-intranet-default.php  (demo defaults)
=================================== */
function intranet_send_security_headers(): void
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY'); // fallback for older browsers
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    header('Cache-Control: no-store'); // authenticated pages
    // CSP: adjust the list to your exact domains
    // header("Content-Security-Policy: default-src 'self' https:; img-src 'self' data: https:; script-src 'self' https://hcaptcha.com https://*.hcaptcha.com; frame-src https://hcaptcha.com https://*.hcaptcha.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests");
}

function fatal_config(string $msg): void
{
    if (!headers_sent()) {
        intranet_send_security_headers();
    }
    http_response_code(500);
    // simple message without relying on config
    echo "<!doctype html><meta charset='utf-8'><title>Intranet configuration</title>";
    echo "<div style='font:16px system-ui;max-width:720px;margin:40px auto;padding:16px;
                 border:1px solid #444;border-radius:12px;background:#111;color:#eee'>
            <h2 style='margin-top:0'>Missing or invalid configuration</h2>
            <p>" . htmlspecialchars($msg, ENT_QUOTES) . "</p>
            <p>Create <code>config-intranet.php</code> by copying
               <code>config-intranet-default.php</code>, then customize it.</p>
          </div>";
    exit;
}

$cfgFile = __DIR__ . '/config-intranet.php';
$defFile = __DIR__ . '/config-intranet-default.php';

if (!is_file($defFile)) {
    fatal_config("Missing file 'config-intranet-default.php'.");
}
if (!is_file($cfgFile)) {
    fatal_config("Missing file 'config-intranet.php'.");
}

$CONFIG = require $cfgFile;
if (!is_array($CONFIG)) {
    fatal_config("'config-intranet.php' must return a PHP array (return [...]).");
}

/* Detect default / placeholder config:
   - __IS_DEFAULT === true  => abort
   - or secret still on placeholder value
*/
if (!empty($CONFIG['__IS_DEFAULT'])) {
    fatal_config("'config-intranet.php' still has default values (__IS_DEFAULT=true).");
}
if (empty($CONFIG['API_BASE'])) {
    fatal_config("'API_BASE' is not set in 'config-intranet.php'.");
}
if (
    empty($CONFIG['INTERNAL_SHARED_SECRET'])
    || stripos((string) $CONFIG['INTERNAL_SHARED_SECRET'], 'change-me') !== false
) {
    fatal_config("'INTERNAL_SHARED_SECRET' must be customized in 'config-intranet.php'.");
}
if (strlen((string) $CONFIG['INTERNAL_SHARED_SECRET']) < 32) {
    fatal_config("'INTERNAL_SHARED_SECRET' must be at least 32 characters.");
}

intranet_send_security_headers();

// PHP session: cookie lifetime + gc (SESSION_LIFETIME_MINUTES in config, default 720 = 12 h).
$sessionLifetimeMinutes = (int) ($CONFIG['SESSION_LIFETIME_MINUTES'] ?? 720);
if ($sessionLifetimeMinutes < 1) {
    $sessionLifetimeMinutes = 720;
}
$sessionLifetime = $sessionLifetimeMinutes * 60;
$cookieSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => $sessionLifetime,
    'path' => '/',
    'secure' => $cookieSecure,
    'httponly' => true,
    'samesite' => 'Lax',
]);
ini_set('session.gc_maxlifetime', (string) $sessionLifetime);
session_start();
require_once __DIR__ . '/intranet-i18n.php';

/* Expected variables for the rest of the code */
$TRUSTED_PROXIES = array_filter(array_map('trim', explode(',', (string) ($CONFIG['TRUSTED_PROXIES'] ?? ''))));
$CLIENT_IP_HEADER = (string) ($CONFIG['CLIENT_IP_HEADER'] ?? 'X-Forwarded-For');

$FORGOT_ENABLED = (bool) ($CONFIG['FORGOT_PASSWORD_ENABLED'] ?? true);

$SHOW_CLIENT_IP = (bool) ($CONFIG['SHOW_CLIENT_IP'] ?? true);

$API_BASE = (string) $CONFIG['API_BASE'];
$API_SHARED_SECRET = (string) ($CONFIG['INTERNAL_SHARED_SECRET'] ?? '');
$API_INSECURE_SKIP_VERIFY = (bool) ($CONFIG['API_INSECURE_SKIP_VERIFY'] ?? false);
if (stripos($API_BASE, 'https://') !== 0) {
    $API_INSECURE_SKIP_VERIFY = false; // no effect over HTTP; explicitly cleared
}

/** Max cURL time to the LDAP API (avoids long hangs behind a reverse proxy). */
define('API_LDAP_CURL_TIMEOUT_SEC', max(1, (int) ($CONFIG['API_LDAP_CURL_TIMEOUT_SEC'] ?? 10)));

/** Current script name (PRG redirects, AJAX fetch, consistency if the file is renamed). */
define('INTRANET_SELF', basename(__FILE__));

$HCAPTCHA_ENABLED = (bool) ($CONFIG['HCAPTCHA_ENABLED'] ?? true);
$HCAPTCHA_SITEKEY = (string) ($CONFIG['HCAPTCHA_SITEKEY'] ?? '');
$HCAPTCHA_SECRET = (string) ($CONFIG['HCAPTCHA_SECRET'] ?? '');
/** TLS verify for hcaptcha.com: false only in lab if the cert chain is broken. */
$HCAPTCHA_VERIFY_SSL = (bool) ($CONFIG['HCAPTCHA_VERIFY_SSL'] ?? true);

$DEFAULT_PAGE_SIZE = (int) ($CONFIG['ADMIN_LIST_PAGE_SIZE'] ?? 50);

// --- Login rate limit (single mechanism: file OR memory) ---
$LOGIN_RL_ENABLED = (bool) ($CONFIG['LOGIN_RL_ENABLED'] ?? true);
$LOGIN_RL_USE_FILE = (bool) ($CONFIG['LOGIN_RL_USE_FILE'] ?? true);
$LOGIN_RL_LOG_DIR = !empty($CONFIG['LOGIN_RL_LOG_DIR']) ? (string) $CONFIG['LOGIN_RL_LOG_DIR'] : (__DIR__ . '/rl_logs');
$LOGIN_RL_WINDOW_SECONDS = max(1, (int) ($CONFIG['LOGIN_RL_WINDOW_SECONDS'] ?? 1800));
$LOGIN_RL_WARN_AFTER = max(1, (int) ($CONFIG['LOGIN_RL_WARN_AFTER'] ?? 5));
$LOGIN_RL_BLOCK_AFTER = max(1, (int) ($CONFIG['LOGIN_RL_BLOCK_AFTER'] ?? 15));
$LOGIN_RL_MEMORY_BLOCK_SECONDS = max(1, (int) ($CONFIG['LOGIN_RL_MEMORY_BLOCK_SECONDS'] ?? 1200));

/** Intra-Sync-Key rotation: 0 = off; otherwise reissue key on GET after N minutes (session + cookie). */
$INTRA_SYNC_KEY_ROTATE_MINUTES = max(0, (int) ($CONFIG['INTRA_SYNC_KEY_ROTATE_MINUTES'] ?? 0));
/** Short grace window for the previous sync key to survive concurrent requests during rotation. */
$INTRA_SYNC_KEY_GRACE_SECONDS = max(15, (int) ($CONFIG['INTRA_SYNC_KEY_GRACE_SECONDS'] ?? 120));

// Group searches — distinct scopes
$groupQueryGlobal = '';
$groupResultsGlobal = [];
$groupsHasMoreGlobal = false;

// --- DEBUG — persisted via session ---
// ?debug=1 enables, ?debug=0 disables
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
   Utilities
=================================== */
const INTRANET_KEY_COOKIE = 'Intra-Sync-Key';

function intranet_session_key_generate(): string
{
    return bin2hex(random_bytes(32));
}

function intranet_session_key_cookie_params(): array
{
    global $sessionLifetime, $cookieSecure;
    return [
        'expires' => time() + $sessionLifetime,
        'path' => '/',
        'secure' => $cookieSecure,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
}

function intranet_session_cookie_refresh(): void
{
    if (session_id() === '') {
        return;
    }
    $params = session_get_cookie_params();
    $lifetime = max(1, (int) ($params['lifetime'] ?? 0));
    setcookie(session_name(), session_id(), [
        'expires' => time() + $lifetime,
        'path' => $params['path'] ?? '/',
        'domain' => $params['domain'] ?? '',
        'secure' => $params['secure'] ?? false,
        'httponly' => $params['httponly'] ?? true,
        'samesite' => $params['samesite'] ?? 'Lax',
    ]);
}

function intranet_session_key_accepts_cookie(string $cookieKey): bool
{
    global $INTRA_SYNC_KEY_GRACE_SECONDS;
    $sessionKey = (string) ($_SESSION['_key'] ?? '');
    if ($sessionKey !== '' && hash_equals($sessionKey, $cookieKey)) {
        return true;
    }
    $prevKey = (string) ($_SESSION['_key_prev'] ?? '');
    $prevUntil = (int) ($_SESSION['_key_prev_valid_until'] ?? 0);
    if ($prevKey === '' || $prevUntil < time()) {
        return false;
    }
    return hash_equals($prevKey, $cookieKey);
}

function intranet_session_key_rotate(): void
{
    global $INTRA_SYNC_KEY_GRACE_SECONDS;
    $currentKey = (string) ($_SESSION['_key'] ?? '');
    if ($currentKey !== '') {
        $_SESSION['_key_prev'] = $currentKey;
        $_SESSION['_key_prev_valid_until'] = time() + $INTRA_SYNC_KEY_GRACE_SECONDS;
    }
    $_SESSION['_key'] = intranet_session_key_generate();
    $_SESSION['_key_issued_at'] = time();
}

function intranet_session_key_cleanup_grace(): void
{
    if ((int) ($_SESSION['_key_prev_valid_until'] ?? 0) < time()) {
        unset($_SESSION['_key_prev'], $_SESSION['_key_prev_valid_until']);
    }
}

function intranet_session_invalidate(): void
{
    global $cookieSecure;
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
        'secure' => $cookieSecure,
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

    // Trust the forwarded header only when the request comes from a trusted proxy
    $trusted = $remote && (in_array($remote, $TRUSTED_PROXIES, true) || ip_in_cidr_list($remote, $TRUSTED_PROXIES));

    if ($trusted && $xff) {
        // "client, proxy1, proxy2" -> take first valid client IP (not a trusted proxy)
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

intranet_i18n_bootstrap();

function verifyCaptcha(string $token, string $secret, string $ip): bool
{
    global $HCAPTCHA_VERIFY_SSL;
    if ($token === '' || $secret === '')
        return false;
    $verifySsl = !empty($HCAPTCHA_VERIFY_SSL);
    $ch = curl_init('https://hcaptcha.com/siteverify');
    $post = http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $post,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => $verifySsl,
        CURLOPT_SSL_VERIFYHOST => $verifySsl ? 2 : 0,
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
        'a' => ['href', 'title', 'target', 'rel', 'class', 'style'],
        'img' => ['src', 'alt', 'title', 'width', 'height', 'loading', 'class', 'style'],
        'div' => ['class', 'style'],
        'span' => ['class', 'style'],
        'p' => ['class', 'style'],
        'ul' => ['class', 'style'],
        'ol' => ['class', 'style'],
        'li' => ['class', 'style'],
        'pre' => ['class', 'style'],
        'code' => ['class', 'style'],
        'blockquote' => ['class', 'style'],
        'strong' => ['class', 'style'],
        'b' => ['class', 'style'],
        'em' => ['class', 'style'],
        'i' => ['class', 'style'],
        'u' => ['class', 'style'],
        'br' => ['class'],
    ];

    if (!class_exists('DOMDocument')) {
        return nl2br(htmlspecialchars(strip_tags($html), ENT_QUOTES, 'UTF-8'));
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
                        if ($name === 'class') {
                            $val = preg_replace('/[^a-zA-Z0-9_\-\s]/', '', $val);
                            $val = trim(preg_replace('/\s+/', ' ', (string) $val));
                            if ($val === '') {
                                $toRemove[] = $attr->name;
                            } else {
                                $child->setAttribute($attr->name, $val);
                            }
                            continue;
                        }
                        if ($name === 'style') {
                            $safeStyle = sanitize_tool_instructions_style($val);
                            if ($safeStyle === '') {
                                $toRemove[] = $attr->name;
                            } else {
                                $child->setAttribute($attr->name, $safeStyle);
                            }
                            continue;
                        }
                        if ($name === 'href') {
                            $safeHref = intranet_sanitize_tool_href($val);
                            if ($safeHref === '') {
                                $toRemove[] = $attr->name;
                            } else {
                                $child->setAttribute($attr->name, $safeHref);
                            }
                            continue;
                        }
                        if ($name === 'src') {
                            $safeSrc = intranet_sanitize_tool_image_url($val);
                            if ($safeSrc === '') {
                                $toRemove[] = $attr->name;
                            } else {
                                $child->setAttribute($attr->name, $safeSrc);
                            }
                            continue;
                        }
                        if ($name === 'target' && !in_array(strtolower($val), ['_blank', '_self'], true)) {
                            $toRemove[] = $attr->name;
                            continue;
                        }
                        if ($name === 'loading' && !in_array(strtolower($val), ['lazy', 'eager', 'auto'], true)) {
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

function intranet_sanitize_tool_url_common(
    string $raw,
    array $allowedSchemes,
    bool $allowRelativePath,
    bool $allowAnchor,
    bool $allowDataImage
): string {
    $raw = trim($raw);
    if ($raw === '' || preg_match('/[\x00-\x1F\x7F]/', $raw)) {
        return '';
    }
    if ($allowAnchor && str_starts_with($raw, '#')) {
        return $raw;
    }
    if ($allowRelativePath && str_starts_with($raw, '/')) {
        return $raw;
    }
    if ($allowDataImage && preg_match('#^data:image/(?:png|gif|jpe?g|webp);base64,[a-z0-9+/=\s]+$#i', $raw)) {
        return preg_replace('/\s+/', '', $raw);
    }
    $scheme = strtolower((string) parse_url($raw, PHP_URL_SCHEME));
    if ($scheme === '' || !in_array($scheme, $allowedSchemes, true)) {
        return '';
    }
    return $raw;
}

function intranet_sanitize_tool_link_url(string $raw): string
{
    return intranet_sanitize_tool_url_common($raw, ['http', 'https'], true, false, false);
}

function intranet_sanitize_tool_image_url(string $raw): string
{
    return intranet_sanitize_tool_url_common($raw, ['http', 'https'], true, false, true);
}

function intranet_sanitize_tool_href(string $raw): string
{
    return intranet_sanitize_tool_url_common($raw, ['http', 'https', 'mailto', 'tel'], true, true, false);
}

function sanitize_tool_instructions_style(string $style): string
{
    $allowedProps = [
        'color',
        'background-color',
        'font-weight',
        'font-style',
        'text-decoration',
        'text-align',
        'font-size',
        'line-height',
        'margin',
        'margin-top',
        'margin-right',
        'margin-bottom',
        'margin-left',
        'padding',
        'padding-top',
        'padding-right',
        'padding-bottom',
        'padding-left',
        'border',
        'border-top',
        'border-right',
        'border-bottom',
        'border-left',
        'border-radius',
        'width',
        'height',
        'max-width',
        'min-width',
        'max-height',
        'min-height',
        'display',
        'vertical-align',
        'opacity',
        'object-fit',
        'white-space',
    ];
    $safe = [];
    foreach (explode(';', $style) as $decl) {
        $decl = trim($decl);
        if ($decl === '' || !str_contains($decl, ':')) {
            continue;
        }
        [$prop, $value] = explode(':', $decl, 2);
        $prop = strtolower(trim($prop));
        $value = trim($value);
        if (!preg_match('/^[a-z-]+$/', $prop) || !in_array($prop, $allowedProps, true)) {
            continue;
        }
        if (
            $value === ''
            || preg_match('/(?:expression|url\s*\(|@import|javascript:|vbscript:|behavior:|-moz-binding)/i', $value)
            || !preg_match('/^[#(),.%+\-\/:\s"a-zA-Z0-9]+$/', $value)
        ) {
            continue;
        }
        $safe[] = $prop . ': ' . $value;
    }
    return implode('; ', $safe);
}

/**
 * Typical cURL error codes when the API is unreachable (no usable HTTP response).
 */
function api_ldap_curl_is_unreachable(int $errno): bool
{
    static $codes = null;
    if ($codes === null) {
        $codes = [
            CURLE_COULDNT_RESOLVE_HOST,
            CURLE_COULDNT_CONNECT,
            CURLE_OPERATION_TIMEDOUT,
            CURLE_GOT_NOTHING,
            CURLE_RECV_ERROR,
        ];
    }
    return in_array($errno, $codes, true);
}

function api_ldap_curl_user_message(int $errno, string $curlError): string
{
    if (api_ldap_curl_is_unreachable($errno)) {
        return __('err_api_offline');
    }
    return sprintf(__('err_network'), $curlError);
}

/**
 * Robust API call.
 * @return array{error:bool,httpCode:int,message:string,data:mixed,headers?:array,curl_errno?:int}
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
        CURLOPT_TIMEOUT => API_LDAP_CURL_TIMEOUT_SEC,
        CURLOPT_CONNECTTIMEOUT => API_LDAP_CURL_TIMEOUT_SEC,
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
        $errno = (int) curl_errno($ch);
        $err = curl_error($ch);
        curl_close($ch);
        $out = [
            'error' => true,
            'httpCode' => $httpCode ?: 0,
            'message' => api_ldap_curl_user_message($errno, $err),
            'data' => null,
            'curl_errno' => $errno,
        ];
        if ($withHeaders) {
            $out['headers'] = [];
        }
        return $out;
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
        return ['error' => true, 'httpCode' => $httpCode, 'message' => __('err_invalid_json'), 'data' => null];
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
        // Avoid logging full JSON (can be huge)
        $keys = is_array($decoded) ? implode(',', array_slice(array_keys($decoded), 0, 12)) : '';
        error_log("[callApi] data_keys: {$keys}");
    }

    return $res;
}

/**
 * Like callApi, but skips repeated timeouts when the API is already marked offline.
 */
function callApi_ldap(string $method, string $endpoint, ?array $data = null, bool $withHeaders = false): array
{
    global $ldap_api_offline;
    if (!empty($ldap_api_offline)) {
        $out = [
            'error' => true,
            'httpCode' => 0,
            'message' => __('err_api_offline'),
            'data' => null,
            'curl_errno' => CURLE_OPERATION_TIMEDOUT,
        ];
        if ($withHeaders) {
            $out['headers'] = [];
        }
        return $out;
    }
    $r = callApi($method, $endpoint, $data, $withHeaders);
    if (!empty($r['curl_errno']) && api_ldap_curl_is_unreachable((int) $r['curl_errno'])) {
        $ldap_api_offline = true;
    }
    return $r;
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

function intranet_dns_suffix_from_base_dn(string $baseDn): string
{
    if (preg_match_all('/DC=([^,]+)/i', $baseDn, $m)) {
        return strtolower(implode('.', $m[1]));
    }
    return 'local';
}

/** isAdmin from the API (camelCase / PascalCase, bool or scalar values). */
function intranet_api_user_row_is_admin(array $u): bool
{
    foreach (['isAdmin', 'IsAdmin'] as $k) {
        if (!array_key_exists($k, $u)) {
            continue;
        }
        $v = $u[$k];
        if (is_bool($v)) {
            return $v;
        }
        if (is_int($v)) {
            return $v !== 0;
        }
        if (is_string($v)) {
            $s = strtolower(trim($v));
            return $s === '1' || $s === 'true' || $s === 'yes' || $s === 'oui';
        }
    }
    return false;
}

/**
 * Security principals with sAM: merge user-groups even when the API returns type=other (objectClass quirk).
 */
function intranet_explorer_merge_should_apply_user_groups(array $data): bool
{
    $type = strtolower((string) ($data['type'] ?? ''));
    if (in_array($type, ['user', 'inetorgperson', 'computer'], true)) {
        return true;
    }
    $classes = array_map('strtolower', (array) ($data['objectClasses'] ?? []));
    if (in_array('group', $classes, true)
        || in_array('organizationalunit', $classes, true)
        || in_array('domaindns', $classes, true)) {
        return false;
    }
    $attrs = is_array($data['attributes'] ?? null) ? $data['attributes'] : [];
    $sam = trim((string) ($attrs['samAccountName'] ?? $attrs['SamAccountName'] ?? ''));
    return $type === 'other' && $sam !== '';
}

/**
 * Keep explorer details/modals in sync with the same list as "User groups" (GET /explorer/user-groups).
 */
function intranet_merge_explorer_user_groups_into_object(array &$data): void
{
    if (!intranet_explorer_merge_should_apply_user_groups($data)) {
        return;
    }
    if (!isset($data['attributes']) || !is_array($data['attributes'])) {
        $data['attributes'] = [];
    }
    $attrs = &$data['attributes'];
    $sam = trim((string) ($attrs['samAccountName'] ?? $attrs['SamAccountName'] ?? ''));
    if ($sam === '') {
        return;
    }
    $type = strtolower((string) ($data['type'] ?? ''));
    $classesLower = array_map('strtolower', (array) ($data['objectClasses'] ?? []));
    $isComputer = $type === 'computer' || in_array('computer', $classesLower, true);
    $ug = callApi('GET', '/explorer/user-groups?user=' . rawurlencode($sam));
    if (!empty($ug['error']) || !is_array($ug['data']['groups'] ?? null)) {
        return;
    }
    $dns = [];
    foreach ($ug['data']['groups'] as $g) {
        if (is_array($g) && ($g['dn'] ?? '') !== '') {
            $dns[] = (string) $g['dn'];
        }
    }
    if ($dns === []) {
        return;
    }
    $pgCur = trim((string) ($attrs['primaryGroupDn'] ?? $attrs['PrimaryGroupDn'] ?? ''));
    if ($pgCur === '') {
        $attrs['primaryGroupDn'] = $dns[0];
    }
    $attrs['memberOf'] = $dns;
    $attrs['memberOfCount'] = count($dns);
    if (($attrs['primaryGroupId'] ?? null) === null && ($attrs['PrimaryGroupId'] ?? null) === null && !$isComputer) {
        $uu = callApi('GET', '/user/' . rawurlencode($sam));
        if (empty($uu['error']) && is_array($uu['data']) && array_key_exists('primaryGroupId', $uu['data'])) {
            $attrs['primaryGroupId'] = $uu['data']['primaryGroupId'];
        }
    }
}

/**
 * Recomputes UPN when cloning if the submitted UPN still matches the source while sAMAccountName changed.
 * Must stay aligned with UserPrincipalNameCloneNormalization (C# API).
 */
function intranet_normalize_clone_user_principal_name(string $submittedUpn, string $newSam, string $sourceSam, ?string $sourceUpn): string
{
    $submittedUpn = trim($submittedUpn);
    $newSam = trim($newSam);
    $sourceSam = trim($sourceSam);
    $sourceUpn = $sourceUpn !== null ? trim($sourceUpn) : '';

    if ($submittedUpn === '' || $newSam === '') {
        return $submittedUpn;
    }
    if ($sourceUpn === '' || strpos($sourceUpn, '@') === false) {
        return $submittedUpn;
    }
    $atSrc = strpos($sourceUpn, '@');
    $srcSuffix = substr($sourceUpn, $atSrc + 1);

    if (strcasecmp($newSam, $sourceSam) === 0) {
        return $submittedUpn;
    }
    if (strcasecmp($submittedUpn, $sourceUpn) === 0) {
        return $newSam . '@' . $srcSuffix;
    }
    $atSub = strpos($submittedUpn, '@');
    if ($atSub === false || $atSub <= 0 || $atSub >= strlen($submittedUpn) - 1) {
        return $submittedUpn;
    }
    $local = substr($submittedUpn, 0, $atSub);
    $subSuffix = substr($submittedUpn, $atSub + 1);
    if (strcasecmp($local, $sourceSam) === 0 && strcasecmp($subSuffix, $srcSuffix) === 0) {
        return $newSam . '@' . $srcSuffix;
    }

    return $submittedUpn;
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
    // Return CN list (lowercase) from full DNs or plain names
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

/* ==== OU picker helpers (via /tree) ==== */
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
    $r = callApi_ldap('GET', $q);
    if ($r['error'] || !is_array($r['data']))
        return [];
    return $r['data']; // { baseDn, nodes: [...] }
}
function fetch_ad_meta(): array
{
    $r = callApi_ldap('GET', '/meta/ad');
    if ($r['error'] || !is_array($r['data']))
        return [];
    return $r['data'];
}
function fetch_ad_explorer_tree(?string $baseDn = ''): array
{
    $q = '/tree?depth=6&includeLeaves=true&maxChildren=2000';
    if ($baseDn)
        $q .= '&baseDn=' . rawurlencode($baseDn);
    $r = callApi_ldap('GET', $q);
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
        $desc = (string) ($n['description'] ?? $n['desc'] ?? '');

        $isOu = $typ === 'ou' || $typ === 'domain' || str_starts_with(strtoupper($dn), 'OU=') && !str_contains(strtoupper($dn), 'DOMAIN CONTROLLER');

        $isContainer = $typ === 'container'
            || (str_starts_with(strtoupper($dn), 'CN=')
                && preg_match('/^CN=(Users|Builtin|Managed Service Accounts|Program Data|System)/i', $dn));
        $kind = $typ === 'domain' ? 'domain' : ($isOu ? 'ou' : ($isContainer ? 'container' : 'other'));

        if ($dn !== '' && in_array($kind, ['ou', 'container', 'domain'], true)) {
            $out[] = ['dn' => $dn, 'label' => trim($prefix . $name), 'kind' => $kind, 'desc' => $desc];
        }
        if (!empty($n['children']) && is_array($n['children'])) {
            $out = array_merge($out, flatten_ou_nodes($n['children'], $prefix . '— '));
        }
    }
    return $out;
}

function render_ad_tree_nodes(array $nodes): void
{
    global $adTreeDisabledUserIndex;
    if (!$nodes) {
        return;
    }
    echo '<ul class="ad-tree-list">';
    foreach ($nodes as $n) {
        $dnRaw = (string) ($n['dn'] ?? '');
        $dn = htmlspecialchars($dnRaw, ENT_QUOTES);
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
            // Highest priority: if computer class is present, treat as PC.
            $type = 'computer';
            $typeEsc = htmlspecialchars($type, ENT_QUOTES);
        } elseif ($type === 'other') {
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
        $labelType = match ($type) {
            'user' => __('js_type_user'),
            'group' => __('js_type_group'),
            'computer' => __('js_type_computer'),
            'inetorgperson' => __('js_type_person'),
            'ou' => __('adm_exp_type_ou'),
            'domain' => __('adm_exp_type_domain'),
            'container' => __('js_type_container'),
            default => ucfirst($type),
        };

        $samRaw = (string) ($n['samAccountName'] ?? '');
        $isUserLike = in_array($type, ['user', 'inetorgperson'], true);
        $isDisabledUser = false;
        if ($isUserLike && is_array($adTreeDisabledUserIndex)) {
            if ($dnRaw !== '' && !empty($adTreeDisabledUserIndex['dn'][$dnRaw])) {
                $isDisabledUser = true;
            } elseif ($samRaw !== '') {
                $isDisabledUser = !empty($adTreeDisabledUserIndex['sam'][mb_strtolower($samRaw)]);
            }
        }

        $typeClass = 'type-' . preg_replace('/[^a-z0-9_-]/', '', $type);
        if ($typeClass === 'type-') {
            $typeClass = 'type-other';
        }

        echo '<li>';
        echo '<button type="button" class="ad-node" data-dn="' . $dn . '" data-type="' . $typeEsc . '" data-name="' . $name . '" data-sam="' . $samEsc . '" data-description="' . $descEsc . '" data-classes="' . $classesEsc . '">';
        echo '<span class="ad-node-dot ' . htmlspecialchars($typeClass, ENT_QUOTES) . '"></span>';
        echo '<span class="ad-node-label">' . $name . '</span>';
        if ($isDisabledUser) {
            echo '<span class="ad-node-status ad-node-status-disabled">' . htmlspecialchars(__('status_disabled')) . '</span>';
        }
        echo '<span class="ad-node-badge ' . htmlspecialchars($typeClass, ENT_QUOTES) . '">' . htmlspecialchars($labelType, ENT_QUOTES) . '</span>';
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
            // In real AD, many users also carry inetOrgPerson.
            // Computer objects often inherit user — exclude them explicitly here.
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
    $url = INTRANET_SELF;
    if ($focus)
        $qs['af'] = $focus; // read by JS for autoscroll
    if ($qs)
        $url .= '?' . http_build_query($qs);
    if ($tab)
        $url .= '#tab-' . $tab;
    header('Cache-Control: no-store');
    header('Location: ' . $url, true, 303); // See Other (PRG)
    exit;
}

/* ==== Login rate limit (file or memory, see LOGIN_RL_USE_FILE) ====
 * Keep logic in sync with any dev copy of this page (no shared include).
 * ==== */

function login_rl_mem_use_apcu(): bool
{
    return function_exists('apcu_fetch');
}
function login_rl_mem_key(string $user, string $ip): string
{
    $u = mb_strtolower(trim($user));
    return 'login_rl:' . sha1($u . '|' . $ip);
}
function login_rl_mem_load(string $user, string $ip): array
{
    $k = login_rl_mem_key($user, $ip);
    if (login_rl_mem_use_apcu()) {
        $v = apcu_fetch($k);
        return is_array($v) ? $v : ['count' => 0, 'first' => time(), 'blocked_until' => 0];
    }
    $v = $_SESSION['_login_rl'][$k] ?? null;
    return is_array($v) ? $v : ['count' => 0, 'first' => time(), 'blocked_until' => 0];
}
function login_rl_mem_save(string $user, string $ip, array $state, int $ttl): void
{
    $k = login_rl_mem_key($user, $ip);
    if (login_rl_mem_use_apcu()) {
        apcu_store($k, $state, $ttl);
    } else {
        $_SESSION['_login_rl'][$k] = $state;
    }
}
function login_rl_mem_reset(string $user, string $ip): void
{
    $k = login_rl_mem_key($user, $ip);
    if (login_rl_mem_use_apcu()) {
        apcu_delete($k);
    } else {
        unset($_SESSION['_login_rl'][$k]);
    }
}
/** Record a failed attempt (in-memory); returns the sliding-window count after increment. */
function login_rl_mem_register_failure(string $ip, string $user): int
{
    global $LOGIN_RL_WINDOW_SECONDS, $LOGIN_RL_BLOCK_AFTER, $LOGIN_RL_MEMORY_BLOCK_SECONDS;
    $now = time();
    $st = login_rl_mem_load($user, $ip);
    if (($now - ($st['first'] ?? $now)) > $LOGIN_RL_WINDOW_SECONDS) {
        $st = ['count' => 0, 'first' => $now, 'blocked_until' => 0];
    }
    $st['count'] = (int) ($st['count'] ?? 0) + 1;
    if ($st['count'] >= $LOGIN_RL_BLOCK_AFTER) {
        $st['blocked_until'] = $now + $LOGIN_RL_MEMORY_BLOCK_SECONDS;
    }
    $ttl = max($LOGIN_RL_WINDOW_SECONDS, $LOGIN_RL_MEMORY_BLOCK_SECONDS);
    login_rl_mem_save($user, $ip, $st, $ttl);
    return (int) $st['count'];
}

function login_rl_is_blocked(string $ip, string $username): bool
{
    global $LOGIN_RL_ENABLED, $LOGIN_RL_USE_FILE;
    if (!$LOGIN_RL_ENABLED) {
        return false;
    }
    if ($LOGIN_RL_USE_FILE) {
        return rl_file_is_blocked($ip);
    }
    $st = login_rl_mem_load($username, $ip);
    return ((int) ($st['blocked_until'] ?? 0)) > time();
}

/** After a failed login (captcha, empty fields, /auth failure): flash message to show. */
function login_rl_message_after_failure(string $ip, string $username, string $defaultSoft): string
{
    global $LOGIN_RL_ENABLED, $LOGIN_RL_USE_FILE, $LOGIN_RL_WARN_AFTER, $LOGIN_RL_BLOCK_AFTER;
    if (!$LOGIN_RL_ENABLED) {
        return $defaultSoft;
    }
    if ($LOGIN_RL_USE_FILE) {
        rl_file_log_failure($ip, $username);
        $count = rl_file_count_sliding($ip);
    } else {
        $count = login_rl_mem_register_failure($ip, $username);
    }
    if ($count >= $LOGIN_RL_BLOCK_AFTER) {
        if ($LOGIN_RL_USE_FILE) {
            rl_file_add_blocked($ip);
        }
        return login_rl_msg_hard();
    }
    if ($count >= $LOGIN_RL_WARN_AFTER) {
        return login_rl_msg_warn();
    }
    return $defaultSoft;
}

function login_rl_clear_on_success(string $ip, string $username): void
{
    global $LOGIN_RL_ENABLED, $LOGIN_RL_USE_FILE;
    if (!$LOGIN_RL_ENABLED || $LOGIN_RL_USE_FILE) {
        return;
    }
    login_rl_mem_reset($username, $ip);
}

/* ==== File storage (IP only, blocked.txt list) ==== */
function rl_file_ensure_dir(): void
{
    global $LOGIN_RL_LOG_DIR;
    if (!is_dir($LOGIN_RL_LOG_DIR)) {
        @mkdir($LOGIN_RL_LOG_DIR, 0750, true);
    }
}

/** Path to the history file for an IP (filename = md5 to avoid special characters). */
function rl_file_path(string $ip): string
{
    global $LOGIN_RL_LOG_DIR;
    rl_file_ensure_dir();
    return $LOGIN_RL_LOG_DIR . '/' . md5($ip) . '.log';
}

/** /64 prefix for IPv6 (16 hex chars); null for IPv4. */
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

/** Path to blocked IPs/prefixes file. */
function rl_file_blocked_path(): string
{
    global $LOGIN_RL_LOG_DIR;
    rl_file_ensure_dir();
    return $LOGIN_RL_LOG_DIR . '/blocked.txt';
}

/** True if the IP (or its /64 prefix for IPv6) is blocked. */
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

/** Append IP to blocked list (IPv4 = exact IP, IPv6 = /64 prefix). */
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

/** Log a failed login (captcha, bad user/password, etc.). File: first line = IP, then lines timestamp<TAB>username. */
function rl_file_log_failure(string $ip, string $username = ''): void
{
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

/** Count failures in the sliding window (LOGIN_RL_WINDOW_SECONDS). */
function rl_file_count_sliding(string $ip): int
{
    global $LOGIN_RL_WINDOW_SECONDS;
    $path = rl_file_path($ip);
    if (!is_file($path)) {
        return 0;
    }
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines || count($lines) < 2) {
        return 0;
    }
    $cutoff = time() - $LOGIN_RL_WINDOW_SECONDS;
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

/* ==== DN helpers / OU validation & account expiry ==== */
function dn_is_descendant(string $parent, string $candidate): bool
{
    $p = trim($parent, " \t\n\r\0\x0B,");
    $c = trim($candidate, " \t\n\r\0\x0B,");
    if ($p === '' || $c === '' || strcasecmp($p, $c) === 0)
        return false;
    // AD child DN ends with ",<parent DN>"
    return (bool) preg_match('/,' . preg_quote($p, '/') . '$/i', $c);
}
function ou_name_is_valid(string $name): bool
{
    // Plain name: no '=' or ',' and no leading/trailing spaces
    if ($name === '' || trim($name) !== $name)
        return false;
    if (strpbrk($name, '=,') !== false)
        return false;
    return mb_strlen($name) <= 64;
}
/** Build ISO8601 UTC "YYYY-MM-DDTHH:MM:SSZ" from date/time fields, or null if date empty */
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
/** Read account expiry from API user row (several possible field names) */
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
        // MySQL (or other PDO driver)
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
        // 1) Create table if missing
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
        // 2) Index (MySQL < 8.0: no IF NOT EXISTS on CREATE INDEX)
        try {
            $pdo->exec("CREATE INDEX idx_tools_enabled ON tools (enabled, sort_order)");
        } catch (Throwable $e) { /* ignore if index already exists */
        }

    } else { // sqlite (default)
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

    // 3) Seed when empty only on first DB creation (new SQLite file)
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
            __('ajax_login_subtitle'),
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
    // Simple sort_order swap with previous/next tool row
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
   Tools: load DB + filter by AD groups
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

    // Compute visible tools only when the user is logged in
    if (!empty($_SESSION['username'])) {
        // memberOf may be null|string|array — normalize to array
        $memberOf = $_SESSION['user_info']['memberOf'] ?? [];
        if (is_string($memberOf)) {
            $memberOf = [$memberOf];
        } elseif (!is_array($memberOf)) {
            $memberOf = [];
        }

        $userCnGroups = ad_groups_to_cn_list($memberOf); // always an array here
        $visibleTools = tools_visible_for_user($TOOL_PDO, $userCnGroups);
        $hasToolsForUser = !empty($visibleTools);
    }
} catch (Throwable $e) {
    error_log('[tools] load error: ' . $e->getMessage());
}

/* ================================
   Application flow
=================================== */
// Logout
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'logout' && csrf_ok($_POST['csrf'] ?? '')) {
    intranet_session_invalidate();
    header('Location: ' . INTRANET_SELF);
    exit;
}

// Sync key check for authenticated sessions
if (isset($_SESSION['username'])) {
    $cookieKey = $_COOKIE[INTRANET_KEY_COOKIE] ?? '';
    $sessionKey = $_SESSION['_key'] ?? '';
    if ($sessionKey === '') {
        intranet_session_invalidate();
        header('Location: ' . INTRANET_SELF);
        exit;
    }
    // Sync cookie required: do not recreate if missing (avoids valid server session without browser proof).
    if ($cookieKey === '') {
        intranet_session_invalidate();
        header('Location: ' . INTRANET_SELF);
        exit;
    }
    if (!intranet_session_key_accepts_cookie($cookieKey)) {
        intranet_session_invalidate();
        header('Location: ' . INTRANET_SELF);
        exit;
    }
    if ($INTRA_SYNC_KEY_ROTATE_MINUTES > 0) {
        $issued = (int) ($_SESSION['_key_issued_at'] ?? 0);
        if ($issued < 1) {
            $_SESSION['_key_issued_at'] = time();
        } elseif (
            ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET'
            && (time() - $issued) >= $INTRA_SYNC_KEY_ROTATE_MINUTES * 60
        ) {
            intranet_session_key_rotate();
        }
    }
    intranet_session_key_cleanup_grace();
    // Sliding expiry: refresh both PHPSESSID and Intra-Sync-Key on each valid authenticated request.
    intranet_session_cookie_refresh();
    setcookie(INTRANET_KEY_COOKIE, (string) $_SESSION['_key'], intranet_session_key_cookie_params());
}

$uiError = '';
$uiSuccess = '';
$adminMsgErr = '';
$adminMsgOk = '';
$ldap_api_offline = false;
$csrf = csrf_token();

/* ---------- LOGIN (PRG): session + Intra-Sync-Key set together after successful /auth ---------- */
if (!isset($_SESSION['username']) && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    $ip = client_ip();
    $username = trim((string) ($_POST['user'] ?? ''));

    if (login_rl_is_blocked($ip, $username)) {
        flash_set('ui', 'err', login_rl_msg_hard());
        redirect_get([], 'login');
    }

    if (!csrf_ok($_POST['csrf'] ?? '')) {
        flash_set('ui', 'err', __('msg_session_retry'));
        redirect_get([], 'login');
    }

    if ($HCAPTCHA_ENABLED && (empty($_POST['h-captcha-response']) || !verifyCaptcha($_POST['h-captcha-response'], $HCAPTCHA_SECRET, $_SERVER['REMOTE_ADDR'] ?? ''))) {
        flash_set('ui', 'err', login_rl_message_after_failure($ip, $username, __('msg_captcha_invalid')));
        redirect_get([], 'login');
    }

    $password = (string) ($_POST['password'] ?? '');
    if ($username === '' || $password === '') {
        flash_set('ui', 'err', login_rl_message_after_failure($ip, $username, __('msg_credentials_required')));
        redirect_get([], 'login');
    }

    $r = callApi('POST', '/auth', ['username' => $username, 'password' => $password]);

    $authFailMsg = null;
    if (!empty($r['curl_errno']) && api_ldap_curl_is_unreachable((int) $r['curl_errno']) && $r['message'] !== '') {
        $authFailMsg = (string) $r['message'];
    }

    if ($r['error'] || empty($r['data']['success'])) {
        flash_set('ui', 'err', login_rl_message_after_failure($ip, $username, $authFailMsg ?? __('msg_auth_failed')));
        redirect_get([], 'login');
    }

    login_rl_clear_on_success($ip, $username);
    session_regenerate_id(true);
    $_SESSION['username'] = $username;
    $_SESSION['user_info'] = $r['data']['user'] ?? [];
    $_SESSION['is_admin'] = (bool) ($r['data']['isAdmin'] ?? false);
    $_SESSION['mustChangePassword'] = (bool) ($r['data']['mustChangePassword'] ?? false);
    unset($_SESSION['_key_prev'], $_SESSION['_key_prev_valid_until']);
    $newKey = intranet_session_key_generate();
    $_SESSION['_key'] = $newKey;
    $_SESSION['_key_issued_at'] = time();
    setcookie(INTRANET_KEY_COOKIE, $newKey, intranet_session_key_cookie_params());
    flash_set('ui', 'ok', __('msg_connected'));
    redirect_get([], 'profil');
}

/* ---------- Refresh user profile when logged in ---------- */
if (isset($_SESSION['username'])) {
    $info = callApi('GET', '/user/' . rawurlencode($_SESSION['username']));
    if (!$info['error'] && is_array($info['data'])) {
        $_SESSION['user_info'] = $info['data'];
    } elseif (!empty($info['curl_errno']) && api_ldap_curl_is_unreachable((int) $info['curl_errno'])) {
        $ldap_api_offline = true;
    } elseif ($info['httpCode'] === 404) {
        flash_set('ui', 'err', __('msg_account_gone'));
        session_unset();
        session_destroy();
        redirect_get([], 'login');
    }
}

/* ---------- PROFILE ACTIONS ---------- */
if (isset($_SESSION['username']) && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'updateProfile') {
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        $uiError = __('msg_session_expired');
    } else {
        $dn = (string) ($_SESSION['user_info']['dn'] ?? '');
        if ($dn === '') {
            $uiError = __('msg_dn_not_available');
        } else {
            // Read fields (use actual form control names)
            // + presence flags so we clear only when the field was posted
            $mail = trim((string) ($_POST['mail'] ?? ''));         // not 'email'
            $site = trim((string) ($_POST['site'] ?? ''));         // not 'site_web'
            $addr = trim((string) ($_POST['adresse'] ?? ''));
            $sn = trim((string) ($_POST['nom'] ?? ''));
            $gn = trim((string) ($_POST['prenom'] ?? ''));
            $tel = trim((string) ($_POST['telephone'] ?? ''));

            // No description field for self-service profile
            // $desc = null; // ignore description for end users

            // Presence flags (do not touch LDAP attrs omitted from the form)
            $present = [
                'mail' => array_key_exists('mail', $_POST),
                'givenName' => array_key_exists('prenom', $_POST),
                'sn' => array_key_exists('nom', $_POST),
                'telephoneNumber' => array_key_exists('telephone', $_POST),
                'wWWHomePage' => array_key_exists('site', $_POST),
                'streetAddress' => array_key_exists('adresse', $_POST),
            ];

            // Basic validation
            if ($present['mail'] && $mail !== '' && !filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                $uiError = __('msg_email_invalid_basic');
            }

            $telNorm = null;
            if ($present['telephoneNumber'] && $tel !== '') {
                $telNorm = normalizePhone($tel);
                if ($telNorm === false) {
                    $uiError = __('msg_phone_invalid_fr');
                }
            }

            if (!$uiError) {
                // Current values (to know what to clear cleanly)
                $cur = $_SESSION['user_info'] ?? [];
                $has = [
                    'mail' => !empty($cur['mail']),
                    'givenName' => !empty($cur['givenName']),
                    'sn' => !empty($cur['sn']),
                    'telephoneNumber' => !empty($cur['telephoneNumber']),
                    'wWWHomePage' => !empty($cur['wwwhomepage']),
                    'streetAddress' => !empty($cur['streetAddress']),
                    // 'description' not editable by end user
                ];

                $mods = [];

                // For each attribute: update only if the field was present in POST
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

                // Do not handle 'description' here (admin only)

                if (empty($mods)) {
                    flash_set('ui', 'ok', __('msg_no_changes'));
                    redirect_get([], 'profil');
                } else {
                    $payload = ['dn' => $dn, 'modifications' => $mods];
                    $r = callApi('POST', '/user/updateProfile', $payload);
                    if ($r['error']) {
                        $uiError = api_err_detail($r, __('msg_profile_update_fail'));
                    } else {
                        flash_set('ui', 'ok', __('msg_profile_updated'));
                        redirect_get([], 'profil');
                    }
                }
            }
        }
    }
}

/* ---------- PASSWORD ACTIONS (PRG) ---------- */
if (isset($_SESSION['username']) && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'changepw') {
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        flash_set('ui', 'err', __('msg_session_expired'));
        redirect_get([], 'profil');
    }
    $cur = (string) ($_POST['current_password'] ?? '');
    $new = (string) ($_POST['new_password'] ?? '');
    $conf = (string) ($_POST['confirm_password'] ?? '');
    if ($cur === '' || $new === '' || $conf === '') {
        flash_set('ui', 'err', __('msg_all_fields_required'));
        redirect_get([], 'profil');
    }
    if ($new !== $conf) {
        flash_set('ui', 'err', __('msg_password_mismatch'));
        redirect_get([], 'profil');
    }
    $r = callApi('POST', '/user/changePassword', ['username' => $_SESSION['username'], 'currentPassword' => $cur, 'newPassword' => $new]);
    if ($r['error']) {
        flash_set('ui', 'err', api_err_detail($r, __('msg_pw_change_fail')));
    } else {
        $_SESSION['mustChangePassword'] = false;
        flash_set('ui', 'ok', __('msg_pw_changed'));
    }
    redirect_get([], 'profil');
}

$is_admin = !empty($_SESSION['is_admin']);
$userInfo = $_SESSION['user_info'] ?? [];
$memberOf = $userInfo['memberOf'] ?? [];
$memberOf = is_array($memberOf) ? $memberOf : ($memberOf ? [$memberOf] : []);
$userCnGroups = ad_groups_to_cn_list($memberOf);

// Admin group lists from config (may be empty)
$ADM_USER_GROUPS = $CONFIG['ADM_USER_GROUPS'] ?? [];
$ADM_DOMAIN_GROUPS = $CONFIG['ADM_DOMAIN_GROUPS'] ?? [];

// Allow config values as comma-separated string "g1,g2"
if (is_string($ADM_USER_GROUPS))
    $ADM_USER_GROUPS = array_values(array_filter(array_map('trim', explode(',', $ADM_USER_GROUPS)), 'strlen'));
if (is_string($ADM_DOMAIN_GROUPS))
    $ADM_DOMAIN_GROUPS = array_values(array_filter(array_map('trim', explode(',', $ADM_DOMAIN_GROUPS)), 'strlen'));

// If list is empty => only built-in is_admin passes.
// Otherwise => is_admin OR member of one listed group.
$canBy = function (array $required) use ($is_admin, $userCnGroups): bool {
    if (count($required) === 0) {
        return $is_admin; // empty list => built-in admin only
    }
    return $is_admin || hasGroup($userCnGroups, $required);
};

$canUserAdmin = $canBy($ADM_USER_GROUPS);
$canDomainAdmin = $canBy($ADM_DOMAIN_GROUPS);

// Local AJAX endpoint for explorer details (keeps API secret off the browser)
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
        echo json_encode(['error' => __('msg_ajax_dn_required')]);
        exit;
    }
    $r = callApi('GET', '/explorer/object?dn=' . rawurlencode($dn));
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, __('msg_ajax_explorer_object_failed'))]);
        exit;
    }
    $payload = $r['data'];
    if (is_array($payload)) {
        intranet_merge_explorer_user_groups_into_object($payload);
    }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
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
        echo json_encode(['error' => api_err_detail($r, __('msg_groups_search_global_failed'))]);
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
        echo json_encode(['error' => __('msg_user_required')]);
        exit;
    }
    $r = callApi('GET', '/explorer/user-groups?user=' . rawurlencode($user));
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, __('msg_ajax_user_groups_read_failed'))]);
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
        echo json_encode(['error' => api_err_detail($r, __('msg_ajax_user_search_failed'))]);
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
        echo json_encode(['error' => __('msg_group_required')]);
        exit;
    }
    $r = callApi('GET', '/explorer/group-members?group=' . rawurlencode($group));
    if (!empty($r['error'])) {
        http_response_code((int) ($r['httpCode'] ?: 500));
        echo json_encode(['error' => api_err_detail($r, __('msg_ajax_group_members_read_failed'))]);
        exit;
    }
    echo json_encode($r['data'], JSON_UNESCAPED_UNICODE);
    exit;
}


/* ================================
   Display data
=================================== */
$is_admin = !empty($_SESSION['is_admin']);
$mustChange = !empty($_SESSION['mustChangePassword']);
$userInfo = $_SESSION['user_info'] ?? [];
$clientIp = client_ip();
$groups = [];
if (!empty($userInfo['memberOf']))
    $groups = is_array($userInfo['memberOf']) ? $userInfo['memberOf'] : [$userInfo['memberOf']];
$profileGroupsDirect = $groups;
$profileGroupsEffective = [];
$profilePrimaryGroupLine = '';
if (isset($_SESSION['username'])) {
    $pr = callApi_ldap('GET', '/user/' . rawurlencode((string) $_SESSION['username']) . '?groups=effective');
    if (!$pr['error'] && is_array($pr['data'])) {
        $pd = $pr['data'];
        if (is_array($pd['memberOf'] ?? null)) {
            $profileGroupsDirect = $pd['memberOf'];
        }
        if (is_array($pd['memberOfEffective'] ?? null)) {
            $profileGroupsEffective = $pd['memberOfEffective'];
        }
        $pgDnP = (string) ($pd['primaryGroupDn'] ?? '');
        if ($pgDnP !== '') {
            $ridP = $pd['primaryGroupId'] ?? null;
            $profilePrimaryGroupLine = $pgDnP . (($ridP !== null && $ridP !== '') ? ' (RID ' . $ridP . ')' : '');
        }
    }
}
$given = $userInfo['givenName'] ?? '';
$sn = $userInfo['sn'] ?? '';
$mail = $userInfo['mail'] ?? '';
$site = $userInfo['wwwhomepage'] ?? '';
$addr = $userInfo['streetAddress'] ?? '';
$tel = $userInfo['telephoneNumber'] ?? '';
$desc = $userInfo['description'] ?? '';
$forcePwMode = isset($_SESSION['username']) && $mustChange;

/* ================================
   Admin: POST actions (PRG)
=================================== */
/* Preload OU pickers (create/move) + full tree for the AD explorer */
$ouOptions = [];
$adTree = [];
$adTreeDisabledUserIndex = null; // ['dn' => [...], 'sam' => [...]] populated when user is admin
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
$explorerRestoreDn = trim((string) ($_GET['exdn'] ?? ''));
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
                'label' => __('adm_tree_root_label'),
                'kind' => 'domain',
                'desc' => __('adm_tree_root_desc')
            ]);
    } else {
            foreach ($ouOptions as &$opt) {
                if (strcasecmp((string) ($opt['dn'] ?? ''), $explorerBaseDn) === 0) {
                    $opt['label'] = __('adm_tree_root_label');
                    break;
                }
            }
            unset($opt);
        }
    }

    // Disabled user accounts: labels in the AD tree (DN / sAM correlation)
    $adTreeDisabledUserIndex = ['dn' => [], 'sam' => []];
    if (empty($ldap_api_offline)) {
        $pageIdx = 1;
        $pageSizeIdx = 2000;
        do {
            $respIdx = callApi_ldap(
                'GET',
                '/users?page=' . $pageIdx . '&pageSize=' . $pageSizeIdx . '&groups=none',
                null,
                true
            );
            $batchIdx = (!$respIdx['error'] && is_array($respIdx['data'])) ? $respIdx['data'] : [];
            foreach ($batchIdx as $uIdx) {
                if (empty($uIdx['disabled'])) {
                    continue;
                }
                $dnIdx = (string) ($uIdx['dn'] ?? '');
                $samIdx = (string) ($uIdx['sAMAccountName'] ?? '');
                if ($dnIdx !== '') {
                    $adTreeDisabledUserIndex['dn'][$dnIdx] = true;
                }
                if ($samIdx !== '') {
                    $adTreeDisabledUserIndex['sam'][mb_strtolower($samIdx)] = true;
                }
            }
            $moreIdx = !empty($respIdx['headers']['x-has-more'])
                && strtolower((string) $respIdx['headers']['x-has-more']) === 'true';
            $pageIdx++;
        } while ($moreIdx && $pageIdx <= 60);
    }
}

if ($is_admin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_action'])) {
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        flash_set('login', 'err', __('msg_session_expired_login'));
        redirect_get([], 'login');
    }

    $act = $_POST['admin_action'];

    // User-admin actions (+ group search on user card + tools management)
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
        'move_computer',
        'delete_computer',
        'bulk_users',
        'tool_save',
        'tool_delete',
        'tool_move'
    ];

    // Domain admin actions
    $DOMAIN_ADMIN_ACTIONS = [
        'create_ou',
        'update_ou',
        'delete_ou',
        'create_group',
        'delete_group',
        'search_groups_global'
    ];

    if (in_array($act, $USER_ADMIN_ACTIONS, true) && !$canUserAdmin) {
        flash_set('admin', 'err', __('msg_admin_forbidden_users'));
        redirect_get([], 'profil');
    }
    if (in_array($act, $DOMAIN_ADMIN_ACTIONS, true) && !$canDomainAdmin) {
        flash_set('admin', 'err', __('msg_admin_forbidden_domain'));
        redirect_get([], 'profil');
    }

    // Keep persisted selection so we stay on the same user after redirect
    $persistSam = trim((string) ($_POST['persist_selected_sam'] ?? ''));
    $qsSel = $persistSam !== '' ? ['select_sam' => $persistSam] : [];
    $exFocusDn = trim((string) ($_POST['explorer_focus_dn'] ?? ''));
    if ($exFocusDn !== '') {
        $qsSel['exdn'] = $exFocusDn;
    }
    $fromExplorer = (string) ($_POST['admin_origin'] ?? '') === 'explorer';
    $tabUserAdmin = $fromExplorer ? 'explorer' : 'admin-users';
    $tabDomainAdmin = $fromExplorer ? 'explorer' : 'admin-domain';

    // --- Create user ---
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

        // New profile fields
        $desc = trim((string) ($_POST['description'] ?? ''));
        $expNever = !empty($_POST['exp_never']);
        $expDateRaw = trim((string) ($_POST['exp_date'] ?? ''));
        $expTimeRaw = trim((string) ($_POST['exp_time'] ?? ''));
        $expIso = build_iso_expiry($expDateRaw, $expTimeRaw);

        if ($mailn !== '' && !filter_var($mailn, FILTER_VALIDATE_EMAIL)) {
            flash_set('admin', 'err', __('msg_email_invalid'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'create_user');

        }
        if (!$expNever && ($expDateRaw !== '' || $expTimeRaw !== '') && !$expIso) {
            flash_set('admin', 'err', __('msg_account_exp_invalid'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'create_user');
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
            flash_set('admin', 'err', api_err_detail($r, __('msg_create_failed')));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'create_user');
        }

        // Force password change on first logon (optional)
        if (!empty($_POST['must_change_at_first_login'])) {
            $rc = callApi('POST', '/admin/changePassword', [
                'username' => $sam,
                'newPassword' => $pwd,
                'mustChangeAtNextLogon' => true
            ]);
            if ($rc['error']) {
                flash_set('admin', 'err', api_err_detail($rc, __('msg_create_must_change_failed')));
                redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'create_user');
            }
        }

        // Account expiration API
        if ($expNever) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'never' => true]);
        } elseif ($expIso) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'expiresAt' => $expIso, 'never' => false]);
        }

        $dnMsg = htmlspecialchars($r['data']['dn'] ?? '');
        $msg = sprintf(__('msg_user_created_dn'), $dnMsg);
        if (!empty($_POST['must_change_at_first_login']))
            $msg .= __('msg_user_created_must_change');
        flash_set('admin', 'ok', $msg);
        $qsCreateOk = $qsSel;
        $newUserDn = trim((string) ($r['data']['dn'] ?? ''));
        if ($newUserDn !== '') {
            $qsCreateOk['exdn'] = $newUserDn;
        }
        redirect_get($qsCreateOk, $tabUserAdmin, $fromExplorer ? null : 'create_user');
    }

    // --- Clone user (copy attributes + new account) ---
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
            flash_set('admin', 'err', __('msg_clone_fields'));
            redirect_get($qsSel, 'explorer');
        }
        if ($mailn !== '' && !filter_var($mailn, FILTER_VALIDATE_EMAIL)) {
            flash_set('admin', 'err', __('msg_clone_email'));
            redirect_get($qsSel, 'explorer');
        }
        if (!$cloneExpNever && ($cloneExpDate !== '' || $cloneExpTime !== '') && !$cloneExpIso) {
            flash_set('admin', 'err', __('msg_clone_exp'));
            redirect_get($qsSel, 'explorer');
        }

        $srcInfo = callApi('GET', '/user/' . rawurlencode($source));
        if ($srcInfo['error'] || !is_array($srcInfo['data'])) {
            flash_set('admin', 'err', api_err_detail($srcInfo, __('msg_clone_read_source')));
            redirect_get($qsSel, 'explorer');
        }
        $src = $srcInfo['data'];

        $srcUpnForClone = trim((string) ($src['userPrincipalName'] ?? ''));
        $upn = intranet_normalize_clone_user_principal_name(
            $upn,
            $sam,
            $source,
            $srcUpnForClone !== '' ? $srcUpnForClone : null
        );
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
            'cloneSourceSam' => $source,
            'cloneSourceUserPrincipalName' => $srcUpnForClone !== '' ? $srcUpnForClone : null,
        ];
        if (!empty($src['description'])) {
            $desc = is_array($src['description']) ? implode("\n", $src['description']) : (string) $src['description'];
            if (trim($desc) !== '')
                $createPayload['description'] = $desc;
        }

        $create = callApi('POST', '/admin/createUser', $createPayload);
        if ($create['error']) {
            flash_set('admin', 'err', api_err_detail($create, __('msg_clone_create_failed')));
            redirect_get($qsSel, 'explorer');
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

        $msg = __('msg_clone_ok');
        if ($applyGroups) {
            if ($groupErrors > 0) {
                $msg .= sprintf(__('msg_clone_ok_groups_err'), $groupErrors);
            } else {
                $msg .= __('msg_clone_ok_groups_ok');
            }
        }
        flash_set('admin', 'ok', $msg);
        $qsAfterClone = $qsSel;
        if ($newDn !== '') {
            $qsAfterClone['exdn'] = $newDn;
        }
        redirect_get($qsAfterClone, 'explorer');
    }

    // --- Admin password reset ---
    if ($act === 'admin_reset_pw') {
        $sam = trim((string) ($_POST['sam_reset'] ?? ''));
        $new = (string) ($_POST['new_password'] ?? '');
        $must = !empty($_POST['must_change']);

        if ($sam === '' || $new === '') {
            flash_set('admin', 'err', __('msg_fields_required'));
            redirect_get($qsSel, $tabUserAdmin);
        }

        $r = callApi('POST', '/admin/changePassword', [
            'username' => $sam,
            'newPassword' => $new,
            'mustChangeAtNextLogon' => $must
        ]);
        if ($r['error']) {
            flash_set('admin-users', 'err', api_err_detail($r, __('msg_reset_pw_failed')));
        } else {
            $msg = sprintf(__('msg_reset_pw_ok'), htmlspecialchars($sam));
            if ($must)
                $msg .= __('msg_reset_pw_must_next');
            flash_set('admin', 'ok', $msg);
        }
        redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'password_reset');
    }

    // --- Update user attributes ---
    if ($act === 'admin_update_user') {
        $sam = trim((string) ($_POST['sam_mod'] ?? ''));
        $mailn = trim((string) ($_POST['mail_mod'] ?? ''));
        $gn = trim((string) ($_POST['givenName_mod'] ?? ''));
        $snv = trim((string) ($_POST['sn_mod'] ?? ''));
        $telm = trim((string) ($_POST['tel_mod'] ?? ''));
        $addr2 = trim((string) ($_POST['addr_mod'] ?? ''));
        $site2 = trim((string) ($_POST['site_mod'] ?? ''));
        $descMod = trim((string) ($_POST['desc_mod'] ?? ''));
        $primaryGroupMod = trim((string) ($_POST['primary_group_mod'] ?? ''));

        // Account expiration
        $expNeverM = !empty($_POST['exp_never_mod']);
        $expDateM = trim((string) ($_POST['exp_date_mod'] ?? ''));
        $expTimeM = trim((string) ($_POST['exp_time_mod'] ?? ''));
        $wantSetExpiry = (!$expNeverM && ($expDateM !== '' || $expTimeM !== ''));
        $expIsoM = build_iso_expiry($expDateM, $expTimeM);

        if ($mailn !== '' && !filter_var($mailn, FILTER_VALIDATE_EMAIL)) {
            flash_set('admin', 'err', __('msg_email_invalid'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
        }

        $telNorm = null;
        if ($telm !== '') {
            $telNorm = normalizePhone($telm);
            if ($telNorm === false) {
                flash_set('admin', 'err', __('msg_phone_invalid'));
                redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
            }
        }

        if ($descMod !== '' && mb_strlen($descMod) > 1024) {
            flash_set('admin', 'err', __('msg_desc_too_long'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
        }

        if ($wantSetExpiry && !$expIsoM) {
            flash_set('admin', 'err', __('msg_account_exp_invalid'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
        }

        // DN + current state from API
        $dn = trim((string) ($_POST['dn'] ?? ''));
        $u = callApi('GET', '/user/' . rawurlencode($sam));
        if ($u['error']) {
            flash_set('admin', 'err', __('msg_user_not_found'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
        }
        $cur = $u['data'];
        if ($dn === '')
            $dn = (string) ($cur['dn'] ?? '');
        if ($dn === '') {
            flash_set('admin', 'err', __('msg_dn_not_found'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
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

        $curPgDnPre = trim((string) ($cur['primaryGroupDn'] ?? ''));
        $primaryReallyChanges = $primaryGroupMod !== ''
            && ($curPgDnPre === '' || strcasecmp($curPgDnPre, $primaryGroupMod) !== 0);

        if (empty($mods) && !$expNeverM && !$wantSetExpiry && !$primaryReallyChanges) {
            flash_set('admin', 'ok', __('msg_no_changes'));
            redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
        }

        if (!empty($mods)) {
            $payload = ['dn' => $dn, 'modifications' => $mods];
            $r = callApi('POST', '/user/updateProfile', $payload);
            if ($r['error']) {
                flash_set('admin', 'err', api_err_detail($r, __('msg_update_failed')));
                redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
            }
        }

        // Account expiration API
        if ($expNeverM) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'never' => true]);
        } elseif ($wantSetExpiry && $expIsoM) {
            callApi('POST', '/admin/setAccountExpiration', ['user' => $sam, 'expiresAt' => $expIsoM, 'never' => false]);
        }

        if ($primaryReallyChanges) {
            $rp = callApi('POST', '/admin/setUserPrimaryGroup', ['user' => $sam, 'group' => $primaryGroupMod]);
            if ($rp['error']) {
                flash_set('admin', 'err', api_err_detail($rp, __('msg_primary_group')));
                redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
            }
        }

        flash_set('admin', 'ok', __('msg_user_updated'));
        redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'user_update');
    }

    // --- Set final user group list (unified flow) ---
    if ($act === 'set_user_groups') {
        $user = trim((string) ($_POST['user_for_groups'] ?? ''));
        $groupsJson = (string) ($_POST['groups_json'] ?? '[]');
        if ($user === '') {
            flash_set('admin', 'err', __('msg_user_required'));
            redirect_get($qsSel, $tabUserAdmin);
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
            flash_set('admin', 'err', api_err_detail($r, __('msg_groups_update_failed')));
        } else {
            $added = (int) ($r['data']['addedCount'] ?? 0);
            $removed = (int) ($r['data']['removedCount'] ?? 0);
            flash_set('admin', 'ok', sprintf(__('msg_groups_updated'), $added, $removed));
        }
        redirect_get($qsSel, 'explorer');
    }

    // --- Set final group member list ---
    if ($act === 'set_group_members') {
        $group = trim((string) ($_POST['group_for_members'] ?? ''));
        $membersJson = (string) ($_POST['members_json'] ?? '[]');
        if ($group === '') {
            flash_set('admin', 'err', __('msg_group_required'));
            redirect_get($qsSel, 'explorer');
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
            flash_set('admin', 'err', api_err_detail($r, __('msg_members_update_failed')));
        } else {
            $added = (int) ($r['data']['addedCount'] ?? 0);
            $removed = (int) ($r['data']['removedCount'] ?? 0);
            flash_set('admin', 'ok', sprintf(__('msg_members_updated'), $added, $removed));
        }
        redirect_get($qsSel, 'explorer');
    }

    // --- Delete user (JSON body, not in URL) ---
    if ($act === 'delete_user') {
        $id = trim((string) ($_POST['del_id'] ?? ''));
        if ($id === '') {
            flash_set('admin', 'err', __('msg_identifier_required'));
            redirect_get($qsSel, $tabUserAdmin);
        }

        // API expects POST body { user: "<sAM or DN>" }
        $payload = ['user' => $id];
        $r = callApi('POST', '/admin/deleteUser', $payload);

        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, __('msg_delete_failed')));
        } else {
            flash_set('admin', 'ok', __('msg_user_deleted'));
        }
        redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'users_list');
    }

    // --- Enable / disable user ---
    if ($act === 'enable_user' || $act === 'disable_user') {
        $user = trim((string) ($_POST['sam_toggle'] ?? ''));
        if ($user === '') {
            flash_set('admin', 'err', __('msg_user_required'));
            redirect_get($qsSel, $tabUserAdmin);
        }
        $ep = $act === 'enable_user' ? '/admin/enableUser' : '/admin/disableUser';
        $r = callApi('POST', $ep, ['user' => $user]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, __('msg_state_change_failed')));
        else
            flash_set('admin', 'ok', $act === 'enable_user' ? __('msg_user_enabled') : __('msg_user_disabled'));
        redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'security');
    }

    // --- Unlock account ---
    if ($act === 'unlock_user') {
        $user = trim((string) ($_POST['sam_unlock'] ?? ''));
        if ($user === '') {
            flash_set('admin', 'err', __('msg_user_required'));
            redirect_get($qsSel, $tabUserAdmin);
        }
        $r = callApi('POST', '/admin/unlockUser', ['user' => $user]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, __('msg_unlock_failed')));
        else
            flash_set('admin', 'ok', __('msg_account_unlocked'));
        redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'security');
    }

    // --- Rename user CN ---
    if ($act === 'rename_user_cn') {
        $user = trim((string) ($_POST['sam_for_rename'] ?? ''));
        $newCn = trim((string) ($_POST['new_cn'] ?? ''));
        if ($user === '' || $newCn === '') {
            flash_set('admin', 'err', __('msg_rename_cn_required'));
            redirect_get($qsSel, $tabUserAdmin);
        }
        $r = callApi('POST', '/admin/renameUserCn', ['user' => $user, 'newCn' => $newCn]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, __('msg_rename_failed')));
        else
            flash_set('admin', 'ok', __('msg_cn_renamed'));
        redirect_get($qsSel, $tabUserAdmin, $fromExplorer ? null : 'rename_cn');
    }

    // --- Move user to another OU ---
    if ($act === 'move_user_ou') {
        $user = trim((string) ($_POST['sam_for_move'] ?? ''));
        $newOu = trim((string) ($_POST['new_ou_dn'] ?? ''));
        if ($user === '' || $newOu === '') {
            flash_set('admin', 'err', __('msg_move_user_required'));
            redirect_get($qsSel, $tabDomainAdmin);
        }
        $r = callApi('POST', '/admin/moveUser', ['user' => $user, 'newOuDn' => $newOu]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, __('msg_move_failed')));
        else
            flash_set('admin', 'ok', __('msg_user_moved'));
        redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'move_user');
    }

    if ($act === 'move_computer') {
        $dn = trim((string) ($_POST['computer_dn'] ?? ''));
        $newOu = trim((string) ($_POST['new_ou_dn_computer'] ?? ''));
        if ($dn === '' || $newOu === '') {
            flash_set('admin', 'err', __('msg_computer_move_required'));
            redirect_get($qsSel, $tabDomainAdmin);
        }
        $r = callApi('POST', '/admin/moveUser', ['user' => $dn, 'newOuDn' => $newOu]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, __('msg_computer_move_failed')));
        else
            flash_set('admin', 'ok', __('msg_computer_moved'));
        redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'move_computer');
    }

    if ($act === 'delete_computer') {
        $dn = trim((string) ($_POST['computer_dn_delete'] ?? ''));
        if ($dn === '') {
            flash_set('admin', 'err', __('msg_computer_dn_required'));
            redirect_get($qsSel, $tabDomainAdmin);
        }
        $r = callApi('POST', '/admin/deleteUser', ['user' => $dn]);
        if ($r['error'])
            flash_set('admin', 'err', api_err_detail($r, __('msg_computer_delete_failed')));
        else
            flash_set('admin', 'ok', __('msg_computer_deleted'));
        redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'delete_computer');
    }

    // --- OU: create ---
    if ($act === 'create_ou') {
        $parent = trim((string) ($_POST['ou_parent_dn'] ?? ''));
        $name = trim((string) ($_POST['ou_name'] ?? ''));
        $desc = trim((string) ($_POST['ou_desc'] ?? ''));
        $protRaw = $_POST['ou_protected'] ?? null; // "1" when checked

        if ($parent === '' || $name === '' || !ou_name_is_valid($name)) {
            flash_set('admin', 'err', __('msg_ou_parent_name_required'));
            redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
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
            flash_set('admin', 'err', api_err_detail($r, __('msg_ou_create_failed')));
        } else {
            flash_set('admin', 'ok', sprintf(__('msg_ou_created'), htmlspecialchars($r['data']['dn'] ?? '')));
        }
        redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
    }

    // --- OU: update (rename / description / protection / move) ---
    if ($act === 'update_ou') {
        $dn = trim((string) ($_POST['ou_dn'] ?? ''));
        $newNm = trim((string) ($_POST['ou_new_name'] ?? ''));
        $desc = trim((string) ($_POST['ou_desc_mod'] ?? ''));
        $currentName = trim((string) ($_POST['ou_current_name'] ?? ''));
        $currentDesc = trim((string) ($_POST['ou_current_desc'] ?? ''));
        $protSel = $_POST['ou_protected_mod'] ?? ''; // "", "1", "0"
        $descClear = !empty($_POST['ou_desc_clear']);
        $newParent = trim((string) ($_POST['ou_new_parent'] ?? ''));

        if ($dn === '') {
            flash_set('admin', 'err', __('msg_ou_source_required'));
            redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
        }

        $payload = ['OuDn' => $dn];
        if ($newNm !== '' && strcasecmp($newNm, $currentName) !== 0) {
            if (!ou_name_is_valid($newNm)) {
                flash_set('admin', 'err', __('msg_ou_name_invalid'));
                redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
            }
            $payload['NewName'] = $newNm;
        }

        // Description: "" = clear, omitted = leave unchanged, non-empty = set
        if ($descClear)
            $payload['Description'] = "";
        elseif ($desc !== '' && $desc !== $currentDesc)
            $payload['Description'] = $desc;

        // Protection: tri-state (empty / on / off)
        if ($protSel === '1')
            $payload['Protected'] = true;
        elseif ($protSel === '0')
            $payload['Protected'] = false;

        // Optional move to new parent OU
        if ($newParent !== '') {
            $payload['NewParentDn'] = $newParent;
        }

        $ru = callApi('POST', '/admin/ou/update', $payload);
        if ($ru['error']) {
            flash_set('admin', 'err', api_err_detail($ru, __('msg_ou_update_failed')));
            redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
        }
        flash_set('admin', 'ok', __('msg_ou_updated'));
        redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
    }

    // --- OU: delete ---
    if ($act === 'delete_ou') {
        $dn = trim((string) ($_POST['ou_del_dn'] ?? ''));
        if ($dn === '') {
            flash_set('admin', 'err', __('msg_ou_dn_required'));
            redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
        }

        // Note: API requires POST; no recursive "force" flag here
        $r = callApi('POST', '/admin/ou/delete', ['OuDn' => $dn]);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, __('msg_ou_delete_failed')));
        } else {
            flash_set('admin', 'ok', __('msg_ou_deleted'));
        }
        redirect_get($qsSel, $tabDomainAdmin, $fromExplorer ? null : 'ou_manage');
    }

    // --- Create group ---
    if ($act === 'create_group') {
        $ouDn = trim((string) ($_POST['group_ouDn'] ?? ''));
        $cn = trim((string) ($_POST['group_cn'] ?? ''));
        $sam = trim((string) ($_POST['group_sam'] ?? '')); // optional

        if ($ouDn === '' || $cn === '') {
            flash_set('admin', 'err', __('msg_group_ou_cn_required'));
            redirect_get($qsSel, $tabDomainAdmin);
        }

        $payload = ['ouDn' => $ouDn, 'cn' => $cn];
        if ($sam !== '')
            $payload['sam'] = $sam;

        $r = callApi('POST', '/admin/createGroup', $payload);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, __('msg_group_create_failed')));
        } else {
            $newDn = htmlspecialchars($r['data']['dn'] ?? '');
            flash_set('admin', 'ok', sprintf(__('msg_group_created'), $newDn));
        }
        // Return to admin tab with group search prefilled
        if ($fromExplorer) {
            $qsGrp = $qsSel;
            if (empty($r['error'])) {
                $gdn = trim((string) ($r['data']['dn'] ?? ''));
                if ($gdn !== '') {
                    $qsGrp['exdn'] = $gdn;
                }
            }
            redirect_get($qsGrp, 'explorer');
        }
        redirect_get(['gq' => ($cn ?: '*')], 'admin-domain');
    }

    // --- Delete group ---
    if ($act === 'delete_group') {
        $id = trim((string) ($_POST['group_del_id'] ?? ''));
        if ($id === '') {
            flash_set('admin', 'err', __('msg_group_id_required'));
            redirect_get($qsSel, $tabDomainAdmin);
        }
        // If DN (contains CN=/DC=), send as-is; otherwise treat as sAMAccountName
        $payload = (stripos($id, 'CN=') !== false || stripos($id, 'DC=') !== false)
            ? ['dn' => $id]
            : ['group' => $id];

        $r = callApi('DELETE', '/admin/deleteGroup', $payload);
        if ($r['error']) {
            flash_set('admin', 'err', api_err_detail($r, __('msg_group_delete_failed')));
        } else {
            flash_set('admin', 'ok', __('msg_group_deleted'));
        }
        redirect_get($qsSel, $tabDomainAdmin);
    }

    // --- Global group search (domain admin card) ---
    if ($act === 'search_groups_global') {
        $q = trim((string) ($_POST['group_query'] ?? ''));
        $gq = ($q === '' ? '*' : $q);
        $gp = max(1, (int) ($_POST['gpG'] ?? 1));
        $gps = max(1, (int) ($_POST['gpsG'] ?? 50));
        redirect_get(['gqG' => $gq, 'gpG' => $gp, 'gpsG' => $gps], 'admin-domain');
    }

    // --- Tools: create / update ---
    if ($act === 'tool_save') {
        // Ensure we have a live PDO
        if (!($TOOL_PDO ?? null) instanceof PDO) {
            try {
                $TOOL_PDO = app_pdo();
                tools_bootstrap($TOOL_PDO);
            } catch (Throwable $e) {
                flash_set('admin', 'err', sprintf(__('msg_tools_db'), $e->getMessage()));
                redirect_get([], 'tools'); // PRG
            }
        }
        $id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
        $title = trim((string) ($_POST['title'] ?? ''));
        $url = intranet_sanitize_tool_link_url((string) ($_POST['url'] ?? ''));
        $icon = intranet_sanitize_tool_image_url((string) ($_POST['icon'] ?? ''));
        if ($title === '' || $url === '') {
            flash_set('admin', 'err', __('msg_title_url_required'));
            redirect_get([], 'tools');
        }
        if (trim((string) ($_POST['icon'] ?? '')) !== '' && $icon === '') {
            flash_set('admin', 'err', __('msg_tool_icon_invalid'));
            redirect_get([], 'tools');
        }
        $data = [
            'id' => $id,
            'title' => $title,
            'description' => (string) ($_POST['description'] ?? ''),
            'url' => $url,
            'icon' => $icon,
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
            flash_set('admin', 'ok', $id ? __('msg_tool_updated') : __('msg_tool_created'));
        } catch (Throwable $e) {
            flash_set('admin', 'err', sprintf(__('msg_tool_save_error'), $e->getMessage()));
        }
        redirect_get([], 'tools');
    }

    // --- Tools: delete ---
    if ($act === 'tool_delete') {
        // Ensure we have a live PDO
        if (!($TOOL_PDO ?? null) instanceof PDO) {
            try {
                $TOOL_PDO = app_pdo();
                tools_bootstrap($TOOL_PDO);
            } catch (Throwable $e) {
                flash_set('admin', 'err', sprintf(__('msg_tools_db'), $e->getMessage()));
                redirect_get([], 'tools'); // PRG
            }
        }

        $id = (int) ($_POST['id'] ?? 0);
        if (!$id) {
            flash_set('admin', 'err', __('msg_id_missing'));
            redirect_get([], 'tools');
        }
        try {
            tools_delete($TOOL_PDO, $id);
            flash_set('admin', 'ok', __('msg_tool_deleted'));
        } catch (Throwable $e) {
            flash_set('admin', 'err', sprintf(__('msg_tool_delete_error'), $e->getMessage()));
        }
        redirect_get([], 'tools');
    }

    // --- Tools: reorder (up/down) ---
    if ($act === 'tool_move') {
        // Ensure we have a live PDO
        if (!($TOOL_PDO ?? null) instanceof PDO) {
            try {
                $TOOL_PDO = app_pdo();
                tools_bootstrap($TOOL_PDO);
            } catch (Throwable $e) {
                flash_set('admin', 'err', sprintf(__('msg_tools_db'), $e->getMessage()));
                redirect_get([], 'tools'); // PRG
            }
        }

        $id = (int) ($_POST['id'] ?? 0);
        $dir = ($_POST['dir'] ?? '') === 'up' ? 'up' : 'down';
        if (!$id) {
            flash_set('admin', 'err', __('msg_id_missing'));
            redirect_get([], 'tools');
        }
        try {
            tools_move($TOOL_PDO, $id, $dir);
        } catch (Throwable $e) {
            flash_set('admin', 'err', sprintf(__('msg_tool_move_error'), $e->getMessage()));
        }
        redirect_get([], 'tools');
    }

    // --- Bulk actions on users ---
    if ($act === 'bulk_users') {
        // Optional persisted selection
        $persistSam = trim((string) ($_POST['persist_selected_sam'] ?? ''));
        $qsSel = $persistSam !== '' ? ['select_sam' => $persistSam] : [];

        $ids = $_POST['sel'] ?? [];
        if (!is_array($ids) || count($ids) === 0) {
            flash_set('admin', 'err', __('msg_bulk_empty'));
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
                    flash_set('admin', 'err', __('msg_bulk_invalid_action'));
                    redirect_get($qsSel, 'admin-users', 'users_list');
            }
            if (!empty($r['error']))
                $ko++;
            else
                $ok++;
        }

        $msg = sprintf(__('msg_bulk_result'), $action, $ok, $ko);
        if ($ko > 0)
            flash_set('admin', 'err', $msg);
        else
            flash_set('admin', 'ok', $msg);
        redirect_get($qsSel, 'admin-users', 'users_list');
    }


}

/* ================================
   Admin: list-driven GET state
=================================== */
if ($is_admin) {
    // Global group search (domain admin card)
    if (isset($_GET['gqG'])) {
        $groupQueryGlobal = trim((string) $_GET['gqG']);
        $gpG = max(1, (int) ($_GET['gpG'] ?? 1));
        $gpsG = max(1, (int) ($_GET['gpsG'] ?? 50));
        $endpoint = '/groups?page=' . $gpG . '&pageSize=' . $gpsG;
        if ($groupQueryGlobal !== '' && $groupQueryGlobal !== '*') {
            $endpoint .= '&search=' . rawurlencode($groupQueryGlobal);
        }
        $gr = callApi_ldap('GET', $endpoint, null, true);
        if (!$gr['error']) {
            $groupResultsGlobal = is_array($gr['data']) ? $gr['data'] : [];
            $groupsHasMoreGlobal = !empty($gr['headers']['x-has-more']) && strtolower($gr['headers']['x-has-more']) === 'true';
        } else {
            $adminMsgErr = $adminMsgErr ?: api_err_detail($gr, __('msg_groups_search_global_failed'));
        }
    }

}

/* ---------- Pop flash messages for page render ---------- */
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
<html lang="<?= htmlspecialchars($INTRANET_LANG ?? 'fr', ENT_QUOTES, 'UTF-8') ?>">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo isset($_SESSION['username']) ? htmlspecialchars(__('title_intranet')) : htmlspecialchars(__('title_login')); ?></title>
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
            flex-wrap: wrap;
            gap: 4px;
            align-items: center;
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 6px 10px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-card);
        }

        .nav-brand {
            padding: 10px 20px 10px 14px;
            font-weight: 700;
            font-size: 1.05rem;
            letter-spacing: -0.02em;
            flex-shrink: 0;
        }

        .nav-lang {
            flex-shrink: 0;
        }

        .nav-menu-toggle {
            display: none;
            align-items: center;
            justify-content: center;
            width: 44px;
            height: 44px;
            margin: 0 0 0 auto;
            padding: 0;
            border: 1px solid rgba(148, 163, 184, 0.35);
            border-radius: 12px;
            background: var(--muted);
            color: var(--text);
            cursor: pointer;
            flex-shrink: 0;
        }

        .nav-menu-toggle:hover {
            background: var(--bg-elevated);
        }

        .nav-menu-toggle:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--border-focus);
        }

        .nav-menu-toggle-box {
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: 5px;
            width: 20px;
            height: 16px;
        }

        .nav-menu-toggle-box span {
            display: block;
            height: 2px;
            background: var(--text);
            border-radius: 1px;
            transition: transform 0.2s, opacity 0.2s;
        }

        .nav.nav--open .nav-menu-toggle-box span:nth-child(1) {
            transform: translateY(7px) rotate(45deg);
        }

        .nav.nav--open .nav-menu-toggle-box span:nth-child(2) {
            opacity: 0;
        }

        .nav.nav--open .nav-menu-toggle-box span:nth-child(3) {
            transform: translateY(-7px) rotate(-45deg);
        }

        .nav-panel {
            display: contents;
        }

        .nav-trailing {
            margin-left: auto;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }

        .nav-forcepw-meta {
            margin-left: auto;
        }

        .nav-panel > .badge {
            margin-left: 8px;
        }

        .visually-hidden {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        .lang-switch-wrap {
            position: relative;
            margin-left: 4px;
        }

        .intranet-lang-form {
            display: inline;
            margin: 0;
            padding: 0;
            vertical-align: middle;
        }

        .lang-switch {
            appearance: none;
            -webkit-appearance: none;
            width: auto;
            min-width: 160px;
            max-width: min(320px, 100%);
            cursor: pointer;
            color-scheme: dark;
            background: linear-gradient(165deg, rgba(30, 41, 59, 0.92), rgba(15, 23, 42, 0.98));
            color: var(--text);
            border: 1px solid rgba(148, 163, 184, 0.28);
            border-radius: 12px;
            padding: 10px 38px 10px 14px;
            font: 600 13px/1.2 'Plus Jakarta Sans', system-ui, sans-serif;
            letter-spacing: 0.02em;
            box-shadow: 0 4px 18px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.06);
            transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
        }

        /* Native <select> list: avoid light popup + inherited light text (Chrome/Edge/Windows). */
        .lang-switch option {
            background-color: #0f172a;
            color: #e5e7eb;
        }

        .lang-switch:hover {
            border-color: rgba(96, 165, 250, 0.45);
            box-shadow: 0 6px 22px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.08);
        }

        .lang-switch:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--border-focus), 0 4px 18px rgba(0, 0, 0, 0.35);
        }

        .lang-switch-wrap::after {
            content: '';
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            width: 0;
            height: 0;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 6px solid rgba(148, 163, 184, 0.75);
            pointer-events: none;
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

        @media (max-width: 768px) {
            .container { padding: 16px 14px; }
            .content { padding: 24px 18px; }
            .nav-menu-toggle { display: inline-flex; }
            .nav-panel {
                display: none;
                flex: 0 0 100%;
                width: 100%;
                flex-direction: column;
                align-items: stretch;
                gap: 6px;
                padding-top: 10px;
                margin-top: 4px;
                border-top: 1px solid var(--border);
            }
            .nav.nav--open .nav-panel { display: flex; }
            .nav-panel .tab-btn {
                width: 100%;
                text-align: left;
                justify-content: flex-start;
            }
            .nav-trailing {
                margin-left: 0;
                width: 100%;
                justify-content: space-between;
                padding-top: 8px;
                margin-top: 4px;
                border-top: 1px solid rgba(148, 163, 184, 0.2);
            }
            .nav-forcepw-meta {
                margin-left: 0;
                width: 100%;
                justify-content: flex-end;
            }
            .nav-panel > .badge {
                margin-left: 0;
                align-self: flex-start;
            }
            .lang-switch {
                min-width: 0;
                max-width: min(220px, 100%);
            }
        }

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
        .ad-node.selected .ad-node-dot { box-shadow: 0 0 0 2px rgba(255,255,255,.85); }
        .ad-node.selected .ad-node-badge { background:rgba(255,255,255,.12) !important; color:#f1f5f9 !important; border-color:rgba(255,255,255,.35) !important; }
        .ad-node-dot { width:8px; height:8px; border-radius:999px; background:#6b7280; flex-shrink:0; }
        /* Couleurs par type d’objet AD (point + pastille type) */
        .ad-node-dot.type-user { background:#38bdf8; box-shadow:0 0 0 1px rgba(56,189,248,.35); }
        .ad-node-dot.type-inetorgperson { background:#2dd4bf; box-shadow:0 0 0 1px rgba(45,212,191,.35); }
        .ad-node-dot.type-group { background:#c084fc; box-shadow:0 0 0 1px rgba(192,132,252,.35); }
        .ad-node-dot.type-computer { background:#fb923c; box-shadow:0 0 0 1px rgba(251,146,60,.35); }
        .ad-node-dot.type-ou { background:#4ade80; box-shadow:0 0 0 1px rgba(74,222,128,.35); }
        .ad-node-dot.type-container { background:#94a3b8; box-shadow:0 0 0 1px rgba(148,163,184,.35); }
        .ad-node-dot.type-domain { background:#818cf8; box-shadow:0 0 0 1px rgba(129,140,248,.35); }
        .ad-node-dot.type-other { background:#64748b; }
        .ad-node-label { flex:1 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .ad-node-badge { flex-shrink:0; font-size:11px; font-weight:600; padding:2px 8px; border-radius:999px; line-height:1.2; border:1px solid transparent; }
        .ad-node-badge.type-user { background:rgba(56,189,248,.14); color:#7dd3fc; border-color:rgba(56,189,248,.4); }
        .ad-node-badge.type-inetorgperson { background:rgba(45,212,191,.14); color:#5eead4; border-color:rgba(45,212,191,.4); }
        .ad-node-badge.type-group { background:rgba(192,132,252,.14); color:#d8b4fe; border-color:rgba(192,132,252,.4); }
        .ad-node-badge.type-computer { background:rgba(251,146,60,.14); color:#fdba74; border-color:rgba(251,146,60,.4); }
        .ad-node-badge.type-ou { background:rgba(74,222,128,.14); color:#86efac; border-color:rgba(74,222,128,.4); }
        .ad-node-badge.type-container { background:rgba(148,163,184,.14); color:#cbd5e1; border-color:rgba(148,163,184,.4); }
        .ad-node-badge.type-domain { background:rgba(129,140,248,.14); color:#a5b4fc; border-color:rgba(129,140,248,.4); }
        .ad-node-badge.type-other { background:rgba(100,116,139,.2); color:#cbd5e1; border-color:rgba(100,116,139,.45); }
        .ad-node-status { flex-shrink:0; font-size:11px; font-weight:600; padding:2px 8px; border-radius:999px; line-height:1.2; }
        .ad-node-status-disabled { background:rgba(127,29,29,.35); color:#fecaca; border:1px solid rgba(248,113,113,.45); }
        .badge.subtle { background:rgba(30,64,175,.12); color:#93c5fd; border:1px solid rgba(59,130,246,.35); }
        .ad-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
        .ad-kv { display:grid; grid-template-columns:minmax(120px, 180px) minmax(0, 1fr); gap:8px; margin-top:8px; }
        .ad-kv code { white-space:pre-wrap; word-break:break-word; }
        .modal-backdrop { position:fixed; inset:0; background:rgba(2,6,23,.8); z-index:9000; display:none; align-items:center; justify-content:center; padding:16px; }
        #explorer-modal.modal-backdrop[aria-hidden="false"] { display:flex; }
        .modal-card { width:min(780px, 96vw); max-height:90vh; overflow:auto; background:var(--bg-elevated); border:1px solid var(--border); border-radius:12px; box-shadow:var(--shadow); padding:16px; }
        .modal-head { display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:12px; }
        .modal-head h3 { margin:0; }
        @media (max-width: 1100px) {
            .ad-explorer { grid-template-columns:1fr; }
        }
    </style>
    <script>
        // Only client-side flag kept here (forced password change is already obvious in the UI):
        const FORCE_PW_MODE = <?= $forcePwMode ? 'true' : 'false' ?>;
        const INTRANET_SELF = <?= json_encode(INTRANET_SELF, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
        const INTRANET_I18N = <?= json_encode(intranet_i18n_js_export(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        const ADMIN_FOCUS = "<?= htmlspecialchars($_GET['af'] ?? '', ENT_QUOTES) ?>";

        function allowedTabsFromDOM() {
            if (FORCE_PW_MODE) return ['profil']; // forced password change: profile tab only
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
            // Resolve initial tab from hash or server default
            let hashTab = (location.hash || '').replace('#tab-', '');
            const ok = allowedTabsFromDOM();
            if (!ok.includes(hashTab)) {
                // Server default without leaking sensitive state
                <?php
                $def = isset($_SESSION['username'])
                    ? (($is_admin ?? false) && !empty($_GET['select_sam'] ?? '') ? 'admin' : 'profil')
                    : 'login';
                ?>
                hashTab = '<?= $def ?>';
                history.replaceState(null, '', '#tab-' + hashTab);
            }
            setActive(hashTab);

            // Mobile nav: hamburger + collapsible panel (desktop keeps display:contents on .nav-panel)
            (function () {
                const appNav = document.getElementById('app-nav');
                const navToggle = document.getElementById('nav-menu-toggle');
                if (!appNav || !navToggle) return;
                const mq = window.matchMedia('(max-width: 768px)');
                const closeNav = () => {
                    if (!mq.matches) return;
                    appNav.classList.remove('nav--open');
                    navToggle.setAttribute('aria-expanded', 'false');
                };
                navToggle.addEventListener('click', (e) => {
                    e.stopPropagation();
                    if (!mq.matches) return;
                    const open = !appNav.classList.contains('nav--open');
                    appNav.classList.toggle('nav--open', open);
                    navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
                });
                mq.addEventListener('change', () => {
                    if (!mq.matches) {
                        appNav.classList.remove('nav--open');
                        navToggle.setAttribute('aria-expanded', 'false');
                    }
                });
                appNav.addEventListener('click', (e) => {
                    if (!mq.matches) return;
                    if (e.target.closest('.tab-btn')) closeNav();
                });
            })();

            // Auto-scroll/focus after admin action (af= query)
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

            // AD explorer: tree selection, details pane, contextual actions
            const adTree = document.getElementById('ad-tree');
            const adDetails = document.getElementById('ad-details');
            const adActions = document.getElementById('ad-actions');
            const explorerModal = document.getElementById('explorer-modal');
            const modalTitle = document.getElementById('explorer-modal-title');
            const modalBody = document.getElementById('explorer-modal-body');
            const explorerRestoreDn = <?= json_encode($explorerRestoreDn, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
            let explorerModalLastFocus = null;
            let explorerModalEscHandler = null;
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
                    const typeLabel = type === 'user' ? INTRANET_I18N.js_type_user
                        : (type === 'group' ? INTRANET_I18N.js_type_group
                        : (type === 'computer' ? INTRANET_I18N.js_type_computer
                        : (type === 'inetorgperson' ? INTRANET_I18N.js_type_person
                        : (type === 'ou' || type === 'domain' || type === 'container' ? INTRANET_I18N.js_type_container : (type || INTRANET_I18N.js_type_object)))));
                    adDetails.innerHTML =
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_type) + '</div><div><strong>' + escapeHtml(typeLabel) + '</strong></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_name) + '</div><div><code>' + escapeHtml(name || dn) + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_dn) + '</div><div><code>' + escapeHtml(dn) + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_classes) + '</div><div><code>' + escapeHtml(classes || '-') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_description) + '</div><div>' + escapeHtml(desc || '—') + '</div></div>' +
                        '<div class=\"small\" style=\"margin-top:10px;opacity:.85\">' + escapeHtml(INTRANET_I18N.js_loading_details) + '</div>';
                    renderExplorerActions(type, dn, name, null);
                    loadExplorerObjectDetails(dn, type, name);
                });
                (function restoreExplorerSelectionFromUrl() {
                    const want = String(explorerRestoreDn || '').trim();
                    if (!want) return;
                    const nodes = adTree.querySelectorAll('.ad-node[data-dn]');
                    for (let i = 0; i < nodes.length; i++) {
                        const n = nodes[i];
                        if ((n.getAttribute('data-dn') || '') === want) {
                            n.click();
                            try { n.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); } catch (e) { n.scrollIntoView(); }
                            try { n.focus({ preventScroll: true }); } catch (e2) { n.focus(); }
                            return;
                        }
                    }
                })();
            }

            function normalizeNodeType(rawType, classes, dn) {
                const c = String(classes || '').toLowerCase();
                // Highest priority: computer class => PC
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
                fetch(INTRANET_SELF + '?ajax=explorer_object&dn=' + encodeURIComponent(dn), {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                })
                    .then(r => r.json())
                    .then(data => {
                        if (!data || data.error) {
                            adDetails.innerHTML += '<div class=\"small\" style=\"margin-top:8px;color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_details_unavailable) + '</div>';
                            return;
                        }
                        selectedObjectDetails = data;
                        renderExplorerObjectDetails(data, fallbackType, fallbackName, dn);
                    })
                    .catch(() => {
                        adDetails.innerHTML += '<div class=\"small\" style=\"margin-top:8px;color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_details_unavailable) + '</div>';
                    });
            }

            function renderExplorerObjectDetails(data, fallbackType, fallbackName, dn) {
                const type = normalizeNodeType(data.type || fallbackType, (data.objectClasses || []).join(','), dn);
                const a = data.attributes || {};
                const isDisabled = !!data.isDisabled;
                const typeLabel = type === 'user' ? INTRANET_I18N.js_type_user
                    : (type === 'group' ? INTRANET_I18N.js_type_group
                    : (type === 'computer' ? INTRANET_I18N.js_type_computer
                    : (type === 'inetorgperson' ? INTRANET_I18N.js_type_person
                    : (type === 'ou' || type === 'domain' || type === 'container' ? INTRANET_I18N.js_type_container : (type || INTRANET_I18N.js_type_object)))));

                let html = '';
                if ((type === 'user' || type === 'inetorgperson') && isDisabled) {
                    html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_state) + '</div><div><strong style=\"color:#f97373\">' + escapeHtml(INTRANET_I18N.js_disabled) + '</strong></div></div>';
                }
                html +=
                    '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_type) + '</div><div><strong>' + escapeHtml(typeLabel) + '</strong></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_name) + '</div><div><code>' + escapeHtml(a.name || a.cn || fallbackName || dn) + '</code></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_dn) + '</div><div><code>' + escapeHtml(data.dn || dn) + '</code></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_classes) + '</div><div><code>' + escapeHtml((data.objectClasses || []).join(', ') || '-') + '</code></div></div>' +
                    '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_description) + '</div><div>' + escapeHtml(a.description || '—') + '</div></div>';

                if (type === 'ou') {
                    const locked = !!data.protectedOu;
                    html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_ou_protection) + '</div><div>' +
                        (locked ? escapeHtml(INTRANET_I18N.js_ou_protected) : escapeHtml(INTRANET_I18N.js_ou_unprotected)) + '</div></div>';
                }

                if (type === 'user' || type === 'inetorgperson') {
                    html +=
                        '<div class=\"ad-kv\"><div class=\"small\">sAMAccountName</div><div><code>' + escapeHtml(a.samAccountName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">UPN</div><div><code>' + escapeHtml(a.userPrincipalName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_email) + '</div><div>' + escapeHtml(a.mail || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_phone) + '</div><div>' + escapeHtml(a.telephoneNumber || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_address) + '</div><div>' + escapeHtml(a.streetAddress || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_label_site) + '</div><div>' + escapeHtml(pickExplorerWebsite(a) || '—') + '</div></div>';
                    const pgDnU = a.primaryGroupDn || '';
                    const pgIdU = a.primaryGroupId != null && a.primaryGroupId !== '' ? String(a.primaryGroupId) : '';
                    const pgLineU = pgDnU ? (escapeHtml(shortDnLabel(pgDnU)) + (pgIdU ? ' (RID ' + escapeHtml(pgIdU) + ')' : '') + '<div class=\"small\" style=\"opacity:.75;margin-top:4px\"><code>' + escapeHtml(pgDnU) + '</code></div>') : '—';
                    html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_primary_group) + '</div><div>' + pgLineU + '</div></div>';
                    const memberOfUser = normalizeMemberOfList(a.memberOf ?? data.memberOf);
                    html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_member_of_all) + '</div><div>';
                    if (!memberOfUser.length) {
                        html += '<span class=\"small\">—</span>';
                    } else {
                        html += '<div style=\"max-height:280px;overflow:auto;border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:8px\">';
                        html += memberOfUser.map(dn => {
                            const label = shortDnLabel(dn);
                            return '<div style=\"margin-bottom:8px\"><strong>' + escapeHtml(label) + '</strong><div class=\"small\" style=\"opacity:.75\"><code>' + escapeHtml(dn) + '</code></div></div>';
                        }).join('');
                        html += '</div><div class=\"small\" style=\"margin-top:6px\">' + INTRANET_I18N.js_groups_count.replace('%d', String(memberOfUser.length)) + '</div>';
                    }
                    html += '</div></div>';
                }

                if (type === 'computer') {
                    const ips = Array.isArray(a.ipAddresses) ? a.ipAddresses : [];
                    html +=
                        '<div class=\"ad-kv\"><div class=\"small\">sAMAccountName</div><div><code>' + escapeHtml(a.samAccountName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_dns_name) + '</div><div><code>' + escapeHtml(a.dnsHostName || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_ip) + '</div><div><code>' + escapeHtml(ips.length ? ips.join(', ') : '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_os) + '</div><div>' + escapeHtml(a.operatingSystem || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_os_version) + '</div><div>' + escapeHtml(a.operatingSystemVersion || '—') + '</div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_last_machine_bind) + '</div><div><code>' + escapeHtml(a.lastBindAtUtc || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_created_at) + '</div><div><code>' + escapeHtml(a.createdAtUtc || a.whenCreated || '—') + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_last_user) + '</div><div><code>' + escapeHtml(a.lastUserConnected || INTRANET_I18N.js_not_available_ad) + '</code></div></div>' +
                        '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_managed_by) + '</div><div><code>' + escapeHtml(a.managedBy || '—') + '</code></div></div>';
                    const pgDnC = a.primaryGroupDn || '';
                    const pgIdC = a.primaryGroupId != null && a.primaryGroupId !== '' ? String(a.primaryGroupId) : '';
                    const pgLineC = pgDnC ? (escapeHtml(shortDnLabel(pgDnC)) + (pgIdC ? ' (RID ' + escapeHtml(pgIdC) + ')' : '') + '<div class=\"small\" style=\"opacity:.75;margin-top:4px\"><code>' + escapeHtml(pgDnC) + '</code></div>') : '—';
                    html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_primary_group) + '</div><div>' + pgLineC + '</div></div>';
                    const memberOfComp = normalizeMemberOfList(a.memberOf ?? data.memberOf);
                    html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_member_of_all) + '</div><div>';
                    if (!memberOfComp.length) {
                        html += '<span class=\"small\">—</span>';
                    } else {
                        html += '<div style=\"max-height:220px;overflow:auto;border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:8px\">';
                        html += memberOfComp.map(gdn => {
                            const label = shortDnLabel(gdn);
                            return '<div style=\"margin-bottom:8px\"><strong>' + escapeHtml(label) + '</strong><div class=\"small\" style=\"opacity:.75\"><code>' + escapeHtml(gdn) + '</code></div></div>';
                        }).join('');
                        html += '</div><div class=\"small\" style=\"margin-top:6px\">' + INTRANET_I18N.js_groups_count.replace('%d', String(memberOfComp.length)) + '</div>';
                    }
                    html += '</div></div>';
                }

                if (type === 'group') {
                    if (data.deleteGroupBlocked === true) {
                        const dgb = String(data.deleteGroupBlockedDetail || '').trim();
                        html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_group_delete_blocked) + '</div><div class=\"small\" style=\"color:#fca5a5\">' +
                            escapeHtml(dgb || INTRANET_I18N.js_group_delete_blocked_default) +
                            '</div></div>';
                    }
                    const memberOfGrp = normalizeMemberOfList(a.memberOf ?? data.memberOf);
                    if (memberOfGrp.length > 0) {
                        html += '<div class=\"ad-kv\"><div class=\"small\">' + escapeHtml(INTRANET_I18N.js_member_of_parents) + '</div><div>' +
                            '<div style=\"max-height:220px;overflow:auto;border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:8px\">' +
                            memberOfGrp.map(dn => {
                                const label = shortDnLabel(dn);
                                return '<div style=\"margin-bottom:8px\"><strong>' + escapeHtml(label) + '</strong><div class=\"small\" style=\"opacity:.75\"><code>' + escapeHtml(dn) + '</code></div></div>';
                            }).join('') +
                            '</div><div class=\"small\" style=\"margin-top:6px\">' + INTRANET_I18N.js_groups_count.replace('%d', String(memberOfGrp.length)) + '</div>' +
                            '</div></div>';
                    }
                }
                adDetails.innerHTML = html;
                renderExplorerActions(type, data.dn || dn, a.samAccountName || fallbackName || dn, data.capabilities || null);
            }

            function renderExplorerActions(type, dn, name, capabilities) {
                if (!adActions) return;
                const isContainer = ['ou', 'container', 'domain'].includes(type);
                const isUser = ['user', 'inetorgperson'].includes(type);
                const isGroup = type === 'group';
                const isComputer = type === 'computer';
                const buttons = [];
                if (isContainer) {
                    buttons.push(btn(INTRANET_I18N.js_btn_create_user, "openExplorerModal('create_user')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_create_ou, "openExplorerModal('create_ou')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_create_group, "openExplorerModal('create_group')"));
                }
                if (type === 'ou') {
                    buttons.push(btn(INTRANET_I18N.js_btn_edit_ou, "openExplorerModal('update_ou')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_delete_ou, "openExplorerModal('delete_ou')"));
                }
                if (isUser) {
                    buttons.push(btn(INTRANET_I18N.js_btn_edit_user, "openExplorerModal('admin_update_user')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_user_groups, "openExplorerModal('set_user_groups')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_enable, "openExplorerModal('enable_user')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_disable, "openExplorerModal('disable_user')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_unlock, "openExplorerModal('unlock_user')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_reset_pw, "openExplorerModal('admin_reset_pw')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_rename_cn, "openExplorerModal('rename_user_cn')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_move, "openExplorerModal('move_user_ou')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_clone, "openExplorerModal('clone_user')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_delete_user, "openExplorerModal('delete_user')"));
                }
                if (isComputer) {
                    buttons.push(btn(INTRANET_I18N.js_btn_move_computer, "openExplorerModal('move_computer')"));
                    buttons.push(btn(INTRANET_I18N.js_btn_delete_computer, "openExplorerModal('delete_computer')"));
                }
                if (isGroup) {
                    buttons.push(btn(INTRANET_I18N.js_btn_group_members, "openExplorerModal('set_group_members')"));
                    const canDelGrp = !capabilities || capabilities.canDeleteGroup !== false;
                    if (canDelGrp) {
                        buttons.push(btn(INTRANET_I18N.js_btn_delete_group, "openExplorerModal('delete_group')"));
                    }
                }
                adActions.innerHTML = buttons.length ? buttons.join('') : '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_actions) + '</div>';
            }

            function btn(label, onclickCode) {
                return '<button type=\"button\" class=\"btn sm\" onclick=\"' + onclickCode + '\">' + escapeHtml(label) + '</button>';
            }

            function explorerParentDn(objectDn) {
                const d = String(objectDn || '');
                const i = d.indexOf(',');
                return i >= 0 ? d.slice(i + 1).trim() : '';
            }

            function normalizeMemberOfList(raw) {
                if (raw == null) return [];
                if (Array.isArray(raw)) return raw.map(x => String(x).trim()).filter(Boolean);
                const s = String(raw).trim();
                return s ? [s] : [];
            }

            function explorerDnKey(s) {
                return String(s || '').trim().toLowerCase();
            }

            function explorerDnEquals(a, b) {
                const x = explorerDnKey(a);
                const y = explorerDnKey(b);
                return x !== '' && x === y;
            }

            function pickExplorerWebsite(attrs) {
                if (!attrs || typeof attrs !== 'object') return '';
                const a = attrs;
                const direct = a.website ?? a.wWWHomePage ?? a.wwwHomePage ?? a.WWWHomePage;
                if (direct != null && String(direct).trim() !== '') return String(direct);
                for (const k of Object.keys(a)) {
                    if (!/wwwhomepage|^website$/i.test(k)) continue;
                    const v = a[k];
                    if (v == null) continue;
                    const s = Array.isArray(v) ? String(v[0] ?? '') : String(v);
                    if (s.trim() !== '') return s;
                }
                return '';
            }

            window.closeExplorerModal = function closeExplorerModal() {
                if (!explorerModal) return;
                if (explorerModalEscHandler) {
                    document.removeEventListener('keydown', explorerModalEscHandler);
                    explorerModalEscHandler = null;
                }
                explorerModal.setAttribute('aria-hidden', 'true');
                modalBody.innerHTML = '';
                const prev = explorerModalLastFocus;
                explorerModalLastFocus = null;
                if (prev && typeof prev.focus === 'function') {
                    try { prev.focus(); } catch (e) {}
                }
            };
            window.openExplorerModal = function openExplorerModal(action) {
                if (!selectedNode || !explorerModal || !modalBody || !modalTitle) return;
                const dn = selectedNode.getAttribute('data-dn') || '';
                const name = selectedNode.getAttribute('data-name') || '';
                const treeType = selectedNode.getAttribute('data-type') || '';
                const treeClasses = selectedNode.getAttribute('data-classes') || '';
                const sam = selectedNode.getAttribute('data-sam') || '';
                const userId = sam || dn || name;
                const resolvedType = selectedObjectDetails
                    ? normalizeNodeType(selectedObjectDetails.type || '', (selectedObjectDetails.objectClasses || []).join(','), dn)
                    : normalizeNodeType(treeType, treeClasses, dn);
                const userOnly = new Set(['enable_user', 'disable_user', 'unlock_user', 'admin_reset_pw', 'admin_update_user', 'rename_user_cn', 'move_user_ou', 'delete_user', 'set_user_groups', 'clone_user']);
                if (userOnly.has(action) && resolvedType === 'computer') {
                    alert(INTRANET_I18N.js_alert_user_action_on_computer);
                    return;
                }
                if ((action === 'move_computer' || action === 'delete_computer') && resolvedType !== 'computer') {
                    alert(INTRANET_I18N.js_alert_computer_action_not_computer);
                    return;
                }
                if (action === 'delete_group' && selectedObjectDetails && selectedObjectDetails.deleteGroupBlocked === true) {
                    const msg = String(selectedObjectDetails.deleteGroupBlockedDetail || '').trim();
                    alert(msg || INTRANET_I18N.js_alert_group_delete_blocked);
                    return;
                }
                if (action === 'admin_update_user' && !selectedObjectDetails) {
                    fetch(INTRANET_SELF + '?ajax=explorer_object&dn=' + encodeURIComponent(dn), {
                        credentials: 'same-origin',
                        headers: { 'X-Requested-With': 'XMLHttpRequest' }
                    })
                        .then(r => r.json())
                        .then(data => {
                            if (!data || data.error) {
                                alert(INTRANET_I18N.js_alert_load_user_details);
                                return;
                            }
                            selectedObjectDetails = data;
                            openExplorerModal('admin_update_user');
                        })
                        .catch(() => alert(INTRANET_I18N.js_alert_network_user_details));
                    return;
                }
                const csrf = <?= json_encode($csrf) ?>;
                const baseDn = <?= json_encode((string) ($adMeta['baseDn'] ?? '')) ?>;
                const ouOptionsHtml = <?= json_encode(implode('', array_map(function($opt){ return '<option value=\"'.htmlspecialchars((string)$opt['dn'], ENT_QUOTES).'\">'.htmlspecialchars((string)$opt['label'], ENT_QUOTES).'</option>'; }, $ouOptions))) ?>;
                modalTitle.textContent = INTRANET_I18N.js_modal_action_prefix + action;
                const hidden = '<input type=\"hidden\" name=\"csrf\" value=\"' + escapeHtml(csrf) + '\"><input type=\"hidden\" name=\"admin_action\" value=\"' + escapeHtml(action) + '\"><input type=\"hidden\" name=\"admin_origin\" value=\"explorer\"><input type=\"hidden\" name=\"explorer_focus_dn\" value=\"' + escapeHtml(dn) + '\">';

                let formBody = '<div class=\"small\" style=\"margin-bottom:8px\">' + escapeHtml(INTRANET_I18N.js_object_label) + '<code>' + escapeHtml(name || dn) + '</code></div>';
                if (action === 'create_ou') {
                    formBody += hidden + '<input type=\"hidden\" name=\"ou_parent_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_ou_name) + '</label><input class=\"input\" name=\"ou_name\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_description) + '</label><input class=\"input\" name=\"ou_desc\">' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">' + escapeHtml(INTRANET_I18N.js_protect) + '</label><input type=\"checkbox\" name=\"ou_protected\" value=\"1\"></div>';
                } else if (action === 'update_ou') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const currentOuName = sa.ou || sa.name || name || '';
                    const currentOuDesc = sa.description || '';
                    const ouProt = !!(selectedObjectDetails && selectedObjectDetails.protectedOu);
                    formBody += hidden + '<input type=\"hidden\" name=\"ou_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<input type=\"hidden\" name=\"ou_current_name\" value=\"' + escapeHtml(currentOuName) + '\">' +
                        '<input type=\"hidden\" name=\"ou_current_desc\" value=\"' + escapeHtml(currentOuDesc) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_ou_name) + '</label><input class=\"input\" name=\"ou_new_name\" value=\"' + escapeHtml(currentOuName) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_description) + '</label><input class=\"input\" name=\"ou_desc_mod\" value=\"' + escapeHtml(currentOuDesc) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_new_parent_optional) + '</label><select class=\"input\" name=\"ou_new_parent\"><option value=\"\">' + escapeHtml(INTRANET_I18N.js_ou_new_parent_unchanged) + '</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_ou_protection_field) + '</label><select class=\"input\" name=\"ou_protected_mod\"><option value=\"\" selected>' + escapeHtml(INTRANET_I18N.js_ou_protection_no_change) + '</option><option value=\"1\">' + escapeHtml(INTRANET_I18N.js_ou_protection_on) + '</option><option value=\"0\">' + escapeHtml(INTRANET_I18N.js_ou_protection_off) + '</option></select>';
                } else if (action === 'delete_ou') {
                    formBody += hidden + '<input type=\"hidden\" name=\"ou_del_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_ou_delete_note) + '</div>';
                } else if (action === 'create_user') {
                    formBody += hidden +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_target_ou) + '</label><select class=\"input\" name=\"ouDn\" required><option value=\"\">' + escapeHtml(INTRANET_I18N.js_choose) + '</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_cn) + '</label><input class=\"input\" name=\"cn\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_sam_account_name) + '</label><input class=\"input\" name=\"sam\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_first_name) + '</label><input class=\"input\" name=\"givenName\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_last_name) + '</label><input class=\"input\" name=\"sn\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_upn) + '</label><input class=\"input\" name=\"userPrincipalName\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_email) + '</label><input class=\"input\" name=\"mail\" type=\"email\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_initial_password) + '</label><input class=\"input\" name=\"password\" type=\"password\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_account_expiry) + '</label>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" type=\"date\" name=\"exp_date\" style=\"max-width:220px\"><input class=\"input\" type=\"time\" name=\"exp_time\" style=\"max-width:160px\"><label class=\"label\" style=\"margin:0 6px 0 10px\">' + escapeHtml(INTRANET_I18N.js_label_never) + '</label><input type=\"checkbox\" name=\"exp_never\" value=\"1\" checked></div>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">' + escapeHtml(INTRANET_I18N.js_label_force_change_first) + '</label><input type=\"checkbox\" name=\"must_change_at_first_login\" value=\"1\"></div>';
                } else if (action === 'create_group') {
                    formBody += hidden +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_target_ou) + '</label><select class=\"input\" name=\"group_ouDn\" required><option value=\"\">' + escapeHtml(INTRANET_I18N.js_choose) + '</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_group_cn) + '</label><input class=\"input\" name=\"group_cn\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_sam_optional) + '</label><input class=\"input\" name=\"group_sam\">';
                } else if (action === 'enable_user' || action === 'disable_user') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_toggle\" value=\"' + escapeHtml(userId) + '\">';
                } else if (action === 'unlock_user') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_unlock\" value=\"' + escapeHtml(userId) + '\">';
                } else if (action === 'admin_reset_pw') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_reset\" value=\"' + escapeHtml(userId) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_new_password) + '</label><input class=\"input\" name=\"new_password\" type=\"password\" required>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">' + escapeHtml(INTRANET_I18N.js_force_change_next_logon) + '</label><input type=\"checkbox\" name=\"must_change\" value=\"1\"></div>';
                } else if (action === 'admin_update_user') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const descValue = Array.isArray(sa.description) ? (sa.description[0] || '') : (sa.description || '');
                    const siteWeb = pickExplorerWebsite(sa);
                    const pgDn = String(sa.primaryGroupDn || sa.PrimaryGroupDn || '').trim();
                    const pgId = sa.primaryGroupId != null && sa.primaryGroupId !== '' ? String(sa.primaryGroupId) : '';
                    const pgActuel = pgDn ? (escapeHtml(shortDnLabel(pgDn)) + (pgId ? ' (RID ' + escapeHtml(pgId) + ')' : '')) : '—';
                    const rawMemberOf = normalizeMemberOfList(sa.memberOf);
                    const groupDns = [];
                    const seenKeys = new Set();
                    for (const g of rawMemberOf) {
                        const gdn = String(g).trim();
                        const k = explorerDnKey(gdn);
                        if (!k || seenKeys.has(k)) continue;
                        seenKeys.add(k);
                        groupDns.push(gdn);
                    }
                    if (pgDn) {
                        const kpg = explorerDnKey(pgDn);
                        if (kpg && !seenKeys.has(kpg)) {
                            seenKeys.add(kpg);
                            groupDns.push(pgDn);
                        }
                    }
                    groupDns.sort((a, b) => shortDnLabel(a).localeCompare(shortDnLabel(b), undefined, { sensitivity: 'base' }));
                    let pgOpts = '<option value=\"\">' + escapeHtml(INTRANET_I18N.js_pg_do_not_change) + '</option>';
                    let primaryMatched = false;
                    for (const gdn of groupDns) {
                        const isPg = pgDn && explorerDnEquals(gdn, pgDn);
                        if (isPg) primaryMatched = true;
                        const selAttr = isPg ? ' selected' : '';
                        const optLabel = shortDnLabel(gdn) + (isPg ? INTRANET_I18N.js_pg_current_suffix : '');
                        pgOpts += '<option value=\"' + escapeHtml(gdn) + '\"' + selAttr + '>' + escapeHtml(optLabel) + '</option>';
                    }
                    if (pgDn && !primaryMatched) {
                        pgOpts += '<option value=\"' + escapeHtml(pgDn) + '\" selected>' + escapeHtml(shortDnLabel(pgDn)) + INTRANET_I18N.js_pg_current_suffix + '</option>';
                    }
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_user_sam) + '</label><input class=\"input\" name=\"sam_mod\" value=\"' + escapeHtml(sa.samAccountName || userId) + '\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_email) + '</label><input class=\"input\" name=\"mail_mod\" type=\"email\" value=\"' + escapeHtml(sa.mail || '') + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_first_name) + '</label><input class=\"input\" name=\"givenName_mod\" value=\"' + escapeHtml(sa.givenName || '') + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_last_name) + '</label><input class=\"input\" name=\"sn_mod\" value=\"' + escapeHtml(sa.sn || '') + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_phone) + '</label><input class=\"input\" name=\"tel_mod\" value=\"' + escapeHtml(sa.telephoneNumber || '') + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_address) + '</label><input class=\"input\" name=\"addr_mod\" value=\"' + escapeHtml(sa.streetAddress || '') + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_website) + '</label><input class=\"input\" name=\"site_mod\" value=\"' + escapeHtml(siteWeb) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_description) + '</label><textarea class=\"input\" name=\"desc_mod\" rows=\"3\" maxlength=\"1024\">' + escapeHtml(descValue) + '</textarea>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_primary_group) + '</label><select class=\"input\" name=\"primary_group_mod\">' + pgOpts + '</select>' +
                        '<div class=\"small\" style=\"margin-top:6px;opacity:.9\">' + escapeHtml(INTRANET_I18N.js_pg_help) + '</div>' +
                        '<div class=\"small\" style=\"margin-top:4px;opacity:.85\">' + escapeHtml(INTRANET_I18N.js_pg_summary) + escapeHtml(pgActuel) + '</div>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_account_expiry) + '</label>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" type=\"date\" name=\"exp_date_mod\" style=\"max-width:220px\"><input class=\"input\" type=\"time\" name=\"exp_time_mod\" style=\"max-width:160px\"><label class=\"label\" style=\"margin:0 6px 0 10px\">' + escapeHtml(INTRANET_I18N.js_never_expire) + '</label><input type=\"checkbox\" name=\"exp_never_mod\" value=\"1\"></div>';
                } else if (action === 'rename_user_cn') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const curCn = sa.cn || sa.name || name || '';
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_for_rename\" value=\"' + escapeHtml(userId) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_new_cn) + '</label><input class=\"input\" name=\"new_cn\" value=\"' + escapeHtml(curCn) + '\" required>';
                } else if (action === 'move_user_ou') {
                    formBody += hidden + '<input type=\"hidden\" name=\"sam_for_move\" value=\"' + escapeHtml(userId) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_target_ou) + '</label><select class=\"input\" name=\"new_ou_dn\" required><option value=\"\">' + escapeHtml(INTRANET_I18N.js_choose) + '</option>' + ouOptionsHtml + '</select>';
                } else if (action === 'delete_user') {
                    formBody += hidden + '<input type=\"hidden\" name=\"del_id\" value=\"' + escapeHtml(userId) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_delete_user_warning) + '</div>';
                } else if (action === 'move_computer') {
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"computer_dn\" value=\"' + escapeHtml(dn) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_target_ou) + '</label><select class=\"input\" name=\"new_ou_dn_computer\" required><option value=\"\">' + escapeHtml(INTRANET_I18N.js_choose) + '</option>' + ouOptionsHtml + '</select>' +
                        '<div class=\"small\" style=\"margin-top:6px\">' + escapeHtml(INTRANET_I18N.js_move_computer_note) + '</div>';
                } else if (action === 'delete_computer') {
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"computer_dn_delete\" value=\"' + escapeHtml(dn) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_delete_computer_note) + '</div>';
                } else if (action === 'delete_group') {
                    formBody += hidden + '<input type=\"hidden\" name=\"group_del_id\" value=\"' + escapeHtml(dn) + '\">' +
                        '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_delete_group_note) + '</div>';
                } else if (action === 'clone_user') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const srcSam = sa.samAccountName || userId;
                    const srcCn = sa.cn || sa.name || name || '';
                    const srcGn = sa.givenName || '';
                    const srcSn = sa.sn || '';
                    const srcMail = sa.mail || '';
                    const srcUpn = sa.userPrincipalName || '';
                    const srcNever = !!sa.accountNeverExpires;
                    const srcMustChg = !!sa.mustChangePasswordAtNextLogon;
                    const srcGroups = normalizeMemberOfList(sa.memberOf);
                    const srcGroupsJson = JSON.stringify(srcGroups.map(d => ({ dn: d })));
                    const applyGrpsChk = srcGroups.length > 0 ? ' checked' : '';
                    const expNeverChk = srcNever ? ' checked' : '';
                    const mustChgChk = srcMustChg ? ' checked' : '';
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"clone_source_sam\" value=\"' + escapeHtml(srcSam) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_target_ou) + '</label><select class=\"input\" name=\"clone_ouDn\" required><option value=\"\">' + escapeHtml(INTRANET_I18N.js_choose) + '</option>' + ouOptionsHtml + '</select>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_cn) + '</label><input class=\"input\" name=\"clone_cn\" required value=\"' + escapeHtml(srcCn) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_sam_account_name) + '</label><input class=\"input\" name=\"clone_sam\" required value=\"' + escapeHtml(srcSam) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_first_name) + '</label><input class=\"input\" name=\"clone_givenName\" value=\"' + escapeHtml(srcGn) + '\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_last_name) + '</label><input class=\"input\" name=\"clone_sn\" value=\"' + escapeHtml(srcSn) + '\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_upn) + '</label><input class=\"input\" name=\"clone_userPrincipalName\" value=\"' + escapeHtml(srcUpn) + '\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_email) + '</label><input class=\"input\" name=\"clone_mail\" type=\"email\" value=\"' + escapeHtml(srcMail) + '\">' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_label_initial_password) + '</label><input class=\"input\" name=\"clone_password\" type=\"password\" required>' +
                        '<label class=\"label\">' + escapeHtml(INTRANET_I18N.js_account_expiry) + '</label>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" type=\"date\" name=\"clone_exp_date\" style=\"max-width:220px\"><input class=\"input\" type=\"time\" name=\"clone_exp_time\" style=\"max-width:160px\"><label class=\"label\" style=\"margin:0 6px 0 10px\">' + escapeHtml(INTRANET_I18N.js_label_never) + '</label><input type=\"checkbox\" name=\"clone_exp_never\" value=\"1\"' + expNeverChk + '></div>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">' + escapeHtml(INTRANET_I18N.js_apply_group_membership) + '</label><input type=\"checkbox\" name=\"clone_apply_groups\" value=\"1\"' + applyGrpsChk + '></div>' +
                        '<input type=\"hidden\" name=\"clone_groups_json\" value=\"' + escapeHtml(srcGroupsJson) + '\">' +
                        '<input type=\"hidden\" name=\"clone_groups_raw\" value=\"\">' +
                        '<div id=\"clone-groups-selected\" class=\"small\" style=\"margin:8px 0\"></div>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" id=\"clone-group-query\" placeholder=\"' + escapeHtml(INTRANET_I18N.js_ridge_placeholder_group) + '\"><button type=\"button\" class=\"btn sm\" id=\"clone-group-search-btn\">' + escapeHtml(INTRANET_I18N.js_search) + '</button></div>' +
                        '<div id=\"clone-group-results\" class=\"small\" style=\"margin-top:8px\"></div>' +
                        '<div class=\"row\" style=\"margin-top:8px\"><label class=\"label\" style=\"margin:0\">' + escapeHtml(INTRANET_I18N.js_label_force_change_first) + '</label><input type=\"checkbox\" name=\"clone_must_change_at_first_login\" value=\"1\"' + mustChgChk + '></div>';
                } else if (action === 'set_user_groups') {
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"user_for_groups\" value=\"' + escapeHtml(userId) + '\">' +
                        '<input type=\"hidden\" name=\"groups_json\" value=\"[]\">' +
                        '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_manage_user_groups_help) + '</div>' +
                        '<div id=\"user-groups-selected\" class=\"small\" style=\"margin:8px 0\"></div>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" id=\"user-group-query\" placeholder=\"' + escapeHtml(INTRANET_I18N.js_ridge_placeholder_group) + '\"><button type=\"button\" class=\"btn sm\" id=\"user-group-search-btn\">' + escapeHtml(INTRANET_I18N.js_search) + '</button></div>' +
                        '<div id=\"user-group-results\" class=\"small\" style=\"margin-top:8px\"></div>';
                } else if (action === 'set_group_members') {
                    formBody += hidden +
                        '<input type=\"hidden\" name=\"group_for_members\" value=\"' + escapeHtml(dn) + '\">' +
                        '<input type=\"hidden\" name=\"members_json\" value=\"[]\">' +
                        '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_manage_group_members_help) + '</div>' +
                        '<div id=\"group-members-selected\" class=\"small\" style=\"margin:8px 0\"></div>' +
                        '<div class=\"row\" style=\"gap:8px\"><input class=\"input\" id=\"group-member-query\" placeholder=\"' + escapeHtml(INTRANET_I18N.js_ridge_placeholder_user) + '\"><button type=\"button\" class=\"btn sm\" id=\"group-member-search-btn\">' + escapeHtml(INTRANET_I18N.js_search) + '</button></div>' +
                        '<div id=\"group-member-results\" class=\"small\" style=\"margin-top:8px\"></div>';
                } else {
                    return;
                }

                modalBody.innerHTML =
                    '<form method=\"post\" onsubmit=\"return confirm(' + JSON.stringify(INTRANET_I18N.js_confirm_ad_action) + ')\">' +
                    formBody +
                    '<div class=\"row\" style=\"justify-content:flex-end; gap:8px; margin-top:12px\">' +
                    '<button type=\"button\" class=\"btn\" onclick=\"closeExplorerModal()\">' + escapeHtml(INTRANET_I18N.js_cancel) + '</button>' +
                    '<button type=\"submit\" class=\"btn\">' + escapeHtml(INTRANET_I18N.js_execute) + '</button>' +
                    '</div></form>';
                if (action === 'create_user') {
                    const s = modalBody.querySelector('select[name=\"ouDn\"]');
                    if (s) s.value = dn || baseDn || '';
                } else if (action === 'create_group') {
                    const s = modalBody.querySelector('select[name=\"group_ouDn\"]');
                    if (s) s.value = dn || baseDn || '';
                } else if (action === 'move_user_ou') {
                    const s = modalBody.querySelector('select[name=\"new_ou_dn\"]');
                    if (s) {
                        const parent = explorerParentDn(dn);
                        if (parent) {
                            const opt = Array.from(s.options).find(o => o.value && o.value.toLowerCase() === parent.toLowerCase());
                            if (opt) s.value = opt.value;
                        }
                        if (!s.value) s.value = baseDn || '';
                    }
                } else if (action === 'move_computer') {
                    const s = modalBody.querySelector('select[name=\"new_ou_dn_computer\"]');
                    if (s) {
                        const parent = explorerParentDn(dn);
                        if (parent) {
                            const opt = Array.from(s.options).find(o => o.value && o.value.toLowerCase() === parent.toLowerCase());
                            if (opt) s.value = opt.value;
                        }
                        if (!s.value) s.value = baseDn || '';
                    }
                } else if (action === 'clone_user') {
                    const s = modalBody.querySelector('select[name=\"clone_ouDn\"]');
                    if (s) {
                        const parent = explorerParentDn(dn);
                        if (parent) {
                            const opt = Array.from(s.options).find(o => o.value && o.value.toLowerCase() === parent.toLowerCase());
                            if (opt) s.value = opt.value;
                        }
                        if (!s.value) s.value = baseDn || '';
                    }
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const never = !!(sa.accountNeverExpires);
                    const dateInput = modalBody.querySelector('input[name=\"clone_exp_date\"]');
                    const timeInput = modalBody.querySelector('input[name=\"clone_exp_time\"]');
                    const neverInput = modalBody.querySelector('input[name=\"clone_exp_never\"]');
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
                    initCloneGroupsEditor();
                    (function () {
                        const samInput = modalBody.querySelector('input[name="clone_sam"]');
                        const upnInput = modalBody.querySelector('input[name="clone_userPrincipalName"]');
                        const srcUpnStr = String(sa.userPrincipalName || '');
                        if (!samInput || !upnInput || srcUpnStr.indexOf('@') < 0) return;
                        const suffix = srcUpnStr.slice(srcUpnStr.indexOf('@') + 1);
                        samInput.addEventListener('input', function () {
                            const v = (samInput.value || '').trim();
                            if (v) upnInput.value = v + '@' + suffix;
                        });
                    })();
                } else if (action === 'set_user_groups') {
                    initUserGroupsEditor(userId);
                } else if (action === 'set_group_members') {
                    initGroupMembersEditor(dn);
                } else if (action === 'admin_update_user') {
                    const sa = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const siteInput = modalBody.querySelector('input[name=\"site_mod\"]');
                    if (siteInput) siteInput.value = pickExplorerWebsite(sa);
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
                    const pgDnFix = String(sa.primaryGroupDn || sa.PrimaryGroupDn || '').trim();
                    const selPg = modalBody.querySelector('select[name=\"primary_group_mod\"]');
                    if (selPg && pgDnFix) {
                        const hit = Array.from(selPg.options).find(o => o.value && explorerDnEquals(o.value, pgDnFix));
                        if (hit) selPg.value = hit.value;
                    }
                } else if (action === 'update_ou') {
                    const s = modalBody.querySelector('select[name=\"ou_new_parent\"]');
                    if (s) s.value = '';
                }
                explorerModalLastFocus = document.activeElement;
                explorerModal.setAttribute('aria-hidden', 'false');
                explorerModalEscHandler = function (ev) {
                    if (ev.key === 'Escape') {
                        ev.preventDefault();
                        closeExplorerModal();
                    }
                };
                document.addEventListener('keydown', explorerModalEscHandler);
                const closeBtn = document.getElementById('explorer-modal-close');
                if (closeBtn && typeof closeBtn.focus === 'function') {
                    try { closeBtn.focus(); } catch (e) {}
                }
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
                if (!selected.length) {
                    const a = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                    const mos = normalizeMemberOfList(a.memberOf);
                    selected = mos.map(dn => ({ dn, name: shortDnLabel(dn) }));
                }

                const sync = () => {
                    hidden.value = JSON.stringify(selected.map(v => ({ dn: v.dn, name: v.name || '' })));
                    if (selected.length === 0) {
                        selectedWrap.innerHTML = '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_groups_selected) + '</div>';
                        return;
                    }
                    selectedWrap.innerHTML = selected.map((g, i) =>
                        '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-rm=\"' + i + '\">' + escapeHtml(INTRANET_I18N.js_remove) + '</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(g.dn || '') + '</span></div>'
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
                    const endpoint = INTRANET_SELF + '?ajax=search_groups&q=' + encodeURIComponent(q || '*');
                    fetch(endpoint, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                        .then(r => r.json())
                        .then(data => {
                            const rows = Array.isArray(data?.groups) ? data.groups : [];
                            if (!rows.length) {
                                resultsWrap.innerHTML = '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_groups_found) + '</div>';
                                return;
                            }
                            resultsWrap.innerHTML = rows.map((g, i) => {
                                const dn = String(g.dn || '');
                                const exists = selected.some(s => s.dn.toLowerCase() === dn.toLowerCase());
                                return '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-add=\"' + i + '\" ' + (exists ? 'disabled' : '') + '>' + escapeHtml(INTRANET_I18N.js_add) + '</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(dn) + '</span></div>';
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
                            resultsWrap.innerHTML = '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_group_search_unavailable) + '</div>';
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

                const a0 = selectedObjectDetails && selectedObjectDetails.attributes ? selectedObjectDetails.attributes : {};
                let pgDnUserGroups = String(a0.primaryGroupDn || a0.PrimaryGroupDn || '').trim();
                let selected = normalizeMemberOfList(a0.memberOf).map(dn => ({ dn, name: shortDnLabel(dn), sam: '' }));

                const sync = () => {
                    hidden.value = JSON.stringify(selected.map(v => ({ dn: v.dn, name: v.name || '', sam: v.sam || '' })));
                    if (selected.length === 0) {
                        selectedWrap.innerHTML = '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_groups_selected) + '</div>';
                        return;
                    }
                    selectedWrap.innerHTML = selected.map((g, i) => {
                        const isPg = pgDnUserGroups && explorerDnEquals(g.dn, pgDnUserGroups);
                        const rmCtrl = isPg
                            ? '<span class=\"small\" style=\"opacity:.85\">' + escapeHtml(INTRANET_I18N.js_primary_not_removable) + '</span>'
                            : '<button type=\"button\" class=\"btn sm\" data-rm=\"' + i + '\">' + escapeHtml(INTRANET_I18N.js_remove) + '</button>';
                        return '<div class=\"row\" style=\"gap:8px;margin:4px 0;align-items:center\">' + rmCtrl + '<code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(g.dn || '') + '</span></div>';
                    }).join('');
                    selectedWrap.querySelectorAll('button[data-rm]').forEach(b => {
                        b.addEventListener('click', () => {
                            const idx = parseInt(b.getAttribute('data-rm') || '-1', 10);
                            if (idx >= 0) {
                                const g = selected[idx];
                                if (pgDnUserGroups && g && explorerDnEquals(g.dn, pgDnUserGroups)) {
                                    return;
                                }
                                selected.splice(idx, 1);
                                sync();
                            }
                        });
                    });
                };

                const search = () => {
                    const q = (qInput.value || '').trim();
                    const endpoint = INTRANET_SELF + '?ajax=search_groups&q=' + encodeURIComponent(q || '*') + '&scope=all';
                    fetch(endpoint, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                        .then(r => r.json())
                        .then(data => {
                            const rows = Array.isArray(data?.groups) ? data.groups : [];
                            if (!rows.length) {
                                resultsWrap.innerHTML = '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_groups_found) + '</div>';
                                return;
                            }
                            resultsWrap.innerHTML = rows.map((g, i) => {
                                const dn = String(g.dn || '');
                                const exists = selected.some(s => s.dn.toLowerCase() === dn.toLowerCase());
                                return '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-add=\"' + i + '\" ' + (exists ? 'disabled' : '') + '>' + escapeHtml(INTRANET_I18N.js_add) + '</button><code>' + escapeHtml(prettyGroupLabel(g)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(dn) + '</span></div>';
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
                            resultsWrap.innerHTML = '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_group_search_unavailable) + '</div>';
                        });
                };

                sync();
                fetch(INTRANET_SELF + '?ajax=user_groups&user=' + encodeURIComponent(userId), {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                })
                    .then(r => r.json())
                    .then(data => {
                        if (data && data.error) return;
                        const pgApi = String(data.primaryGroupDn || data.PrimaryGroupDn || '').trim();
                        if (pgApi) pgDnUserGroups = pgApi;
                        const groups = Array.isArray(data?.groups) ? data.groups : [];
                        if (groups.length) {
                            selected = groups
                                .map(g => ({ dn: String(g.dn || ''), name: String(g.name || ''), sam: String(g.sam || '') }))
                                .filter(g => g.dn);
                        }
                        sync();
                    })
                    .catch(() => {
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
                        selectedWrap.innerHTML = '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_members_selected) + '</div>';
                        return;
                    }
                    selectedWrap.innerHTML = selected.map((u, i) =>
                        '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-rm=\"' + i + '\">' + escapeHtml(INTRANET_I18N.js_remove) + '</button><code>' + escapeHtml(prettyUserLabel(u)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(u.dn || '') + '</span></div>'
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
                    fetch(INTRANET_SELF + '?ajax=search_users&q=' + encodeURIComponent(q || '*'), {
                        credentials: 'same-origin',
                        headers: { 'X-Requested-With': 'XMLHttpRequest' }
                    })
                        .then(r => r.json())
                        .then(data => {
                            const rows = Array.isArray(data?.results) ? data.results : [];
                            if (!rows.length) {
                                resultsWrap.innerHTML = '<div class=\"small\">' + escapeHtml(INTRANET_I18N.js_no_users_found) + '</div>';
                                return;
                            }
                            resultsWrap.innerHTML = rows.map((u, i) => {
                                const dn = String(u.dn || '');
                                const exists = selected.some(s => s.dn.toLowerCase() === dn.toLowerCase());
                                return '<div class=\"row\" style=\"gap:8px;margin:4px 0\"><button type=\"button\" class=\"btn sm\" data-add=\"' + i + '\" ' + (exists ? 'disabled' : '') + '>' + escapeHtml(INTRANET_I18N.js_add) + '</button><code>' + escapeHtml(prettyUserLabel(u)) + '</code><span class=\"small\" style=\"opacity:.75\">' + escapeHtml(dn) + '</span></div>';
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
                            resultsWrap.innerHTML = '<div class=\"small\" style=\"color:#fca5a5\">' + escapeHtml(INTRANET_I18N.js_user_search_unavailable) + '</div>';
                        });
                };

                fetch(INTRANET_SELF + '?ajax=group_members&group=' + encodeURIComponent(groupDn), {
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
        <small><?= htmlspecialchars(__('toast_click_close')) ?></small>
    </div>
<?php else: ?>
    <div id="toast" class="toast hide" data-show="0"></div>
<?php endif; ?>


<body>
    <div class="container">

        <div class="nav" id="app-nav">
            <div class="nav-brand">Intranet</div>
            <?php $intranetLangUi = $INTRANET_LANG ?? 'en'; ?>
            <?php if (!empty($INTRANET_LANG_SWITCH_UI)): ?>
            <div class="nav-lang">
            <div class="lang-switch-wrap" title="<?= htmlspecialchars(__('lang_switch_title')) ?>">
                <form method="post" class="intranet-lang-form" action="">
                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                    <input type="hidden" name="intranet_set_lang" value="1">
                    <label class="visually-hidden" for="intranet-lang"><?= htmlspecialchars(__('lang_switch_aria')) ?></label>
                    <select id="intranet-lang" name="intranet_lang" class="lang-switch" autocomplete="off"
                        aria-label="<?= htmlspecialchars(__('lang_switch_aria')) ?>"
                        onchange="this.form.submit()">
                        <?php foreach (intranet_i18n_allowed_locales() as $loc): ?>
                            <option value="<?= htmlspecialchars($loc, ENT_QUOTES, 'UTF-8') ?>" <?= $intranetLangUi === $loc ? 'selected' : '' ?>>
                                <?= htmlspecialchars(intranet_i18n_locale_native_label($loc)) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>
            </div>
            </div>
            <?php endif; ?>
            <?php if (!isset($_SESSION['username'])): ?>
            <button type="button" class="nav-menu-toggle" id="nav-menu-toggle" aria-expanded="false" aria-controls="nav-menu-panel"
                aria-label="<?= htmlspecialchars(__('nav_menu_toggle_aria')) ?>">
                <span class="nav-menu-toggle-box" aria-hidden="true"><span></span><span></span><span></span></span>
            </button>
            <div class="nav-panel" id="nav-menu-panel">
                <button class="tab-btn active" data-tab="login" onclick="setActive('login')"><?= htmlspecialchars(__('tab_login')) ?></button>
                <span class="badge"><?= htmlspecialchars(__('nav_portal')) ?></span>
            </div>
            <?php else: ?>
                <?php if ($forcePwMode): ?>
                    <!-- Forced password change: no tabs or logout -->
                    <?php if ($SHOW_CLIENT_IP): ?>
                        <div class="row nav-forcepw-meta" style="gap:8px; align-items:center">
                            <span class="badge"><?= htmlspecialchars(sprintf(__('badge_ip'), $clientIp)) ?></span>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
            <button type="button" class="nav-menu-toggle" id="nav-menu-toggle" aria-expanded="false" aria-controls="nav-menu-panel"
                aria-label="<?= htmlspecialchars(__('nav_menu_toggle_aria')) ?>">
                <span class="nav-menu-toggle-box" aria-hidden="true"><span></span><span></span><span></span></span>
            </button>
            <div class="nav-panel" id="nav-menu-panel">
                    <button class="tab-btn" data-tab="profil" onclick="setActive('profil')"><?= htmlspecialchars(__('tab_profile')) ?></button>

                    <?php if ($hasToolsForUser): ?>
                        <button class="tab-btn" data-tab="outils" onclick="setActive('outils')"><?= htmlspecialchars(__('tab_tools_user')) ?></button>
                    <?php endif; ?>

                    <?php if ($canUserAdmin): ?>
                        <button class="tab-btn" data-tab="tools" onclick="setActive('tools')"><?= htmlspecialchars(__('tab_tools_admin')) ?></button>
                        <button class="tab-btn" data-tab="admin-users" onclick="setActive('admin-users')"><?= htmlspecialchars(__('tab_admin_users')) ?></button>
                    <?php endif; ?>
                    <?php if ($canDomainAdmin): ?>
                        <button class="tab-btn" data-tab="explorer" onclick="setActive('explorer')"><?= htmlspecialchars(__('tab_explorer')) ?></button>
                        <button class="tab-btn" data-tab="admin-domain" onclick="setActive('admin-domain')"><?= htmlspecialchars(__('tab_admin_domain')) ?></button>
                    <?php endif; ?>

                    <div class="row nav-trailing">
                        <?php if ($SHOW_CLIENT_IP): ?>
                            <span class="badge"><?= htmlspecialchars(sprintf(__('badge_ip'), $clientIp)) ?></span>
                        <?php endif; ?>
                        <form method="post" class="inline">
                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                            <input type="hidden" name="action" value="logout">
                            <button class="tab-btn"><?= htmlspecialchars(__('nav_logout')) ?></button>
                        </form>
                    </div>
            </div>
                <?php endif; ?>

            <?php endif; ?>
        </div>

        <div class="content">

            <?php if (!empty($ldap_api_offline) && isset($_SESSION['username'])): ?>
                <div class="card" style="margin-bottom:16px;border:1px solid #b45309;background:#1c1917;color:#fcd34d">
                    <strong><?= htmlspecialchars(__('offline_banner_title')) ?></strong>
                    <?= htmlspecialchars(sprintf(__('offline_banner_body'), (int) API_LDAP_CURL_TIMEOUT_SEC)) ?>
                </div>
            <?php endif; ?>

            <?php if ($forcePwMode): ?>
                <div class="card center" style="max-width:520px">
                    <h2><?= htmlspecialchars(__('force_pw_title')) ?></h2>
                    <p class="page-subtitle" style="color:var(--sub)"><?= htmlspecialchars(__('force_pw_subtitle')) ?></p>
                    <form method="post" autocomplete="off" novalidate>
                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="action" value="changepw">
                        <label class="label" for="current_password"><?= htmlspecialchars(__('label_current_password')) ?></label>
                        <input class="input" id="current_password" name="current_password" type="password" required>

                        <label class="label" for="new_password"><?= htmlspecialchars(__('label_new_password')) ?></label>
                        <input class="input" id="new_password" name="new_password" type="password" required>

                        <label class="label" for="confirm_password"><?= htmlspecialchars(__('label_confirm')) ?></label>
                        <input class="input" id="confirm_password" name="confirm_password" type="password" required>

                        <div style="margin-top:12px">
                            <button class="btn" type="submit"><?= htmlspecialchars(__('btn_change')) ?></button>
                        </div>
                    </form>
                </div>

            <?php else: ?>

                <!-- LOGIN -->
                <div id="tab-login" class="tab" style="display:none">
                    <div class="card center">
                        <h2><?= htmlspecialchars(__('login_title')) ?></h2>
                        <p class="page-subtitle"><?= htmlspecialchars(__('login_subtitle')) ?></p>
                        <form method="post" autocomplete="off" novalidate>
                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                            <input type="hidden" name="action" value="login">
                            <label class="label" for="user"><?= htmlspecialchars(__('label_username')) ?></label>
                            <input class="input" id="user" name="user" type="text" required>
                            <label class="label" for="password"><?= htmlspecialchars(__('label_password')) ?></label>
                            <input class="input" id="password" name="password" type="password" required>
                            <?php if ($HCAPTCHA_ENABLED): ?>
                            <div style="margin:14px 0" class="h-captcha"
                                data-sitekey="<?= htmlspecialchars($HCAPTCHA_SITEKEY) ?>"></div>
                            <?php endif; ?>
                            <button class="btn" type="submit"><?= htmlspecialchars(__('btn_sign_in')) ?></button>
                        </form>
                        <?php if (!empty($FORGOT_ENABLED)): ?>
                            <div class="hr"></div>
                            <a class="link" href="forgot_password.php"><?= htmlspecialchars(__('link_forgot_password')) ?></a>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- PROFILE -->
                <div id="tab-profil" class="tab" style="display:none">
                    <?php if (isset($_SESSION['username'])): ?>

                        <div class="row" style="margin-bottom:8px">
                            <h2 style="margin:0"><?= htmlspecialchars(sprintf(__('profile_hello'), $given ?: $_SESSION['username'])) ?></h2>
                            <span class="right badge"><?= htmlspecialchars(__('badge_connected')) ?></span>
                            <?php if ($mustChange): ?><span class="badge" style="background:#7f1d1d;color:#fecaca"><?= htmlspecialchars(__('badge_must_change_pw')) ?></span><?php endif; ?>
                        </div>

                        <div class="grid grid-2">
                            <div class="card">
                                <h3><?= htmlspecialchars(__('profile_info_title')) ?></h3>
                                <form method="post" autocomplete="off" novalidate>
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                    <input type="hidden" name="action" value="updateProfile">
                                    <label class="label" for="prenom"><?= htmlspecialchars(__('label_first_name')) ?></label>
                                    <input class="input" id="prenom" name="prenom" type="text"
                                        value="<?= htmlspecialchars($given) ?>">
                                    <label class="label" for="nom"><?= htmlspecialchars(__('label_last_name')) ?></label>
                                    <input class="input" id="nom" name="nom" type="text" value="<?= htmlspecialchars($sn) ?>">
                                    <label class="label" for="mail"><?= htmlspecialchars(__('label_email')) ?></label>
                                    <input class="input" id="mail" name="mail" type="email"
                                        value="<?= htmlspecialchars($mail) ?>">
                                    <label class="label" for="site"><?= htmlspecialchars(__('label_website')) ?></label>
                                    <input class="input" id="site" name="site" type="text"
                                        value="<?= htmlspecialchars($site) ?>">
                                    <label class="label" for="adresse"><?= htmlspecialchars(__('label_address')) ?></label>
                                    <input class="input" id="adresse" name="adresse" type="text"
                                        value="<?= htmlspecialchars($addr) ?>">
                                    <label class="label" for="telephone"><?= htmlspecialchars(__('label_phone')) ?></label>
                                    <input class="input" id="telephone" name="telephone" type="text"
                                        value="<?= htmlspecialchars($tel) ?>">
                                    <div class="small"><?= htmlspecialchars(__('hint_phone_fr')) ?></div>
                                    <div style="margin-top:12px"><button class="btn" type="submit"><?= htmlspecialchars(__('btn_update')) ?></button></div>
                                </form>
                                <div class="hr"></div>
                                <h3><?= htmlspecialchars(__('profile_groups_title')) ?></h3>
                                <?php if ($profilePrimaryGroupLine !== ''): ?>
                                    <div class="small" style="margin-bottom:8px"><strong><?= htmlspecialchars(__('profile_primary_group')) ?></strong><br><code
                                            style="word-break:break-all"><?= htmlspecialchars($profilePrimaryGroupLine) ?></code>
                                    </div>
                                <?php endif; ?>
                                <div class="small" style="opacity:.9;margin-bottom:4px"><?= htmlspecialchars(__('profile_member_direct')) ?></div>
                                <?php if ($profileGroupsDirect): ?>
                                    <ul class="small" style="max-height:200px;overflow:auto;margin:0 0 8px"><?php foreach ($profileGroupsDirect as $g): ?>
                                            <li><?= htmlspecialchars((string) $g) ?></li><?php endforeach; ?>
                                    </ul>
                                <?php else: ?>
                                    <div class="small" style="margin-bottom:8px"><?= htmlspecialchars(__('profile_no_direct_groups')) ?></div>
                                <?php endif; ?>
                                <?php if ($profileGroupsEffective && count($profileGroupsEffective) !== count($profileGroupsDirect)): ?>
                                    <div class="small" style="opacity:.9;margin-bottom:4px"><?= htmlspecialchars(__('profile_effective')) ?></div>
                                    <ul class="small" style="max-height:200px;overflow:auto;margin:0"><?php foreach ($profileGroupsEffective as $g): ?>
                                            <li><?= htmlspecialchars((string) $g) ?></li><?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </div>

                            <div class="card">
                                <h3><?= htmlspecialchars(__('profile_change_pw_title')) ?></h3>
                                <form method="post" autocomplete="off" novalidate>
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                    <input type="hidden" name="action" value="changepw">
                                    <label class="label" for="current_password"><?= htmlspecialchars(__('label_current_password')) ?></label>
                                    <input class="input" id="current_password" name="current_password" type="password" required>
                                    <label class="label" for="new_password"><?= htmlspecialchars(__('label_new_password')) ?></label>
                                    <input class="input" id="new_password" name="new_password" type="password" required>
                                    <label class="label" for="confirm_password"><?= htmlspecialchars(__('label_confirm')) ?></label>
                                    <input class="input" id="confirm_password" name="confirm_password" type="password" required>
                                    <div style="margin-top:12px"><button class="btn" type="submit"><?= htmlspecialchars(__('btn_change')) ?></button></div>
                                </form>
                                <?php if ($mustChange): ?>
                                    <div class="small" style="margin-top:10px;color:#fca5a5"><?= htmlspecialchars(__('profile_must_change_first')) ?></div><?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- OUTILS -->
                <div id="tab-outils" class="tab" style="display:none">
                    <?php if (isset($_SESSION['username'])): ?>
                        <h2><?= htmlspecialchars(__('tools_my_title')) ?></h2>

                        <?php if (!$hasToolsForUser): ?>
                            <div class="card">
                                <div class="small"><?= htmlspecialchars(__('tools_none')) ?></div>
                            </div>
                        <?php else: ?>
                            <div class="tools">
                                <?php
                                $loginBase = $userInfo['userPrincipalName'] ?? $_SESSION['username'];
                                foreach ($visibleTools as $t):
                                    $toolId = (int) ($t['id'] ?? 0);
                                    $title = $t['title'] ?? '';
                                    $desc = $t['description'] ?? '';
                                    $url = intranet_sanitize_tool_link_url((string) ($t['url'] ?? ''));
                                    $icon = intranet_sanitize_tool_image_url((string) ($t['icon'] ?? ''));
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
                                                    <?= htmlspecialchars(__('tools_expected_login')) ?>&nbsp;
                                                    <code><?= htmlspecialchars($hintP) ?><strong><?= htmlspecialchars($loginBase) ?></strong><?= htmlspecialchars($hintS) ?></code>
                                                </div>
                                            <?php endif; ?>
                                            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
                                                <?php if ($url !== ''): ?>
                                                <a class="btn" style="padding:8px 12px" target="_blank" rel="noopener noreferrer"
                                                    href="<?= htmlspecialchars($url) ?>"><?= htmlspecialchars(__('tools_open')) ?></a>
                                                <?php endif; ?>
                                                <?php if ($inst): ?>
                                                    <?php
                                                    // Allow rich HTML with a strict tag whitelist only.
                                                    $instSafe = sanitize_tool_instructions_html((string) $inst);
                                                    ?>
                                                    <?php if (!empty($instSafe)): ?>
                                                        <button
                                                            type="button"
                                                            class="btn"
                                                            style="padding:6px 10px;background:transparent;border:1px solid var(--border,#1f2937);color:var(--sub,#9ca3af);font-size:12px"
                                                            onclick="(function(id,btn){var el=document.getElementById(id);if(!el)return;var open=el.getAttribute('data-open')==='1';el.setAttribute('data-open',open?'0':'1');el.style.display=open?'none':'block';btn.innerText=open?<?= json_encode(__('tools_instructions'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>:<?= json_encode(__('tools_hide_instructions'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;})('tool-inst-<?= $toolId ?>', this);">
                                                            <?= htmlspecialchars(__('tools_instructions')) ?>
                                                        </button>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </div>
                                            <?php if (!empty($instSafe)): ?>
                                                <div id="tool-inst-<?= $toolId ?>"
                                                    data-open="0"
                                                    style="display:none;margin-top:8px;padding:10px 12px;border-radius:10px;border:1px solid #1f2937;background:#020617;max-width:100%;overflow-x:auto">
                                                    <div class="small" style="font-weight:600;margin-bottom:4px;opacity:.9">
                                                        <?= htmlspecialchars(__('tools_instructions')) ?>
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

                <!-- Tools admin (user admins) -->
                <div id="tab-tools" class="tab" style="display:none">
                    <?php if ($canUserAdmin): ?>
                        <div class="grid grid-2">
                            <div class="card">
                                <h3><?= htmlspecialchars(__('adm_tools_list_title')) ?></h3>
                                <?php
                                try {
                                    $adminTools = tools_all($TOOL_PDO);
                                } catch (Throwable $e) {
                                    $adminTools = [];
                                }
                                if (!$adminTools): ?>
                                    <div class="small"><?= htmlspecialchars(__('adm_tools_none')) ?></div>
                                <?php else: ?>
                                    <table class="table">
                                        <tr>
                                            <th><?= htmlspecialchars(__('adm_th_num')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_title')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_groups')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_order')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_state')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_actions')) ?></th>
                                        </tr>
                                        <?php foreach ($adminTools as $t): ?>
                                            <tr>
                                                <td><?= (int) $t['id'] ?></td>
                                                <td><?= htmlspecialchars($t['title']) ?></td>
                                                <td class="small">
                                                    <?php $g = json_decode($t['group_cns'] ?? '[]', true);
                                                    echo $g && is_array($g) ? htmlspecialchars(implode(', ', $g)) : htmlspecialchars(__('adm_groups_all')); ?>
                                                </td>
                                                <td><?= (int) $t['sort_order'] ?></td>
                                                <td><?= !empty($t['enabled'])
                                                    ? '<span class="badge" style="background:#14532d;color:#bbf7d0">' . htmlspecialchars(__('status_active')) . '</span>'
                                                    : '<span class="badge" style="background:#7f1d1d;color:#fecaca">' . htmlspecialchars(__('status_inactive')) . '</span>' ?>
                                                </td>
                                                <td class="actions">
                                                    <form method="post" class="inline">
                                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                        <input type="hidden" name="admin_action" value="tool_move">
                                                        <input type="hidden" name="id" value="<?= (int) $t['id'] ?>">
                                                        <button class="btn sm" name="dir" value="up">↑</button>
                                                        <button class="btn sm" name="dir" value="down">↓</button>
                                                    </form>
                                                    <a class="btn sm" href="?edit_tool_id=<?= (int) $t['id'] ?>#tab-tools"><?= htmlspecialchars(__('adm_tool_edit')) ?></a>
                                                    <form method="post" class="inline"
                                                        onsubmit="return confirm(<?= json_encode(__('adm_tool_delete_confirm'), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>)">
                                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                        <input type="hidden" name="admin_action" value="tool_delete">
                                                        <input type="hidden" name="id" value="<?= (int) $t['id'] ?>">
                                                        <button class="btn sm"><?= htmlspecialchars(__('adm_tool_delete')) ?></button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </table>
                                <?php endif; ?>
                            </div>

                            <div class="card">
                                <?php
                                $editId = isset($_GET['edit_tool_id']) ? (int) $_GET['edit_tool_id'] : 0;
                                $editTool = $editId ? tools_find($TOOL_PDO, $editId) : null;
                                ?>
                                <h3><?= $editTool
                                    ? htmlspecialchars(sprintf(__('adm_tool_form_edit'), $editId))
                                    : htmlspecialchars(__('adm_tool_form_add')) ?></h3>
                                <form method="post">
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                    <input type="hidden" name="admin_action" value="tool_save">
                                    <input type="hidden" name="id" value="<?= (int) ($editTool['id'] ?? 0) ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_title')) ?></label>
                                    <input class="input" name="title" required
                                        value="<?= htmlspecialchars($editTool['title'] ?? '') ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_desc')) ?></label>
                                    <input class="input" name="description"
                                        value="<?= htmlspecialchars($editTool['description'] ?? '') ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_url')) ?></label>
                                    <input class="input" name="url" required
                                        value="<?= htmlspecialchars($editTool['url'] ?? '') ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_icon')) ?></label>
                                    <input class="input" name="icon" value="<?= htmlspecialchars($editTool['icon'] ?? '') ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_group_cns')) ?></label>
                                    <input class="input" name="group_cns" placeholder="<?= htmlspecialchars(__('adm_tool_ph_group_cns')) ?>" value="<?php
                                    $g = $editTool ? (json_decode($editTool['group_cns'] ?? '[]', true) ?: []) : [];
                                    echo htmlspecialchars(implode(',', $g));
                                    ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_sort')) ?></label>
                                    <input class="input" type="number" name="sort_order"
                                        value="<?= (int) ($editTool['sort_order'] ?? 1000) ?>">

                                    <label class="label"><?= htmlspecialchars(__('adm_tool_label_instructions')) ?></label>
                                    <textarea class="input" name="instructions" rows="4"
                                        placeholder="<?= htmlspecialchars(__('adm_tool_ph_instructions')) ?>"><?= htmlspecialchars($editTool['instructions'] ?? '') ?></textarea>
                                    <div class="small" style="margin-top:4px;opacity:.8">
                                        <?= htmlspecialchars(__('adm_tool_rich_help')) ?>
                                    </div>

                                    <div class="grid" style="grid-template-columns:1fr 1fr; gap:8px">
                                        <div>
                                            <label class="label"><?= htmlspecialchars(__('adm_tool_login_prefix')) ?></label>
                                            <input class="input" name="login_hint_prefix"
                                                value="<?= htmlspecialchars($editTool['login_hint_prefix'] ?? '') ?>">
                                        </div>
                                        <div>
                                            <label class="label"><?= htmlspecialchars(__('adm_tool_login_suffix')) ?></label>
                                            <input class="input" name="login_hint_suffix"
                                                value="<?= htmlspecialchars($editTool['login_hint_suffix'] ?? '') ?>">
                                        </div>
                                    </div>

                                    <div class="row" style="margin-top:8px">
                                        <label class="label" style="margin:0"><?= htmlspecialchars(__('adm_tool_show_login_hint')) ?></label>
                                        <input type="checkbox" name="show_login_hint" value="1"
                                            <?= !empty($editTool['show_login_hint']) ? 'checked' : '' ?>>
                                        <label class="label" style="margin-left:16px;margin:0"><?= htmlspecialchars(__('adm_tool_enabled')) ?></label>
                                        <input type="checkbox" name="enabled" value="1" <?= !empty($editTool['enabled']) ? 'checked' : '' ?>>
                                    </div>

                                    <div style="margin-top:10px"><button class="btn"
                                            type="submit"><?= htmlspecialchars($editTool ? __('adm_btn_update') : __('adm_btn_create')) ?></button></div>
                                </form>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- Admin: users -->
                <div id="tab-admin-users" class="tab" style="display:none">
                    <?php if ($canUserAdmin): ?>

                        <div class="card" data-focus="users_search">
                            <h3><?= htmlspecialchars(__('adm_users_search_title')) ?></h3>
                            <form method="get" class="grid" style="grid-template-columns:repeat(6,1fr);gap:8px">
                                <input type="hidden" name="ps" value="<?= (int) $DEFAULT_PAGE_SIZE ?>">
                                <input type="hidden" name="p" value="<?= (int) ($_GET['p'] ?? 1) ?>">

                                <div><label class="label"><?= htmlspecialchars(__('label_first_name')) ?></label><input class="input" name="q_gn"
                                        value="<?= htmlspecialchars($_GET['q_gn'] ?? '') ?>"></div>
                                <div><label class="label"><?= htmlspecialchars(__('label_last_name')) ?></label><input class="input" name="q_sn"
                                        value="<?= htmlspecialchars($_GET['q_sn'] ?? '') ?>"></div>
                                <div><label class="label"><?= htmlspecialchars(__('label_email')) ?></label><input class="input" name="q_mail"
                                        value="<?= htmlspecialchars($_GET['q_mail'] ?? '') ?>"></div>
                                <div><label class="label"><?= htmlspecialchars(__('label_phone')) ?></label><input class="input" name="q_tel"
                                        value="<?= htmlspecialchars($_GET['q_tel'] ?? '') ?>"></div>
                                <div><label class="label"><?= htmlspecialchars(__('adm_label_site')) ?></label><input class="input" name="q_site"
                                        value="<?= htmlspecialchars($_GET['q_site'] ?? '') ?>"></div>
                                <div><label class="label"><?= htmlspecialchars(__('adm_label_desc')) ?></label><input class="input" name="q_desc"
                                        value="<?= htmlspecialchars($_GET['q_desc'] ?? '') ?>"></div>

                                <div class="row" style="align-items:end">
                                    <div>
                                        <label class="label"><?= htmlspecialchars(__('adm_th_isadmin')) ?></label>
                                        <select class="input" name="q_admin">
                                            <?php $qa = $_GET['q_admin'] ?? ''; ?>
                                            <option value="" <?= $qa === '' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_filter_any')) ?></option>
                                            <option value="1" <?= $qa === '1' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_yes')) ?></option>
                                            <option value="0" <?= $qa === '0' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_no')) ?></option>
                                        </select>
                                    </div>
                                </div>

                                <div class="row" style="align-items:end">
                                    <div style="width:100%">
                                        <label class="label">OU</label>
                                        <?php if (!empty($ouOptions)): ?>
                                            <select class="input" name="q_ou">
                                                <option value=""><?= htmlspecialchars(__('adm_ou_all')) ?></option>
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
                                            <input class="input" name="q_ou" placeholder="<?= htmlspecialchars(__('adm_ph_ou_dn')) ?>">
                                        <?php endif; ?>
                                    </div>
                                </div>

                                <div style="grid-column:1/-1" class="row">
                                    <div style="flex:1">
                                        <label class="label"><?= htmlspecialchars(__('adm_global_search_label')) ?></label>
                                        <input class="input" name="uq" placeholder="<?= htmlspecialchars(__('adm_global_search_ph')) ?>"
                                            value="<?= htmlspecialchars($_GET['uq'] ?? '') ?>">
                                    </div>
                                    <div>
                                        <label class="label">&nbsp;</label>
                                        <button class="btn" type="submit"
                                            onclick="history.replaceState(null,'','#tab-admin-users')"><?= htmlspecialchars(__('adm_search')) ?></button>
                                    </div>
                                </div>
                            </form>
                            <div class="small"><?= htmlspecialchars(__('adm_users_hint_search')) ?></div>
                        </div>

                        <?php /* Legacy inline user detail forms removed (AD explorer modals). */ ?>

                    <div class="card" style="margin-top:16px" data-focus="users_list">
                        <h3><?= htmlspecialchars(__('adm_users_list_title')) ?></h3>

                        <?php
                        // Pagination + optional global search (* = all)
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
                            // groups=effective: nested + primary group, isAdmin (same as /auth and GET /user)
                            $endpoint = '/users?page=' . $p . '&pageSize=' . $ps . '&groups=effective';
                            // Do not send search='*' to the API
                            if ($uq !== '' && $uq !== '*') {
                                $endpoint .= '&search=' . rawurlencode($uq);
                            }

                            $resp = callApi_ldap('GET', $endpoint, null, true);

                            // 1) Load results first
                            $users = (!$resp['error'] && is_array($resp['data'])) ? $resp['data'] : [];
                            $hasMore = !empty($resp['headers']['x-has-more'])
                                && strtolower($resp['headers']['x-has-more']) === 'true';

                            // 2) Optional PHP-side global search filter (fallback)
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

                            // 3) Other filters (name, mail, OU, etc.)
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
                                    $ok = $ok && (intranet_api_user_row_is_admin($u) === ($want['adm'] === '1'));
                                if ($want['ou'] !== '')
                                    $ok = $ok && isset($u['dn']) && dn_is_descendant($want['ou'], (string) $u['dn']);
                                return $ok;
                            }));
                        }
                        ?>

                        <?php if (!$filtersPresent): ?>
                            <div class="small"><?= htmlspecialchars(__('adm_users_empty_until_search')) ?></div>
                        <?php elseif (!$users): ?>
                            <div class="small"><?= htmlspecialchars(__('adm_users_none_found')) ?></div>
                        <?php else: ?>

                            <form id="bulkForm" method="post">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="bulk_users">

                                <div class="row" style="gap:8px; margin:8px 0">
                                    <select class="input" id="bulk-action" name="bulk_action" style="max-width:220px">
                                        <option value="disable"><?= htmlspecialchars(__('adm_bulk_disable')) ?></option>
                                        <option value="enable"><?= htmlspecialchars(__('adm_bulk_enable')) ?></option>
                                        <option value="unlock"><?= htmlspecialchars(__('adm_bulk_unlock')) ?></option>
                                        <option value="delete"><?= htmlspecialchars(__('adm_bulk_delete')) ?></option>
                                        <option value="move"><?= htmlspecialchars(__('adm_bulk_move_ou')) ?></option>
                                    </select>

                                    <div id="bulk-ou-wrap" style="display:none; max-width:520px; width:100%">
                                        <div class="row" style="gap:8px">
                                            <label class="label" style="margin:0"><?= htmlspecialchars(__('adm_bulk_target_ou')) ?></label>
                                            <?php if (!empty($ouOptions)): ?>
                                                <select class="input" name="bulk_move_ou" style="flex:1">
                                                    <option value=""><?= htmlspecialchars(__('adm_bulk_choose_ou')) ?></option>
                                                    <?php foreach ($ouOptions as $opt): ?>
                                                        <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                            <?= htmlspecialchars($opt['label']) ?>
                                                        </option>
                                                    <?php endforeach; ?>
                                                </select>
                                            <?php else: ?>
                                                <input class="input" name="bulk_move_ou" placeholder="<?= htmlspecialchars(__('adm_ph_ou_dn')) ?>"
                                                    style="flex:1">
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <button class="btn" type="submit" onclick="history.replaceState(null,'','#tab-admin-users')">
                                        <?= htmlspecialchars(__('adm_apply_selection')) ?>
                                    </button>
                                </div>
                            </form>

                            <table class="table">
                                <tr>
                                    <th style="width:36px">
                                        <input id="sel-all" type="checkbox" title="<?= htmlspecialchars(__('adm_sel_all_title')) ?>">
                                    </th>
                                    <th><?= htmlspecialchars(__('adm_th_sam')) ?></th>
                                    <th><?= htmlspecialchars(__('label_first_name')) ?></th>
                                    <th><?= htmlspecialchars(__('label_last_name')) ?></th>
                                    <th><?= htmlspecialchars(__('label_email')) ?></th>
                                    <th><?= htmlspecialchars(__('adm_th_tel')) ?></th>
                                    <th><?= htmlspecialchars(__('adm_th_isadmin')) ?></th>
                                    <th><?= htmlspecialchars(__('adm_th_state')) ?></th>
                                    <th style="width:360px"><?= htmlspecialchars(__('adm_th_actions')) ?></th>
                                </tr>

                                <?php foreach ($users as $u):
                                    $sam = htmlspecialchars($u['sAMAccountName'] ?? '');
                                    $gn = htmlspecialchars($u['givenName'] ?? '');
                                    $snv = htmlspecialchars($u['sn'] ?? '');
                                    $em = htmlspecialchars($u['mail'] ?? '');
                                    $ph = htmlspecialchars($u['telephoneNumber'] ?? '');
                                    $disabled = !empty($u['disabled']);
                                    $isAdm = intranet_api_user_row_is_admin($u);
                                    $state = $disabled
                                        ? '<span class="badge" style="background:#7f1d1d;color:#fecaca">' . htmlspecialchars(__('status_disabled')) . '</span>'
                                        : '<span class="badge" style="background:#14532d;color:#bbf7d0">' . htmlspecialchars(__('status_active')) . '</span>';
                                    $link = '?exq=' . urlencode($sam) . '&extype=user#tab-explorer';
                                    ?>
                                    <tr>
                                        <td><input type="checkbox" form="bulkForm" name="sel[]" value="<?= $sam ?>"></td>
                                        <td><?= $sam ?></td>
                                        <td><?= $gn ?></td>
                                        <td><?= $snv ?></td>
                                        <td><?= $em ?></td>
                                        <td><?= $ph ?></td>
                                        <td><?= $isAdm ? '<span class="badge">' . htmlspecialchars(__('adm_yes')) . '</span>' : '<span class="badge">' . htmlspecialchars(__('adm_no')) . '</span>' ?></td>
                                        <td><?= $state ?></td>
                                        <td class="actions">
                                            <a class="btn sm" href="<?= $link ?>"><?= htmlspecialchars(__('adm_explore_ad')) ?></a>

                                            <?php if ($disabled): ?>
                                                <form method="post" class="inline">
                                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                    <input type="hidden" name="admin_action" value="enable_user">
                                                    <input type="hidden" name="persist_selected_sam" value="<?= htmlspecialchars($sam) ?>">
                                                    <input type="hidden" name="sam_toggle" value="<?= htmlspecialchars($sam) ?>">
                                                    <button class="btn sm" type="submit"><?= htmlspecialchars(__('js_btn_enable')) ?></button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" class="inline">
                                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                    <input type="hidden" name="admin_action" value="disable_user">
                                                    <input type="hidden" name="persist_selected_sam" value="<?= htmlspecialchars($sam) ?>">
                                                    <input type="hidden" name="sam_toggle" value="<?= htmlspecialchars($sam) ?>">
                                                    <button class="btn sm" type="submit"><?= htmlspecialchars(__('js_btn_disable')) ?></button>
                                                </form>
                                            <?php endif; ?>

                                            <form method="post" class="inline" title="<?= htmlspecialchars(__('adm_unlock_form_title')) ?>">
                                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                                <input type="hidden" name="admin_action" value="unlock_user">
                                                <input type="hidden" name="persist_selected_sam" value="<?= htmlspecialchars($sam) ?>">
                                                <input type="hidden" name="sam_unlock" value="<?= htmlspecialchars($sam) ?>">
                                                <button class="btn sm" type="submit"><?= htmlspecialchars(__('js_btn_unlock')) ?></button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </table>

                            <div class="pagination">
                                <?php if ($p > 1): ?>
                                    <a class="btn"
                                        href="<?= htmlspecialchars(preg_replace('/([?#].*)?$/', '', $_SERVER['REQUEST_URI'])) ?>?<?= http_build_query(array_merge($_GET, ['p' => $p - 1])) ?>#tab-admin-users"><?= htmlspecialchars(__('adm_pagination_prev')) ?></a>
                                <?php endif; ?>
                                <span class="small"><?= htmlspecialchars(sprintf(__('adm_pagination_page'), $p)) ?></span>
                                <?php if ($hasMore): ?>
                                    <a class="btn"
                                        href="<?= htmlspecialchars(preg_replace('/([?#].*)?$/', '', $_SERVER['REQUEST_URI'])) ?>?<?= http_build_query(array_merge($_GET, ['p' => $p + 1])) ?>#tab-admin-users"><?= htmlspecialchars(__('adm_pagination_next')) ?></a>
                                <?php endif; ?>
                            </div>

                        <?php endif; ?>
                    </div>

                    <?php /* Legacy user forms removed (duplicate of AD explorer modals). */ ?>

                <?php endif; ?>
            </div>

            <!-- EXPLORATEUR AD (arbre) -->
            <div id="tab-explorer" class="tab" style="display:none">
                <?php if ($canDomainAdmin): ?>
                    <h2><?= htmlspecialchars(__('adm_exp_title')) ?></h2>
                    <p class="page-subtitle" style="margin-bottom:16px">
                        <?= htmlspecialchars(__('adm_exp_subtitle')) ?>
                    </p>
                    <div class="small" style="margin-bottom:12px">
                        <?= htmlspecialchars(__('adm_exp_base_dn_label')) ?>
                        <code><?= htmlspecialchars((string) ($adMeta['baseDn'] ?? ($adTree['explorerBaseDn'] ?? $adTree['baseDn'] ?? __('adm_unknown')))) ?></code>
                    </div>
                    <form method="get" style="display:flex;flex-direction:column;gap:12px;margin-bottom:12px">
                        <div style="width:100%;box-sizing:border-box">
                            <label class="label"><?= htmlspecialchars(__('adm_exp_search_label')) ?></label>
                            <input class="input" name="exq" value="<?= htmlspecialchars($explorerQuery) ?>" placeholder="<?= htmlspecialchars(__('adm_exp_search_ph')) ?>" style="width:100%;box-sizing:border-box">
                        </div>
                        <div class="row" style="gap:8px;align-items:end">
                        <div>
                            <label class="label"><?= htmlspecialchars(__('adm_exp_type_label')) ?></label>
                            <select class="input" name="extype">
                                <option value="all" <?= $explorerTypeFilter === 'all' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_all')) ?></option>
                                <option value="user" <?= $explorerTypeFilter === 'user' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_user')) ?></option>
                                <option value="inetorgperson" <?= $explorerTypeFilter === 'inetorgperson' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_person')) ?></option>
                                <option value="computer" <?= $explorerTypeFilter === 'computer' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_computer')) ?></option>
                                <option value="group" <?= $explorerTypeFilter === 'group' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_group')) ?></option>
                                <option value="ou" <?= $explorerTypeFilter === 'ou' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_ou')) ?></option>
                                <option value="container" <?= $explorerTypeFilter === 'container' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_container')) ?></option>
                                <option value="domain" <?= $explorerTypeFilter === 'domain' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_exp_type_domain')) ?></option>
                            </select>
                        </div>
                        <div>
                            <label class="label"><?= htmlspecialchars(__('adm_exp_sort_label')) ?></label>
                            <select class="input" name="tree_sort">
                                <option value="name" <?= $explorerTreeSortBy === 'name' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_sort_name')) ?></option>
                                <option value="type" <?= $explorerTreeSortBy === 'type' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_sort_type')) ?></option>
                                <option value="dn" <?= $explorerTreeSortBy === 'dn' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_sort_dn')) ?></option>
                            </select>
                        </div>
                        <div>
                            <label class="label"><?= htmlspecialchars(__('adm_exp_order_label')) ?></label>
                            <select class="input" name="tree_dir">
                                <option value="asc" <?= $explorerTreeSortDir === 'asc' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_order_asc')) ?></option>
                                <option value="desc" <?= $explorerTreeSortDir === 'desc' ? 'selected' : '' ?>><?= htmlspecialchars(__('adm_order_desc')) ?></option>
                            </select>
                        </div>
                        <div>
                            <button class="btn" type="submit" onclick="history.replaceState(null,'','#tab-explorer')"><?= htmlspecialchars(__('adm_exp_search_btn')) ?></button>
                        </div>
                        </div>
                    </form>
                    <div class="ad-explorer">
                        <div class="card ad-tree-card">
                            <h3 style="margin-top:0"><?= htmlspecialchars(__('adm_tree_title')) ?></h3>
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
                                            'name' => __('adm_tree_root_label'),
                                            'dn' => $baseDnNode,
                                            'type' => 'domain',
                                            'hasChildren' => true,
                                            'children' => $nodes,
                                            'description' => __('adm_tree_root_desc'),
                                            'objectClasses' => ['domainDNS'],
                                        ]];
                                        render_ad_tree_nodes($root);
                                    } else {
                                    render_ad_tree_nodes($nodes);
                                    }
                                } else {
                                    if ($explorerQuery !== '' || $explorerTypeFilter !== 'all') {
                                        echo '<div class="small">' . htmlspecialchars(__('adm_tree_no_match')) . '</div>';
                                } else {
                                    echo '<div class="small">' . htmlspecialchars(__('adm_tree_unavailable')) . '</div>';
                                    }
                                }
                                ?>
                            </div>
                        </div>
                        <div class="card ad-details-card">
                            <h3 style="margin-top:0"><?= htmlspecialchars(__('adm_details_title')) ?></h3>
                            <div id="ad-details" class="small">
                                <?= htmlspecialchars(__('adm_details_pick')) ?>
                            </div>
                            <div id="ad-actions" class="ad-actions">
                                <div class="small"><?= htmlspecialchars(__('adm_actions_pick')) ?></div>
                            </div>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="card">
                        <div class="small"><?= htmlspecialchars(__('adm_domain_admins_only')) ?></div>
                    </div>
                <?php endif; ?>
            </div>
            <div id="explorer-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="explorer-modal-title" onclick="if(event.target===this) closeExplorerModal()">
                <div class="modal-card" role="document" onclick="event.stopPropagation()">
                    <div class="modal-head">
                        <h3 id="explorer-modal-title"><?= htmlspecialchars(__('adm_modal_action')) ?></h3>
                        <button type="button" class="btn sm" id="explorer-modal-close" onclick="closeExplorerModal()"><?= htmlspecialchars(__('adm_modal_close')) ?></button>
                    </div>
                    <div id="explorer-modal-body"></div>
                </div>
            </div>

            <!-- Admin: domain -->
            <div id="tab-admin-domain" class="tab" style="display:none">
                <?php if ($canDomainAdmin): ?>
                    <p class="page-subtitle" style="margin-bottom:20px"><?= htmlspecialchars(__('adm_domain_intro')) ?></p>

                    <div class="grid grid-2" style="margin-top:0">
                        <div class="card" data-focus="groups_global">
                            <h3><?= htmlspecialchars(__('adm_groups_search_title')) ?></h3>

                            <form method="post" class="row" style="gap:8px">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="search_groups_global">
                                <input type="hidden" name="gpG" value="<?= htmlspecialchars((string) ($_GET['gpG'] ?? 1)) ?>">
                                <input type="hidden" name="gpsG"
                                    value="<?= htmlspecialchars((string) ($_GET['gpsG'] ?? 50)) ?>">
                                <input class="input" name="group_query"
                                    placeholder="<?= htmlspecialchars(__('adm_groups_search_ph')) ?>"
                                    value="<?= htmlspecialchars($groupQueryGlobal ?: ($_GET['gqG'] ?? '')) ?>">
                                <button class="btn sm" type="submit"><?= htmlspecialchars(__('adm_search')) ?></button>
                            </form>

                            <?php if ($groupQueryGlobal !== '' || isset($_GET['gqG'])): ?>
                                <div class="small" style="margin-top:8px">
                                    <?= htmlspecialchars(__('adm_groups_results_for')) ?>
                                    <code><?= htmlspecialchars($groupQueryGlobal ?: ($_GET['gqG'] ?? '')) ?></code>
                                    — <?= htmlspecialchars(sprintf(__('adm_groups_page_info'), (int) ($_GET['gpG'] ?? 1), (int) ($_GET['gpsG'] ?? 50))) ?>
                                </div>
                                <?php if (!empty($groupResultsGlobal)): ?>
                                    <table class="table" style="margin-top:8px">
                                        <tr>
                                            <th><?= htmlspecialchars(__('adm_th_cn')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_sam')) ?></th>
                                            <th><?= htmlspecialchars(__('adm_th_dn')) ?></th>
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
                                    <div class="small" style="margin-top:8px"><?= htmlspecialchars(__('adm_groups_none')) ?></div>
                                <?php endif; ?>
                            <?php endif; ?>

                            <div class="hr"></div>

                            <h4><?= htmlspecialchars(__('adm_create_group_h')) ?></h4>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="create_group">
                                <label class="label"><?= htmlspecialchars(__('adm_ou_create_under')) ?></label>
                                <?php if (!empty($ouOptions)): ?>
                                    <select class="input" name="group_ouDn" required>
                                        <option value=""><?= htmlspecialchars(__('adm_bulk_choose_ou')) ?></option>
                                        <?php foreach ($ouOptions as $opt): ?>
                                            <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                <?= htmlspecialchars($opt['label']) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                <?php else: ?>
                                    <input class="input" name="group_ouDn" placeholder="<?= htmlspecialchars(__('adm_ph_ou_dn')) ?>" required>
                                <?php endif; ?>
                                <label class="label"><?= htmlspecialchars(__('adm_group_cn')) ?></label>
                                <input class="input" name="group_cn" placeholder="<?= htmlspecialchars(__('adm_group_cn_ph')) ?>" required>
                                <label class="label"><?= htmlspecialchars(__('adm_group_sam_opt')) ?></label>
                                <input class="input" name="group_sam" placeholder="<?= htmlspecialchars(__('adm_group_sam_ph')) ?>">
                                <div style="margin-top:10px"><button class="btn" type="submit"><?= htmlspecialchars(__('adm_create_group_btn')) ?></button>
                                </div>
                            </form>

                            <div class="hr"></div>

                            <h4><?= htmlspecialchars(__('adm_delete_group_h')) ?></h4>
                            <form method="post" onsubmit="return confirm(<?= json_encode(__('adm_delete_group_confirm'), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>)">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="delete_group">
                                <label class="label"><?= htmlspecialchars(__('adm_group_del_id')) ?></label>
                                <input class="input" name="group_del_id" placeholder="<?= htmlspecialchars(__('adm_group_del_ph')) ?>"
                                    required>
                                <div style="margin-top:10px"><button class="btn" type="submit"><?= htmlspecialchars(__('adm_delete_group_btn')) ?></button>
                                </div>
                            </form>
                        </div>

                        <div class="card" data-focus="ou_manage" style="grid-column:1/-1">
                            <h3><?= htmlspecialchars(__('adm_ou_manage_h')) ?></h3>

                            <?php
                            // DN -> meta for instant form fill
                            $ouByDn = [];
                            foreach ($ouOptions as $opt)
                                $ouByDn[strtoupper($opt['dn'])] = $opt;
                            $selOuDn = trim((string) ($_GET['ouSel'] ?? ''));
                            $selMeta = $selOuDn ? ($ouByDn[strtoupper($selOuDn)] ?? null) : null;
                            ?>

                            <form method="get" class="row" style="gap:8px; align-items:end">
                                <input type="hidden" name="af" value="ou_manage">
                                <div style="flex:1">
                                    <label class="label"><?= htmlspecialchars(__('adm_select_ou')) ?></label>
                                    <select class="input" name="ouSel" onchange="this.form.submit()">
                                        <option value=""><?= htmlspecialchars(__('adm_choose_dash')) ?></option>
                                        <?php foreach ($ouOptions as $opt):
                                            if (($opt['kind'] ?? '') !== 'ou')
                                                continue;
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
                                    <span class="badge"><?= htmlspecialchars(__('adm_dn_selected')) ?>
                                        <code><?= htmlspecialchars($selOuDn) ?></code></span>
                                <?php endif; ?>
                            </form>

                            <?php if (!$selMeta): ?>
                                <div class="small" style="margin-top:8px"><?= htmlspecialchars(__('adm_choose_ou_actions')) ?>
                                </div>
                            <?php else: ?>
                                <div class="hr"></div>

                                <div class="small" style="opacity:.9">
                                    <div><strong><?= htmlspecialchars(__('adm_ou_label')) ?></strong> <?= htmlspecialchars($selMeta['label'] ?? '') ?></div>
                                    <div style="margin-top:4px"><strong><?= htmlspecialchars(__('adm_desc_current')) ?></strong>
                                        <?= ($selMeta['desc'] ?? '') !== '' ? nl2br(htmlspecialchars($selMeta['desc'])) : htmlspecialchars(__('adm_dash')) ?>
                                    </div>
                                </div>

                                <div class="grid grid-2" style="margin-top:10px">
                                    <div class="card">
                                        <h4><?= htmlspecialchars(__('adm_modify_ou_h')) ?></h4>
                                        <form method="post">
                                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                            <input type="hidden" name="admin_action" value="update_ou">
                                            <input type="hidden" name="ou_dn" value="<?= htmlspecialchars($selOuDn) ?>">

                                            <label class="label"><?= htmlspecialchars(__('adm_new_name_opt')) ?></label>
                                            <input class="input" name="ou_new_name" placeholder="<?= htmlspecialchars(__('adm_new_name_ph')) ?>">

                                            <label class="label"><?= htmlspecialchars(__('adm_new_parent_opt')) ?></label>
                                            <select class="input" name="ou_new_parent">
                                                <option value=""><?= htmlspecialchars(__('adm_do_not_move')) ?></option>
                                                <?php foreach ($ouOptions as $opt):
                                                    if (!in_array($opt['kind'] ?? '', ['ou', 'container', 'domain'], true))
                                                        continue;
                                                    if (strcasecmp($opt['dn'], $selOuDn) === 0)
                                                        continue;
                                                    ?>
                                                    <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                        <?= htmlspecialchars($opt['label']) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>

                                            <label class="label"><?= htmlspecialchars(__('adm_desc_field')) ?></label>
                                            <input class="input" name="ou_desc_mod"
                                                value="<?= htmlspecialchars($selMeta['desc'] ?? '') ?>"
                                                placeholder="<?= htmlspecialchars(__('adm_desc_leave_empty')) ?>">
                                            <div class="row" style="margin-top:6px">
                                                <input type="checkbox" id="ou_desc_clear" name="ou_desc_clear" value="1">
                                                <label for="ou_desc_clear" class="label" style="margin:0"><?= htmlspecialchars(__('adm_clear_desc')) ?></label>
                                            </div>

                                            <label class="label"><?= htmlspecialchars(__('adm_ou_protection')) ?></label>
                                            <select class="input" name="ou_protected_mod">
                                                <option value=""><?= htmlspecialchars(__('adm_ou_prot_nochange')) ?></option>
                                                <option value="1"><?= htmlspecialchars(__('adm_ou_prot_on')) ?></option>
                                                <option value="0"><?= htmlspecialchars(__('adm_ou_prot_off')) ?></option>
                                            </select>

                                            <div style="margin-top:10px"><button class="btn" type="submit"><?= htmlspecialchars(__('adm_save')) ?></button>
                                            </div>
                                        </form>
                                    </div>

                                    <div class="card">
                                        <h4><?= htmlspecialchars(__('adm_delete_ou_h')) ?></h4>
                                        <form method="post" onsubmit="return confirm(<?= json_encode(__('adm_delete_ou_confirm'), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>)">
                                            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                            <input type="hidden" name="admin_action" value="delete_ou">
                                            <input type="hidden" name="ou_del_dn" value="<?= htmlspecialchars($selOuDn) ?>">
                                            <div class="small">DN: <code><?= htmlspecialchars($selOuDn) ?></code></div>
                                            <div class="row" style="margin-top:6px">
                                                <label class="label" style="margin:0"><?= htmlspecialchars(__('adm_force_recursive')) ?></label>
                                                <input type="checkbox" name="ou_del_force" value="1">
                                            </div>
                                            <div style="margin-top:10px"><button class="btn" type="submit"><?= htmlspecialchars(__('adm_delete_ou_btn')) ?></button></div>
                                        </form>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <div class="hr"></div>

                            <h4><?= htmlspecialchars(__('adm_create_ou_h')) ?></h4>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                                <input type="hidden" name="admin_action" value="create_ou">
                                <label class="label"><?= htmlspecialchars(__('adm_parent')) ?></label>
                                <?php if (!empty($ouOptions)): ?>
                                    <select class="input" name="ou_parent_dn" required>
                                        <option value=""><?= htmlspecialchars(__('adm_choose_dash')) ?></option>
                                        <?php foreach ($ouOptions as $opt):
                                            if (!in_array($opt['kind'] ?? '', ['ou', 'container', 'domain'], true))
                                                continue; ?>
                                            <option value="<?= htmlspecialchars($opt['dn']) ?>">
                                                <?= htmlspecialchars($opt['label']) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                <?php else: ?>
                                    <input class="input" name="ou_parent_dn" placeholder="<?= htmlspecialchars(__('adm_ph_ou_dn')) ?>" required>
                                <?php endif; ?>
                                <label class="label"><?= htmlspecialchars(__('adm_ou_name')) ?></label>
                                <input class="input" name="ou_name" placeholder="<?= htmlspecialchars(__('adm_ou_name_ph')) ?>" required>
                                <label class="label"><?= htmlspecialchars(__('adm_ou_desc_opt')) ?></label>
                                <input class="input" name="ou_desc" placeholder="<?= htmlspecialchars(__('adm_ou_desc_ph')) ?>">
                                <div class="row" style="margin-top:6px">
                                    <label class="label" style="margin:0"><?= htmlspecialchars(__('adm_protect_ou_cb')) ?></label>
                                    <input type="checkbox" name="ou_protected" value="1">
                                </div>
                                <div style="margin-top:10px"><button class="btn" type="submit"><?= htmlspecialchars(__('adm_create_ou_btn')) ?></button></div>
                            </form>
                        </div>

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