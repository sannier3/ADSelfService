<?php
declare(strict_types=1);

/**
 * Intranet UI i18n: French and English.
 * Language preference is stored only in $_SESSION['intranet_lang'] (no dedicated language cookie).
 * The PHP session cookie (PHPSESSID) is enough for anonymous users (e.g. login page): session_start()
 * runs before bootstrap, so the chosen locale survives across requests until the session expires.
 * User preference is applied via POST (CSRF-protected), not ?lang= GET.
 * If USER_LANGUAGE_SWITCH_ENABLED is false: UI always uses DEFAULT_LANGUAGE; session value is ignored and cleared.
 */

/** Locales with a full catalog in intranet-i18n-messages.php (extend when adding a language). */
function intranet_i18n_known_locales(): array
{
    return ['fr', 'en'];
}

/**
 * Locales exposed in the UI. Controlled by config UI_LOCALES, or all known locales by default.
 * A single locale hides the switcher (no choice to make).
 */
function intranet_i18n_allowed_locales(): array
{
    global $CONFIG;
    $known = intranet_i18n_known_locales();
    $raw = $CONFIG['UI_LOCALES'] ?? null;
    if (!is_array($raw) || $raw === []) {
        return $known;
    }
    $out = [];
    foreach ($raw as $loc) {
        $loc = strtolower(trim((string) $loc));
        if (in_array($loc, $known, true)) {
            $out[] = $loc;
        }
    }
    $out = array_values(array_unique($out));
    if ($out === []) {
        return $known;
    }
    return $out;
}

/** Native language name for a locale (uses current UI language for translation). */
function intranet_i18n_locale_native_label(string $locale): string
{
    if (!in_array($locale, intranet_i18n_known_locales(), true)) {
        return $locale;
    }
    return __('lang_' . $locale . '_native');
}

/**
 * ISO 3166-1 alpha-2 country code for flagcdn.com (may differ from UI locale code, e.g. en → gb).
 */
function intranet_i18n_flag_country_code(string $locale): string
{
    if ($locale === 'fr') {
        return 'fr';
    }
    if ($locale === 'en') {
        return 'gb';
    }
    return 'fr';
}

/** PNG URL from https://flagcdn.com (size e.g. 20×15 as in /20x15/fr.png). */
function intranet_i18n_flag_image_url(string $locale, int $width = 20, int $height = 15): string
{
    $c = preg_replace('/[^a-z]/', '', strtolower(intranet_i18n_flag_country_code($locale)));
    return 'https://flagcdn.com/' . $width . 'x' . $height . '/' . $c . '.png';
}

/**
 * Remove legacy intranet_lang cookie from browsers that still have it (migration).
 */
function intranet_i18n_clear_legacy_lang_cookie(): void
{
    if (empty($_COOKIE['intranet_lang'])) {
        return;
    }
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    setcookie('intranet_lang', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => $secure,
        'httponly' => false,
        'samesite' => 'Lax',
    ]);
}

/**
 * Current request path + query without a "lang" parameter (for PRG after POST language change).
 */
function intranet_i18n_redirect_uri_without_lang(): string
{
    $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
    $parts = parse_url($uri);
    $path = $parts['path'] ?? '/';
    $query = [];
    if (!empty($parts['query'])) {
        parse_str($parts['query'], $query);
    }
    unset($query['lang']);
    $qs = http_build_query($query);
    return $path . ($qs !== '' ? '?' . $qs : '');
}

function intranet_i18n_catalog(): array
{
    static $c = null;
    if ($c === null) {
        $c = require __DIR__ . '/intranet-i18n-messages.php';
    }
    return $c;
}

function intranet_i18n_bootstrap(): void
{
    global $INTRANET_LANG, $CONFIG, $INTRANET_LANG_SWITCH_ENABLED, $INTRANET_LANG_SWITCH_UI;
    intranet_i18n_clear_legacy_lang_cookie();

    $allowed = intranet_i18n_allowed_locales();
    $cfgLang = strtolower(trim((string) ($CONFIG['DEFAULT_LANGUAGE'] ?? 'en')));
    if (!in_array($cfgLang, $allowed, true)) {
        $cfgLang = $allowed[0];
    }
    $switchEnabled = (bool) ($CONFIG['USER_LANGUAGE_SWITCH_ENABLED'] ?? true);
    $INTRANET_LANG_SWITCH_ENABLED = $switchEnabled;
    $INTRANET_LANG_SWITCH_UI = false;

    if (!$switchEnabled) {
        unset($_SESSION['intranet_lang']);
        $INTRANET_LANG = $cfgLang;
        return;
    }

    if (count($allowed) === 1) {
        $INTRANET_LANG = $cfgLang;
        $_SESSION['intranet_lang'] = $cfgLang;
        return;
    }

    $INTRANET_LANG_SWITCH_UI = true;

    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
        && isset($_POST['intranet_set_lang'])
        && (string) $_POST['intranet_set_lang'] === '1'
        && function_exists('csrf_ok')
        && csrf_ok($_POST['csrf'] ?? null)
    ) {
        $newLang = strtolower(trim((string) ($_POST['intranet_lang'] ?? '')));
        if (in_array($newLang, $allowed, true)) {
            $_SESSION['intranet_lang'] = $newLang;
            if (!headers_sent()) {
                header('Location: ' . intranet_i18n_redirect_uri_without_lang(), true, 303);
                exit;
            }
        }
    }

    $stored = $_SESSION['intranet_lang'] ?? '';
    $lang = in_array($stored, $allowed, true) ? $stored : $cfgLang;
    $INTRANET_LANG = $lang;
    $_SESSION['intranet_lang'] = $lang;
}

function __(string $key, string|int|float ...$args): string
{
    global $INTRANET_LANG;
    $cat = intranet_i18n_catalog();
    $lang = (($INTRANET_LANG ?? 'fr') === 'en') ? 'en' : 'fr';
    $msg = $cat[$lang][$key] ?? $cat['fr'][$key] ?? $key;
    if ($args === []) {
        return $msg;
    }
    return vsprintf($msg, $args);
}

/**
 * Same-page URL without a lang= query parameter (legacy helper). Language is not toggled via GET.
 *
 * @param string $lang Unused; kept for backward compatibility
 */
function intranet_i18n_href(string $lang): string
{
    return htmlspecialchars(intranet_i18n_redirect_uri_without_lang(), ENT_QUOTES, 'UTF-8');
}

/** JSON-ready strings for inline JavaScript (explorer modals, etc.). */
function intranet_i18n_js_export(): array
{
    $keys = [
        'js_type_user', 'js_type_group', 'js_type_computer', 'js_type_person', 'js_type_container', 'js_type_object',
        'js_label_type', 'js_label_name', 'js_label_dn', 'js_label_classes', 'js_label_description',
        'js_label_email', 'js_label_phone', 'js_label_address', 'js_label_site', 'js_label_state',
        'js_disabled', 'js_loading_details', 'js_details_unavailable', 'js_ou_protection', 'js_ou_protected', 'js_ou_unprotected',
        'js_primary_group', 'js_member_of_all', 'js_groups_count', 'js_dns_name', 'js_ip', 'js_os', 'js_os_version',
        'js_last_machine_bind', 'js_created_at', 'js_last_user', 'js_not_available_ad', 'js_managed_by',
        'js_group_delete_blocked', 'js_group_delete_blocked_default', 'js_member_of_parents',
        'js_btn_create_user', 'js_btn_create_ou', 'js_btn_create_group', 'js_btn_edit_ou', 'js_btn_delete_ou',
        'js_btn_edit_user', 'js_btn_user_groups', 'js_btn_enable', 'js_btn_disable', 'js_btn_unlock', 'js_btn_reset_pw',
        'js_btn_rename_cn', 'js_btn_move', 'js_btn_clone', 'js_btn_delete_user', 'js_btn_move_computer', 'js_btn_delete_computer',
        'js_btn_group_members', 'js_btn_delete_group', 'js_no_actions', 'js_alert_user_action_on_computer',
        'js_alert_computer_action_not_computer', 'js_alert_group_delete_blocked', 'js_alert_load_user_details',
        'js_alert_network_user_details', 'js_modal_action_prefix', 'js_object_label', 'js_label_ou_name', 'js_label_never',
        'js_label_force_change_first', 'js_label_target_ou', 'js_choose', 'js_label_cn', 'js_label_new_cn', 'js_label_group_cn', 'js_label_sam_account_name', 'js_sam_optional',
        'js_label_new_password', 'js_force_change_next_logon', 'js_ou_delete_note', 'js_label_initial_password', 'js_account_expiry',
        'js_move_computer_note', 'js_delete_computer_note', 'js_delete_group_note', 'js_apply_group_membership',
        'js_clone_search_group', 'js_search', 'js_manage_user_groups_help', 'js_manage_group_members_help',
        'js_confirm_ad_action', 'js_cancel', 'js_execute', 'js_no_groups_selected', 'js_remove', 'js_add', 'js_no_groups_found',
        'js_group_search_unavailable', 'js_primary_not_removable', 'js_no_members_selected', 'js_no_users_found',
        'js_user_search_unavailable', 'js_ridge_placeholder_group', 'js_ridge_placeholder_user',
        'js_ou_new_parent_unchanged', 'js_ou_protection_no_change', 'js_ou_protection_on', 'js_ou_protection_off',
        'js_pg_do_not_change', 'js_pg_current_suffix', 'js_pg_help', 'js_pg_summary', 'js_never_expire',
        'js_delete_user_warning', 'js_website', 'js_user_sam', 'js_modal_title_tpl',
        'js_first_name', 'js_last_name', 'js_upn', 'js_protect', 'js_new_parent_optional', 'js_ou_protection_field',
    ];
    $out = [];
    foreach ($keys as $k) {
        $out[$k] = __($k);
    }
    return $out;
}

function login_rl_msg_hard(): string
{
    return __('msg_login_rl_hard');
}

function login_rl_msg_warn(): string
{
    return __('msg_login_rl_warn');
}
