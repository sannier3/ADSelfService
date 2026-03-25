# WEB-CLIENT-PHP

PHP intranet client for `ADSelfService`.

This component provides the web interface for:

- user authentication
- profile view and update
- password change
- forgot-password flow
- AD administration by role
- AD explorer
- permission-filtered tool access

## Main files

- `intranet.php`: main user/admin portal.
- `forgot_password.php`: account recovery/reset flow.
- `intranet-i18n.php`: i18n bootstrap and UI language handling.
- `intranet-i18n-messages.php`: FR/EN message catalog.
- `config-intranet-default.php`: configuration template.
- `config-intranet.php`: local runtime config to create, do not commit.
- `.htaccess` / `web.config`: Apache / IIS web-server integration.

## Configuration

1. Copy `config-intranet-default.php` to `config-intranet.php`.
2. Set `__IS_DEFAULT` to `false`.
3. Fill in at least:
   - `API_BASE`
   - `INTERNAL_SHARED_SECRET`
   - backend-aligned API settings
   - session / captcha / mail options for your environment
4. Make sure `config-intranet.php` is not committed.

## Web server dependencies

- PHP with `curl`, `json`, `mbstring`, `pdo`
- `pdo_sqlite` if you use SQLite for the tools module
- `DOMDocument` recommended: rich HTML tool instructions are sanitized server-side with this extension

## Built-in security

- CSRF protection on sensitive forms
- PHP session cookie configured with `HttpOnly`, `SameSite=Lax`, `Secure` when HTTPS is used
- application sync cookie `Intra-Sync-Key` bound to the PHP session
- optional key rotation on `GET` through `INTRA_SYNC_KEY_ROTATE_MINUTES`
- short grace window to avoid desync during concurrent requests
- sliding refresh of both session and sync cookies on valid authenticated requests
- strict HTML sanitization for tool instructions

## Deployment

### IIS

- use `web.config`
- point the site to the `WEB-CLIENT-PHP` folder
- verify write permissions if SQLite / local logs are used

### Apache

- use `.htaccess`
- verify required modules depending on your hosting setup

## Operational notes

- `config-intranet.php`, `intranet.sqlite`, `rl_logs/`, and local logs must not be committed
- the PHP client expects a reachable API at `API_BASE`
- `INTERNAL_SHARED_SECRET` must match the API value when the internal auth header is enabled
- i18n and browser session behavior are configured in PHP, not in the API

## Useful links

- [Root README](../README.en.md)
- [API configuration](../CONFIG-OPTIONS.en.md)
- [API LDAP configuration](../ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [API endpoints reference](../ADSelfService-API.Server/ENDPOINTS.en.md)
