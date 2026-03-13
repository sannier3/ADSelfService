# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is an open-source intranet solution for Active Directory.
It provides a simple user journey, centralized IT administration, and a strict security baseline on both API and web client sides.

## Overview

The project includes two main components:

- `ADSelfService-API.Server`: .NET 8 API for Active Directory authentication and administration.
- `WEB-CLIENT-PHP`: PHP intranet client for user and admin workflows.

## Core features

- AD authentication (`POST /auth`).
- User profile view and update.
- User password change.
- Dedicated forgot-password reset flow.
- AD account administration: create, update, delete, enable, disable, unlock, rename, move, set expiration.
- Group and membership administration.
- OU administration (create, update, delete).
- AD explorer and object search.
- Tool access filtered by user permissions.

## Mandatory security baseline

Current code behavior enforces:

- Request filtering through `Security.AllowedIps`.
- Required and strong internal shared key: `Security.InternalSharedSecret`.
- Required application context header on sensitive routes: `X-App-Context`.
- Protected LDAP transport is mandatory:
  - `Ldap.Ssl=true` (LDAPS), or
  - `Ldap.UseKerberosSealing=true` (LDAP + Kerberos sealing).
- `Debug.ShowPasswords=true` is forbidden.

If these constraints are not met, the API may refuse startup or reject requests.

## Role separation

- **Standard user**: profile, password, allowed tools.
- **User admin**: account and membership operations.
- **Domain admin**: advanced actions (OU, groups, AD explorer).

The PHP client filters UI actions by role, and the API also enforces authorization server-side.

## Quick installation

### Option 1 — From release (recommended)

1. Download archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run `ADSelfService-API.Server.exe` once to generate `config.json`.
4. Complete `config.json` (LDAP, security, server binding).
5. Restart and verify `GET /health`.
6. Deploy `ADSelfService-WEBSERVER-Files.zip` on the web host.
7. Create `WEB-CLIENT-PHP/config-intranet.php` from `config-intranet-default.php`.
8. Verify consistency between `API_BASE` and `INTERNAL_SHARED_SECRET`.

### Option 2 — Build from source

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Production recommendations

- Do not expose the API directly to the public Internet.
- Keep `AllowedIps` as strict as possible.
- Use a long, unique, non-reused shared secret.
- Prefer LDAPS in production.
- Enable debug only for short, controlled troubleshooting.
- Never commit sensitive runtime configuration files.

## Post-deployment checks

1. `GET /health` returns `200`.
2. User login works.
3. Password change works.
4. Forgot-password flow works.
5. Tools are correctly permission-filtered.
6. Admin actions are visible and effective for the right role.
7. AD search behavior matches `BaseDn`, `GroupBaseDn`, and `RootDn`.

## Quick troubleshooting

| Issue | First check |
|---|---|
| `403` on API calls | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API fails at startup | invalid/incomplete `config.json`, unmet security requirement |
| LDAP bind failure | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, DNS/network |
| Password change rejected | verify LDAPS or Kerberos sealing |
| PHP client blocked at startup | `config-intranet.php`, `API_BASE`, shared secret |

## Key endpoints

- `GET /health`: API health + LDAP bind.
- `POST /auth`: AD authentication.
- `POST /user/changePassword`: user password change.
- `POST /user/updateProfile`: user profile update.
- `GET /tree`: AD tree.
- `GET /users`, `GET /groups`: base views.
- `POST /admin/*` and `GET/POST /explorer/*`: advanced administration by role and context.

## Related documentation

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)
