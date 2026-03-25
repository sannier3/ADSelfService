# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is an open-source intranet solution for Active Directory.
This repository combines a .NET 8 API and a PHP web client designed to work together, with clear separation between AD logic, access security, and intranet UI.

## Overview

The two main components are:

- `ADSelfService-API.Server`: .NET 8 API for authentication, LDAP/AD operations, and server-side security enforcement.
- `WEB-CLIENT-PHP`: PHP intranet portal for user workflows, admin operations, i18n, and web-facing flows.

## Useful repository layout

```text
ADSelfService-API/
|- ADSelfService-API.Server/   .NET 8 API
|- WEB-CLIENT-PHP/            PHP intranet client
|- CONFIG-OPTIONS.md          API config reference (FR)
|- CONFIG-OPTIONS.en.md       API config reference (EN)
|- README.md                  FR overview
`- README.en.md               EN overview
```

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

- request filtering through `Security.AllowedIps`
- required and strong internal shared key: `Security.InternalSharedSecret`
- required application context header on sensitive routes: `X-App-Context`
- protected LDAP transport is mandatory:
  - `Ldap.Ssl=true` (LDAPS), or
  - `Ldap.UseKerberosSealing=true` (LDAP + Kerberos sealing)
- `Debug.ShowPasswords=true` is forbidden

If these constraints are not met, the API may refuse startup or reject requests.

## Role separation

- **Standard user**: profile, password, allowed tools.
- **User admin**: account and membership operations.
- **Domain admin**: advanced actions (OU, groups, AD explorer).

The PHP client filters UI actions by role, and the API also enforces authorization server-side.

## Quick start

### Option 1 — From release

1. Download archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run `ADSelfService-API.Server.exe` once to generate `config.json`.
4. Complete `config.json` (LDAP, security, server binding).
5. Restart and verify `GET /health`.
6. Deploy `ADSelfService-WEBSERVER-Files.zip` on the web host.
7. Create `WEB-CLIENT-PHP/config-intranet.php` from `config-intranet-default.php`.
8. Verify consistency between `API_BASE` and `INTERNAL_SHARED_SECRET`.

### Option 2 — From source

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Documentation by component

### .NET API

- [ADSelfService-API.Server/README.en.md](ADSelfService-API.Server/README.en.md)
- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)

### PHP client

- [WEB-CLIENT-PHP/README.en.md](WEB-CLIENT-PHP/README.en.md)
- `WEB-CLIENT-PHP/config-intranet-default.php`
- `WEB-CLIENT-PHP/intranet-i18n.php`
- `WEB-CLIENT-PHP/forgot_password.php`

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
