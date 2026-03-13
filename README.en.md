# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is an open-source intranet solution for Active Directory, designed to provide:

- a simple and secure experience for end users,
- centralized administration for IT teams,
- a strict security baseline on both API and web client sides.

## Overview

The project contains two main components:

- `ADSelfService-API.Server`: .NET 8 API for AD authentication and administration.
- `WEB-CLIENT-PHP`: PHP intranet client for user and admin workflows.

## Core features

- AD authentication (`POST /auth`).
- User profile view and update.
- User password change.
- Dedicated forgot-password reset flow.
- AD user administration:
  - create, update, delete,
  - enable, disable, unlock,
  - rename, move, set expiration.
- Group and membership administration.
- OU administration (create, update, delete).
- AD explorer and object search.
- Tool access filtered by user permissions.

## Security highlights

Current code behavior enforces a clear baseline:

- network filtering through `Security.AllowedIps`,
- required and strong internal shared key (`InternalSharedSecret`),
- app-context enforcement (`X-App-Context`) on sensitive routes,
- protected LDAP transport required:
  - LDAPS (`Ldap.Ssl=true`), or
  - LDAP + Kerberos sealing (`Ldap.UseKerberosSealing=true`),
- `Debug.ShowPasswords=true` is forbidden.

## Role separation

- **Standard user**: profile, password, allowed tools.
- **User admin**: account and membership operations.
- **Domain admin**: advanced actions (OU, groups, explorer scope).

The PHP client filters UI actions, and the API enforces checks server-side as well.

## Quick installation

### Option 1 - From release (recommended)

1. Download archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run `ADSelfService-API.Server.exe` once to generate `config.json`.
4. Complete `config.json` (LDAP, security, server URLs).
5. Restart and check `GET /health`.
6. Deploy `ADSelfService-WEBSERVER-Files.zip` on the web host.
7. Create `WEB-CLIENT-PHP/config-intranet.php` from `config-intranet-default.php`.
8. Verify `API_BASE` + `INTERNAL_SHARED_SECRET` consistency.

### Option 2 - From source

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Practical recommendations

- Do not expose the API directly to the public Internet.
- Keep `AllowedIps` limited to required internal hosts.
- Use a long and unique `InternalSharedSecret`.
- Prefer LDAPS in production.
- Enable debug logging only for controlled troubleshooting.
- Never commit sensitive runtime configuration files.

## Validation checklist

1. `GET /health` returns `200`.
2. User login works.
3. User password change works.
4. Forgot-password reset works.
5. Tools are correctly permission-filtered.
6. Admin actions are visible and effective for the right role.
7. AD search behavior matches `BaseDn`, `GroupBaseDn`, and `RootDn`.

## Quick troubleshooting

| Issue | First check |
|---|---|
| `403` on API calls | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API fails at startup | invalid/incomplete `config.json` |
| LDAP bind failure | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, DNS/network |
| Password change rejected | enable LDAPS or Kerberos sealing |
| PHP client startup blocked | `config-intranet.php`, `API_BASE`, shared secret |

## Related documentation

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is a complete intranet solution for Active Directory:

- a .NET 8 API for AD authentication and administration,
- a PHP web client for end users and administrators,
- a strict security model (IP perimeter, shared secret, app context).

The project is open source, fully editable, and designed for fast deployment without sacrificing control.

## Why ADSelfService

- **For end users:** access only what they need (profile, password, allowed tools).
- **For administrators:** centralized management of users, groups, OUs, and AD exploration.
- **For IT teams:** readable code, clear JSON endpoints, explicit configuration.

## Components

- `ADSelfService-API.Server`: HTTP API connected to Active Directory.
- `WEB-CLIENT-PHP`: PHP intranet client that consumes the API.

## Main capabilities

- AD user authentication (`/auth`).
- Profile read and update.
- User password change.
- Dedicated and protected forgot-password flow.
- AD account administration:
  - create, delete, enable, disable, unlock,
  - rename, move, set expiration.
- Group and membership administration.
- OU administration (create, update, delete).
- AD explorer with object search.
- Tool access filtered by user permissions.

## Security model (mandatory)

Current code behavior enforces a strict baseline:

- `Security.AllowedIps` limits caller origins.
- `Security.InternalSharedSecret` must be configured and strong.
- sensitive API calls require a valid `X-App-Context`.
- `/health` is context-exempt, but still IP-filtered.
- LDAP transport must be protected:
  - `Ldap.Ssl=true` (LDAPS),
  - or `Ldap.UseKerberosSealing=true`.
- `Debug.ShowPasswords=true` is rejected.

Practical impact: startup is blocked until security requirements are met.

## Role separation

- **Standard user:** profile, password, allowed tools.
- **User admin:** account and membership operations.
- **Domain admin:** advanced domain actions (OU, groups, explorer scope).

The PHP client gates UI actions by role, and the API enforces server-side checks as well.

## Quick start

### Option 1 - Install from release (recommended)

1. Download archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run `ADSelfService-API.Server.exe` once to generate `config.json`.
4. Complete `config.json` (LDAP, security, URLs).
5. Restart API and verify `GET /health`.
6. Deploy `ADSelfService-WEBSERVER-Files.zip` on your web host.
7. Create `WEB-CLIENT-PHP/config-intranet.php` from `config-intranet-default.php`.
8. Verify `API_BASE` + `INTERNAL_SHARED_SECRET` consistency.

### Option 2 - Build from source

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Production guidance

- Never expose the API directly to the public Internet.
- Keep `AllowedIps` minimal (internal servers only).
- Use a long, unique `InternalSharedSecret`.
- Prefer LDAPS (`636`) with a valid certificate.
- Enable debug logs only for controlled troubleshooting.
- Never commit sensitive runtime configuration files.

## Post-install verification

Recommended checklist:

1. `GET /health` returns `200`.
2. User login works.
3. User password change works.
4. Forgot-password flow works (without account enumeration leaks).
5. User tools are correctly filtered.
6. Admin actions are visible and functional for the expected role.
7. AD searches (users/groups/OUs) are consistent with `RootDn` and `BaseDn`.

## Quick troubleshooting

| Issue | First checks |
|---|---|
| `403` on most calls | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API does not start | invalid/incomplete `config.json`, missing weak secret, forbidden values |
| LDAP bind fails | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, network path |
| Password change fails | enable LDAPS or Kerberos sealing |
| PHP client startup fails | `config-intranet.php`, secret, `API_BASE` |

## Related documentation

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is a complete intranet solution for Active Directory:

- a .NET 8 API for AD authentication and administration,
- a PHP web client for end users and administrators,
- a strict security model (IP perimeter, shared secret, app context).

The project is open source, fully editable, and designed for fast deployment without sacrificing control.

## Why ADSelfService

- **For end users:** access only what they need (profile, password, allowed tools).
- **For administrators:** centralized management of users, groups, OUs, and AD exploration.
- **For IT teams:** readable code, clear JSON endpoints, explicit configuration.

## Components

- `ADSelfService-API.Server`: HTTP API connected to Active Directory.
- `WEB-CLIENT-PHP`: PHP intranet client that consumes the API.

## Main capabilities

- AD user authentication (`/auth`).
- Profile read and update.
- User password change.
- Dedicated and protected forgot-password flow.
- AD account administration:
  - create, delete, enable, disable, unlock,
  - rename, move, set expiration.
- Group and membership administration.
- OU administration (create, update, delete).
- AD explorer with object search.
- Tool access filtered by user permissions.

## Security model (mandatory)

Current code behavior enforces a strict baseline:

- `Security.AllowedIps` limits caller origins.
- `Security.InternalSharedSecret` must be configured and strong.
- sensitive API calls require a valid `X-App-Context`.
- `/health` is context-exempt, but still IP-filtered.
- LDAP transport must be protected:
  - `Ldap.Ssl=true` (LDAPS),
  - or `Ldap.UseKerberosSealing=true`.
- `Debug.ShowPasswords=true` is rejected.

Practical impact: startup is blocked until security requirements are met.

## Role separation

- **Standard user:** profile, password, allowed tools.
- **User admin:** account and membership operations.
- **Domain admin:** advanced domain actions (OU, groups, explorer scope).

The PHP client gates UI actions by role, and the API enforces server-side checks as well.

## Quick start

### Option 1 - Install from release (recommended)

1. Download archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run `ADSelfService-API.Server.exe` once to generate `config.json`.
4. Complete `config.json` (LDAP, security, URLs).
5. Restart API and verify `GET /health`.
6. Deploy `ADSelfService-WEBSERVER-Files.zip` on your web host.
7. Create `WEB-CLIENT-PHP/config-intranet.php` from `config-intranet-default.php`.
8. Verify `API_BASE` + `INTERNAL_SHARED_SECRET` consistency.

### Option 2 - Build from source

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Production guidance

- Never expose the API directly to the public Internet.
- Keep `AllowedIps` minimal (internal servers only).
- Use a long, unique `InternalSharedSecret`.
- Prefer LDAPS (`636`) with a valid certificate.
- Enable debug logs only for controlled troubleshooting.
- Never commit sensitive runtime configuration files.

## Post-install verification

Recommended checklist:

1. `GET /health` returns `200`.
2. User login works.
3. User password change works.
4. Forgot-password flow works (without account enumeration leaks).
5. User tools are correctly filtered.
6. Admin actions are visible and functional for the expected role.
7. AD searches (users/groups/OUs) are consistent with `RootDn` and `BaseDn`.

## Quick troubleshooting

| Issue | First checks |
|---|---|
| `403` on most calls | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API does not start | invalid/incomplete `config.json`, missing weak secret, forbidden values |
| LDAP bind fails | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, network path |
| Password change fails | enable LDAPS or Kerberos sealing |
| PHP client startup fails | `config-intranet.php`, secret, `API_BASE` |

## Related documentation

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is a complete intranet solution for Active Directory:

- a .NET 8 API for AD authentication and administration,
- a PHP web client for end users and administrators,
- a strict security model (IP perimeter, shared secret, app context).

The project is open source, fully editable, and designed for fast deployment without sacrificing control.

## Why ADSelfService

- **For end users:** access only what they need (profile, password, allowed tools).
- **For administrators:** centralized management of users, groups, OUs, and AD exploration.
- **For IT teams:** readable code, clear JSON endpoints, explicit configuration.

## Components

- `ADSelfService-API.Server`: HTTP API connected to Active Directory.
- `WEB-CLIENT-PHP`: PHP intranet client that consumes the API.

## Main capabilities

- AD user authentication (`/auth`).
- Profile read and update.
- User password change.
- Dedicated and protected forgot-password flow.
- AD account administration:
  - create, delete, enable, disable, unlock,
  - rename, move, set expiration.
- Group and membership administration.
- OU administration (create, update, delete).
- AD explorer with object search.
- Tool access filtered by user permissions.

## Security model (mandatory)

Current code behavior enforces a strict baseline:

- `Security.AllowedIps` limits caller origins.
- `Security.InternalSharedSecret` must be configured and strong.
- sensitive API calls require a valid `X-App-Context`.
- `/health` is context-exempt, but still IP-filtered.
- LDAP transport must be protected:
  - `Ldap.Ssl=true` (LDAPS),
  - or `Ldap.UseKerberosSealing=true`.
- `Debug.ShowPasswords=true` is rejected.

Practical impact: startup is blocked until security requirements are met.

## Role separation

- **Standard user:** profile, password, allowed tools.
- **User admin:** account and membership operations.
- **Domain admin:** advanced domain actions (OU, groups, explorer scope).

The PHP client gates UI actions by role, and the API enforces server-side checks as well.

## Quick start

### Option 1 - Install from release (recommended)

1. Download archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run `ADSelfService-API.Server.exe` once to generate `config.json`.
4. Complete `config.json` (LDAP, security, URLs).
5. Restart API and verify `GET /health`.
6. Deploy `ADSelfService-WEBSERVER-Files.zip` on your web host.
7. Create `WEB-CLIENT-PHP/config-intranet.php` from `config-intranet-default.php`.
8. Verify `API_BASE` + `INTERNAL_SHARED_SECRET` consistency.

### Option 2 - Build from source

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Production guidance

- Never expose the API directly to the public Internet.
- Keep `AllowedIps` minimal (internal servers only).
- Use a long, unique `InternalSharedSecret`.
- Prefer LDAPS (`636`) with a valid certificate.
- Enable debug logs only for controlled troubleshooting.
- Never commit sensitive runtime configuration files.

## Post-install verification

Recommended checklist:

1. `GET /health` returns `200`.
2. User login works.
3. User password change works.
4. Forgot-password flow works (without account enumeration leaks).
5. User tools are correctly filtered.
6. Admin actions are visible and functional for the expected role.
7. AD searches (users/groups/OUs) are consistent with `RootDn` and `BaseDn`.

## Quick troubleshooting

| Issue | First checks |
|---|---|
| `403` on most calls | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API does not start | invalid/incomplete `config.json`, missing weak secret, forbidden values |
| LDAP bind fails | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, network path |
| Password change fails | enable LDAPS or Kerberos sealing |
| PHP client startup fails | `config-intranet.php`, secret, `API_BASE` |

## Related documentation

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md)
[![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md)

![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` is a modern, customizable Active Directory self-service solution that gives end users a simple way to manage their AD identity while giving administrators a central place to handle accounts, groups, and OUs. It is designed for intranet environments, but flexible enough to be adapted to your organization, your web UI, and your internal workflows.

## Overview

The repository contains two main parts:

- `ADSelfService-API.Server`: the HTTP API that talks to Active Directory through LDAP, LDAPS, or LDAP + Kerberos.
- `WEB-CLIENT-PHP`: a PHP intranet client that consumes the API and provides a user interface.

Main features:

- Authenticate a domain user with `/auth`.
- Read and update user profile data and change the user's password.
- Access tools assigned by administrators through the web client, depending on the user's permissions.
- Change password even on first sign-in when the account requires it.
- Administer AD accounts: create, delete, enable, disable, unlock, rename, move, set expiration.
- Administer groups: browse, create, delete, add and remove members.
- Administer OUs: create, update, logically protect, and delete.
- Browse the directory tree through `/tree`.

In practice:

- a standard user can sign in, view and edit their profile, change their password, and access the tools they are allowed to use
- an administrator keeps all standard user capabilities and also gets the full administration feature set

## Who this is for

- Administrators who want a release-based installation path for production.
- Developers or integrators who want to build from source, customize the project, or wire it into an existing intranet.

## Architecture

```text
PHP client / scripts / HTTP tools
              |
              v
     ADSelfService (.NET 8)
              |
              v
        Active Directory
```

The API does not use JWT or server-side sessions. It relies on:

- an allow-list of IPs through `Security.AllowedIps`
- an optional shared secret through the `X-Internal-Auth` header
- the effective permissions of the LDAP service account used by the application

The `isAdmin` flag returned by `/auth` is meant for clients. The `/admin/*` endpoints must therefore only be exposed to trusted internal callers.

## Quick start

### Option 1. Install from a release

This is the recommended production path.

1. Download the archives from [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deploy `ADSelfService-API-Server.zip` on the API host.
3. Run the published executable once.
4. Complete the `config.json` file generated on first startup.
5. Run the API again and check `GET /health`.
6. If needed, deploy `ADSelfService-WEBSERVER-Files.zip` on the PHP web server.
7. Create `config-intranet.php` from `config-intranet-default.php` and set `API_BASE` and `INTERNAL_SHARED_SECRET`.

### Option 2. Build the project and run it

This path is intended for development, testing, or customization.

```bash
git clone <repo-url>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

When started from a published folder, the application creates `config.json` automatically if it does not already exist. When working from source, you can start from `config.example.json`.

## Install from a release

### API server

1. Download `ADSelfService-API-Server.zip`.
2. Extract it into a dedicated folder.
3. Run `ADSelfService-API.Server.exe` once.
4. Open the generated `config.json` and replace the example values.
5. Run again in console mode and verify:
   - LDAP connectivity
   - successful service account bind
   - `200` on `/health`
6. On Windows, install the service if needed:
   - `ADSelfService-API.Server.exe --add-service`
   - remove it with `ADSelfService-API.Server.exe --remove-service`

The created Windows service is named `ADSelfServiceAPI`.

### PHP client

1. Download `ADSelfService-WEBSERVER-Files.zip`.
2. Extract it into the directory served by Apache, IIS, or nginx + PHP.
3. Copy `config-intranet-default.php` to `config-intranet.php`.
4. Fill in at least:
   - `API_BASE`
   - `INTERNAL_SHARED_SECRET` if the API requires it
   - database settings if you use the built-in tools area
5. Keep the provided protection files such as `.htaccess` and `web.config`.

## Build the project and run it

### Prerequisites

- .NET 8 SDK
- Windows recommended for `System.DirectoryServices`
- access to an Active Directory over LDAP or LDAPS
- an AD service account with sufficient rights
- PHP 8+ if you use the web client

### .NET API

From the repository root:

```bash
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

For a published build:

```bash
cd ADSelfService-API.Server
dotnet publish -c Release
```

Then place `config.json` next to the published executable.

### PHP client

The `WEB-CLIENT-PHP` folder can be deployed as-is on your web server. Local configuration must be done in `config-intranet.php`, never in `config-intranet-default.php`.

## Configuration

Useful documents:

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md): full reference for `config.json`
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md): choosing between LDAPS and LDAP + Kerberos
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md): HTTP endpoint reference

Important notes:

- `Ldap.Url` should preferably be a FQDN when using Kerberos on port `389`.
- `Ldap.BindDn` should preferably use `user@domain.local` or `DOMAIN\user`.
- `Security.AllowedIps` must include the PHP server, the reverse proxy if any (discouraged), or other trusted internal callers.
- `InternalSharedSecret` must match on both API and PHP sides if you enable the header-based check.

## Usage

In day-to-day use, an end user can:

- sign in with their Active Directory account
- view and edit their profile
- access the tools assigned to them by administrators
- change their password, including on first sign-in when a password change is required

An administrator has all of these standard user capabilities, plus the full set of directory administration features exposed by the API and web client.

### Main endpoints

- `GET /health`: availability and LDAP bind check
- `POST /auth`: domain user authentication
- `GET /users`: list users
- `GET /groups`: list groups
- `GET /tree`: browse directory tree
- `POST /user/updateProfile`: update user profile
- `POST /user/changePassword`: change user password
- `POST /admin/*`: administration operations

Authentication example:

```json
{
  "username": "jdoe",
  "password": "MyPassword"
}
```

## Security

- Do not expose the API directly to the public Internet.
- Keep `Security.AllowedIps` as strict as possible.
- Enable `InternalSharedSecret` if your PHP client or another internal caller uses it.
- Prefer LDAPS in production.
- Only enable `Debug.ShowPasswords` in a tightly controlled troubleshooting context.
- Never commit `config.json` or `config-intranet.php`.

## Quick troubleshooting

| Issue | Check |
|-------|-------|
| `403 Forbidden` on every call | verify `AllowedIps` and, if enabled, the `X-Internal-Auth` header |
| API exits at startup | check for placeholder values still present in `config.json` |
| LDAP bind failure | verify `Url`, `Port`, `Ssl`, `BindDn`, `BindPassword` |
| password change rejected | verify you use LDAPS or `UseKerberosSealing=true` |
| PHP client refuses to start | verify `config-intranet.php`, `API_BASE`, and `INTERNAL_SHARED_SECRET` |

## Detailed documentation

- [CONFIG-OPTIONS.en.md](CONFIG-OPTIONS.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
- [ADSelfService-API.Server/CHANGELOG.en.md](ADSelfService-API.Server/CHANGELOG.en.md)

## Languages

- English: `README.en.md`
- Francais: [README.md](README.md)
