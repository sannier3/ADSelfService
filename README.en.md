# ADSelfService-API

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-lightgrey.svg)](README.md)
[![English](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md)

![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

.NET 8 REST API for Active Directory self-service and directory administration, designed for intranet usage with a PHP web client, scripts, or internal integrations.

## Overview

The repository contains two main parts:

- `ADSelfService-API.Server`: the HTTP API that talks to Active Directory through LDAP, LDAPS, or LDAP + Kerberos.
- `WEB-CLIENT-PHP`: a PHP intranet client that consumes the API and provides a user interface.

Main features:

- Authenticate a domain user with `/auth`.
- Read and update user profile data.
- Change the user's password.
- Administer AD accounts: create, delete, enable, disable, unlock, rename, move, set expiration.
- Administer groups: browse, create, delete, add and remove members.
- Administer OUs: create, update, logically protect, and delete.
- Browse the directory tree through `/tree`.

## Who this is for

- Administrators who want a release-based installation path for production.
- Developers or integrators who want to build from source, customize the project, or wire it into an existing intranet.

## Architecture

```text
PHP client / scripts / HTTP tools
              |
              v
     ADSelfService-API (.NET 8)
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

When started from a published folder, the application creates `config.json` automatically if neither `config.json` nor `config.yaml` exists. When working from source, you can start from `config.example.json`.

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

Then place `config.json` or `config.yaml` next to the published executable.

### PHP client

The `WEB-CLIENT-PHP` folder can be deployed as-is on your web server. Local configuration must be done in `config-intranet.php`, never in `config-intranet-default.php`.

## Configuration

Useful documents:

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md): full reference for `config.json` and `config.yaml`
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md): choosing between LDAPS and LDAP + Kerberos
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md): HTTP endpoint reference

Important notes:

- `Ldap.Url` should preferably be a FQDN when using Kerberos on port `389`.
- `Ldap.BindDn` should preferably use `user@domain.local` or `DOMAIN\user`.
- `Security.AllowedIps` must include the PHP server, the reverse proxy if any (discouraged), or other trusted internal callers.
- `InternalSharedSecret` must match on both API and PHP sides if you enable the header-based check.

## Usage

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
- Never commit `config.json`, `config.yaml`, or `config-intranet.php`.

## Quick troubleshooting

| Issue | Check |
|-------|-------|
| `403 Forbidden` on every call | verify `AllowedIps` and, if enabled, the `X-Internal-Auth` header |
| API exits at startup | check for placeholder values still present in `config.json` |
| LDAP bind failure | verify `Url`, `Port`, `Ssl`, `BindDn`, `BindPassword` |
| password change rejected | verify you use LDAPS or `UseKerberosSealing=true` |
| PHP client refuses to start | verify `config-intranet.php`, `API_BASE`, and `INTERNAL_SHARED_SECRET` |

## Detailed documentation

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)

## Languages

- English: `README.en.md`
- Francais: [README.md](README.md)
