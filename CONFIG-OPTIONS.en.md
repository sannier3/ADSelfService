# Configuration options (`config.json`)

This document describes the options used by `ADSelfService-API.Server` and the runtime constraints enforced at startup.

## How configuration is loaded

- If `config.json` is missing next to the executable, the application creates a default file and exits.
- You must complete that file before restarting.

## Baseline example (adapt to your environment)

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 636,
    "Ssl": true,
    "UseKerberosSealing": false,
    "IgnoreCertificate": false,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "replace-me",
    "BaseDn": "OU=Infra,DC=example,DC=local",
    "GroupBaseDn": "DC=example,DC=local",
    "RootDn": "DC=example,DC=local",
    "AdminGroupDn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local"
  },
  "Security": {
    "AllowedIps": ["127.0.0.1", "::1", "192.168.1.0/24"],
    "InternalSharedSecret": "long-unique-secret-at-least-32-chars",
    "RequireAppContextHeader": true
  },
  "Debug": {
    "Enabled": false,
    "ShowPasswords": false,
    "LogDir": "logs",
    "Console": true
  },
  "Pagination": {
    "Enabled": true,
    "PageSize": 200
  },
  "Server": {
    "Urls": ["http://0.0.0.0:5001"]
  },
  "StartupCheck": {
    "Enabled": true,
    "FailFast": false,
    "ShowDetailsInConsole": true
  }
}
```

## `Ldap` section

| Option | Type | Description |
|---|---|---|
| `Url` | `string` | Domain controller. Use FQDN for Kerberos on `389`. |
| `Port` | `int` | `389` (LDAP/Kerberos) or `636` (LDAPS). |
| `Ssl` | `bool` | Enables LDAPS. |
| `UseKerberosSealing` | `bool` | Enables Sign & Seal over non-TLS LDAP. |
| `IgnoreCertificate` | `bool` | Skips LDAPS certificate validation (test only). |
| `BindDn` | `string` | LDAP service account (`user@domain` or `DOMAIN\\user` recommended). |
| `BindPassword` | `string` | Service account password. |
| `BaseDn` | `string` | User/explorer base DN. |
| `GroupBaseDn` | `string` | Group search base DN. |
| `RootDn` | `string` | Domain root DN. |
| `AdminGroupDn` | `string` | AD group used as logical admin reference. |

### Important transport rule

At least one protected transport mode must be enabled:

- `Ssl=true`, or
- `UseKerberosSealing=true`.

Otherwise startup validation fails.

## `Security` section

| Option | Type | Description |
|---|---|---|
| `AllowedIps` | `string[]` | Allowed API caller IPs/CIDR ranges. |
| `InternalSharedSecret` | `string` | Internal shared secret; must be strong. |
| `RequireAppContextHeader` | `bool` | Enforces `X-App-Context` checks (recommended: `true`). |

### Enforced constraints

- If `InternalSharedSecret` is defined and shorter than 32 chars, startup is rejected.
- Calls outside `/health` must provide `X-Internal-Auth` when the secret is configured.
- Sensitive calls are app-context filtered (`X-App-Context`) when `RequireAppContextHeader=true`.

## `Debug` section

| Option | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Enables detailed request/response logs. |
| `ShowPasswords` | `bool` | Shows password values in logs. |
| `LogDir` | `string` | Log output directory. |
| `Console` | `bool` | Prints logs to console. |

### Forbidden value

- `ShowPasswords=true` is rejected by config validation.

## `Pagination` section

| Option | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Enables API list pagination. |
| `PageSize` | `int` | Default page size, must be > 0. |

## `Server` section

| Option | Type | Description |
|---|---|---|
| `Urls` | `string[]` | Kestrel listening URLs. |

## `StartupCheck` section

| Option | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Runs LDAP connectivity + bind checks on startup. |
| `FailFast` | `bool` | Stops the app when checks fail. |
| `ShowDetailsInConsole` | `bool` | Shows detailed startup exceptions in console. |

## Mandatory / Forbidden summary

### Mandatory

- Matching `InternalSharedSecret` on API and PHP sides.
- Tight `AllowedIps` perimeter.
- Protected LDAP transport (`Ssl=true` or `UseKerberosSealing=true`).

### Forbidden

- `Debug.ShowPasswords=true`.
- Unprotected LDAP mode (neither SSL nor Kerberos sealing).

## Useful references

- [README.en.md](README.en.md)
- [ADSelfService-API.Server/LDAP-CONFIG.en.md](ADSelfService-API.Server/LDAP-CONFIG.en.md)
- [ADSelfService-API.Server/ENDPOINTS.en.md](ADSelfService-API.Server/ENDPOINTS.en.md)
