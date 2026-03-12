## Configuration options

This document lists the options read by the API from `config.json`.

### How configuration is loaded

- If `config.json` does not exist next to the executable, the application creates a default `config.json` and then exits.

For development, you can start from the `config.example.json` file.

### Minimal example

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
    "BaseDn": "OU=Users,DC=example,DC=local",
    "GroupBaseDn": "DC=example,DC=local",
    "RootDn": "DC=example,DC=local",
    "AdminGroupDn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local"
  },
  "Security": {
    "AllowedIps": [ "127.0.0.1", "::1", "192.168.1.0/24" ],
    "InternalSharedSecret": null
  },
  "Server": {
    "Urls": [ "http://0.0.0.0:5000" ]
  }
}
```

### Section `Ldap`

Controls how the API connects to Active Directory.

| Option | Type | Description |
|--------|------|-------------|
| `Url` | `string` | Domain controller hostname. When using Kerberos on port `389`, this must be the FQDN. |
| `Port` | `int` | `389` for LDAP or LDAP + Kerberos, `636` for LDAPS. |
| `Ssl` | `bool` | `true` for LDAPS, `false` for LDAP. |
| `UseKerberosSealing` | `bool` | Enables Sign & Seal over non‑TLS LDAP to allow password changes on port `389`. Ignored when `Ssl=true`. |
| `IgnoreCertificate` | `bool` | Skips certificate validation for LDAPS. Only for lab/test setups. |
| `BindDn` | `string` | Service account used to bind to LDAP. Recommended format: `user@example.local` or `DOMAIN\user`. |
| `BindPassword` | `string` | Password for the service account. |
| `BaseDn` | `string` | Base DN for user searches. |
| `GroupBaseDn` | `string` | Base DN for group searches. |
| `RootDn` | `string` | Domain root DN. |
| `AdminGroupDn` | `string` | AD group treated as the “admin” group by API logic. |

See also `ADSelfService-API.Server/LDAP-CONFIG.en.md`.

### Section `Debug`

Controls application logging.

| Option | Type | Description |
|--------|------|-------------|
| `Enabled` | `bool` | Enables detailed logging of requests and responses. |
| `ShowPasswords` | `bool` | Logs passwords in some debug traces. Keep `false` in production. |
| `LogDir` | `string` | Directory where log files are written. |
| `Console` | `bool` | Also writes logs to the console. |

### Section `Security`

Controls who can call the API.

| Option | Type | Description |
|--------|------|-------------|
| `AllowedIps` | `string[]` | List of IPs or CIDR ranges allowed to call the API. All others receive `403`. |
| `InternalSharedSecret` | `string?` | Optional secret compared with the `X-Internal-Auth` header. If set, all calls except `/health` must provide this exact value. |

Important:

- Filtering happens at HTTP level before any endpoint logic.
- `/admin/*` endpoints should always stay behind this trusted network perimeter.

### Section `Pagination`

Controls pagination for `GET /users` and `GET /groups`.

| Option | Type | Description |
|--------|------|-------------|
| `Enabled` | `bool` | Enables pagination on list endpoints. |
| `PageSize` | `int` | Default page size. Must be strictly positive. |

### Section `Server`

Controls Kestrel listening URLs.

| Option | Type | Description |
|--------|------|-------------|
| `Urls` | `string[]` | Array of URLs to listen on, e.g. `http://0.0.0.0:5000` or `https://0.0.0.0:5001`. |

### Section `StartupCheck`

Controls startup checks.

| Option | Type | Description |
|--------|------|-------------|
| `Enabled` | `bool` | Enables LDAP TCP connectivity test and service account bind at startup. |
| `FailFast` | `bool` | If `true`, the app exits when the check or bind fails. |
| `ShowDetailsInConsole` | `bool` | Prints exception details to the console when startup checks fail. |

### Recommendations

- In production, prefer `Ssl=true` and `Port=636`.
- When using port `389`, enable `UseKerberosSealing=true`.
- Keep `IgnoreCertificate=false` outside of test environments.
- Restrict `AllowedIps` to the PHP server, reverse proxy (if any), or internal tooling.
- Never commit `config.json` or any variant containing real secrets.

