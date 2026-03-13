# LDAP / AD configuration

This guide explains how to configure AD connectivity for `ADSelfService-API.Server` in a secure and reliable way.

## Core rule

Runtime now enforces protected LDAP transport. You must use:

- **LDAPS** (`Ssl=true`, port `636`), or
- **LDAP + Kerberos sealing** (`Ssl=false`, `UseKerberosSealing=true`, port `389`).

Unprotected mode (`Ssl=false` and `UseKerberosSealing=false`) is rejected.

## Recommended choice

| Context | Recommendation |
|---|---|
| Valid AD certificate + open 636 | LDAPS |
| No LDAPS but controlled Kerberos environment | LDAP + Kerberos sealing |

## Option 1 - LDAPS (recommended for production)

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 636,
    "Ssl": true,
    "UseKerberosSealing": false,
    "IgnoreCertificate": false,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "password",
    "BaseDn": "OU=Infra,DC=example,DC=local",
    "GroupBaseDn": "DC=example,DC=local",
    "RootDn": "DC=example,DC=local",
    "AdminGroupDn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local"
  }
}
```

### Good practices

- Use a valid certificate on domain controllers.
- Keep `IgnoreCertificate=false` outside lab/testing.
- Keep `BindDn` in `user@domain` or `DOMAIN\\user` format.

## Option 2 - LDAP + Kerberos sealing

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 389,
    "Ssl": false,
    "UseKerberosSealing": true,
    "IgnoreCertificate": true,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "password",
    "BaseDn": "OU=Infra,DC=example,DC=local",
    "GroupBaseDn": "DC=example,DC=local",
    "RootDn": "DC=example,DC=local",
    "AdminGroupDn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local"
  }
}
```

### Attention points

- `Url` must be DC FQDN (not IP) to avoid Kerberos/SPN issues.
- The API host must resolve DC names correctly.
- The service account must be valid for Kerberos authentication.

## Essential LDAP fields

| Field | Purpose |
|---|---|
| `BaseDn` | primary user/explorer scope |
| `GroupBaseDn` | dedicated group-search base |
| `RootDn` | domain-wide root scope |
| `AdminGroupDn` | logical admin group reference |

## Common symptoms and checks

| Symptom | Check |
|---|---|
| Startup failure | incomplete LDAP config, unprotected mode, blocked port |
| `Bind LDAP échoué` | invalid `BindDn`/`BindPassword`, AD ACL, DNS |
| Password change failure | missing LDAPS or Kerberos sealing |
| Kerberos errors on 389 | wrong FQDN, DNS/SPN mismatch |

## Validation checklist

1. `GET /health` returns `200`.
2. `POST /auth` works with a valid account.
3. `POST /user/changePassword` succeeds.
4. `explorer/*` endpoints return results in expected DN scope.

## See also

- [../ENDPOINTS.en.md](../ENDPOINTS.en.md)
- [../../CONFIG-OPTIONS.en.md](../../CONFIG-OPTIONS.en.md)
