## LDAP connection

The API can talk to Active Directory in two main ways:

- `LDAPS` over port `636`
- `LDAP + Kerberos` over port `389`

Your choice mostly depends on your infrastructure. When in doubt, pick `LDAPS`.

### Quick recommendation

| Scenario | Recommendation |
|----------|----------------|
| You have valid AD certificates and port 636 open | use `LDAPS` |
| You cannot enable LDAPS but the server can use Kerberos | use `LDAP + Kerberos` |
| You only have plain, unsecured LDAP | not recommended for this API |

## Option 1 – LDAPS

`LDAPS` is the recommended mode for production.

### When to use it

- you can reach the domain controller over port `636`
- the controller certificate is valid or trusted in your environment
- you want standard TLS transport

### Expected settings

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 636,
    "Ssl": true,
    "UseKerberosSealing": false,
    "IgnoreCertificate": false,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "password"
  }
}
```

### Important notes

- `Url` may be a FQDN or an IP, but FQDN is preferable.
- `BindDn` should ideally use `user@domain.local` or `DOMAIN\user`.
- Avoid a full DN like `CN=...,OU=...` as `BindDn`.
- Only set `IgnoreCertificate=true` in test environments.

## Option 2 – LDAP + Kerberos

This mode lets you stay on port `389` while using Kerberos with Sign & Seal.

### When to use it

- you cannot enable LDAPS
- the server running the API can obtain Kerberos tickets
- you need to support password changes without TLS

### Expected settings

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 389,
    "Ssl": false,
    "UseKerberosSealing": true,
    "IgnoreCertificate": true,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "password"
  }
}
```

### Important notes

- `Url` must be the domain controller FQDN, not its IP.
- `BindDn` must use `user@domain.local` or `DOMAIN\user`.
- The machine or service account must be correctly integrated in the Kerberos environment.
- Without `UseKerberosSealing=true`, sensitive operations such as password changes may be rejected.

## Common symptoms

| Issue | Likely cause |
|-------|--------------|
| `The supplied credential is invalid (49)` with a correct password | `BindDn` provided as a full DN instead of UPN or `DOMAIN\user` |
| Connection failure on `389` | wrong FQDN, SPN not resolved, or Kerberos unavailable |
| Password change rejected | using plain LDAP without Kerberos sealing |
| Startup check fails | blocked port, invalid certificate, wrong bind, or AD unreachable |

## Practical tips

- Always test in console mode before installing the Windows service.
- With `LDAPS`, start with `IgnoreCertificate=false`.
- With Kerberos, first verify DNS resolution of the controller FQDN.
- Keep operational DNs (for queries) in `BaseDn`, `GroupBaseDn`, and `RootDn`, not in `BindDn`.

