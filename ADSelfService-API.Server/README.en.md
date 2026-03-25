# ADSelfService-API.Server

.NET 8 API for `ADSelfService`.

This component centralizes:

- Active Directory authentication
- LDAP/AD operations for users, groups, OUs, and explorer views
- server-side access enforcement
- startup-time security configuration validation

## Main files

- `Program.cs`: bootstrap, configuration, endpoints, main logic.
- `ADSelfService-API.Server.csproj`: .NET 8 project file.
- `LDAP-CONFIG.en.md`: LDAP / AD guide.
- `ENDPOINTS.en.md`: route reference.
- `CHANGELOG.en.md`: notable changes.

## Runtime configuration

The API reads `config.json` or `config.yaml` next to the binary.

On first start:

- if no config file exists, the application may generate a template
- you must then complete the configuration before real use

For available options:

- [../CONFIG-OPTIONS.en.md](../CONFIG-OPTIONS.en.md)

## Enforced security constraints

- `Security.AllowedIps`
- `Security.InternalSharedSecret`
- `Security.RequireAppContextHeader`
- protected LDAP transport is mandatory:
  - `Ldap.Ssl=true`, or
  - `Ldap.UseKerberosSealing=true`
- `Debug.ShowPasswords=true` is forbidden

## Local startup

```bash
copy ..\config.example.json .\config.json
dotnet run --project ADSelfService-API.Server
```

Then verify:

- `GET /health`

## Publishing

The project can be published as a folder deployment or packaged for releases.

Example:

```bash
dotnet publish ADSelfService-API.Server -c Release -r win-x64 --self-contained false
```

## Note about `SpaRoot`

The `.csproj` still contains `SpaRoot` / `SpaProxy*` properties.
In the current repository state, the actively maintained and shipped client is `WEB-CLIENT-PHP`, not a versioned SPA frontend inside this repo.

Treat these properties as a technical / historical leftover unless a dedicated frontend folder is added back.

## Related documentation

- [Root README](../README.en.md)
- [API configuration](../CONFIG-OPTIONS.en.md)
- [LDAP configuration](./LDAP-CONFIG.en.md)
- [Endpoints reference](./ENDPOINTS.en.md)
- [Changelog](./CHANGELOG.en.md)
