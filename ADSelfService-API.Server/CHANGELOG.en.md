## Changelog

This file summarizes the main functional changes visible in the repository. For ready‑to‑run binaries, also refer to the project’s published releases.

### Unreleased

- Reworked documentation to clearly distinguish installation from a release vs running from source.
- API, configuration, and LDAP documentation aligned with the actual code behavior.

### 1.00.00

Version number as reported by `ADSelfService-API.Server`.

Key features:

- .NET 8 REST API targeting `net8.0-windows`
- AD authentication via `/auth`
- user profile read and update
- user and admin password change
- user management: create, delete, enable, disable, unlock, rename, move, set expiration
- group management: list, create, delete, add and remove members
- OU management: create, update, logically protect, delete
- `/tree` endpoint to explore the directory
- network filtering via `AllowedIps`
- optional internal shared secret via `X-Internal-Auth`
- automatic `config.json` generation on first run when no configuration file exists
- support for `config.json`
- Windows service installation via `--add-service` and removal via `--remove-service`

### Suggested format for future entries

```md
## x.y.z

- added:
- changed:
- fixed:
```

