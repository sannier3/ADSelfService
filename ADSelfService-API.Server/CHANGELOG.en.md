# Changelog

This changelog highlights major repository-level changes.

## Unreleased

### Security

- Hardened API access model:
  - app-context enforcement through `X-App-Context`,
  - stricter config validation (`InternalSharedSecret`, protected LDAP transport),
  - startup rejection for unsafe/incomplete security configurations.
- Hardened forgot-password flow:
  - dedicated API endpoint `/recovery/lookup`,
  - reduced account-enumeration exposure,
  - anti-bruteforce handling in PHP client flow.
- Secured HTML rendering for tool instructions with strict allowlist sanitization.

### API and endpoint contract

- Consolidated group/membership operations around unified explorer endpoints:
  - `/explorer/group-search`,
  - `/explorer/user-groups`,
  - `/explorer/user-groups/set`,
  - `/explorer/group-members`,
  - `/explorer/group-members/set`.
- Removed documented legacy group routes (`addToGroup/removeFromGroup/groupMembers`).
- Fixed group search scope behavior so `scope=all` correctly includes groups under `RootDn` and subtrees.

### PHP UI and integration logic

- Simplified group/member management flows.
- Improved readability of user-group displays.
- Aligned intranet AJAX calls with current API contracts.

### Documentation

- Full Markdown documentation refresh (FR/EN):
  - clearer structure for users and operators,
  - strict alignment with current runtime behavior,
  - stronger deployment and troubleshooting guidance.

## 1.00.00

Initial project baseline:

- .NET 8 API for Active Directory.
- Authentication, profile, and password flows.
- User/group/OU administration.
- PHP intranet client.

## Suggested format for future entries

```md
## x.y.z

### Security
- ...

### API
- ...

### UI / Integration
- ...

### Documentation
- ...
```
