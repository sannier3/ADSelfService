# API endpoint reference

All endpoints return JSON.

## Access security (before endpoint logic)

Before business logic executes, the API applies:

- IP filtering (`Security.AllowedIps`),
- `X-Internal-Auth` shared-secret check (when configured),
- app-context check via `X-App-Context` (when `RequireAppContextHeader=true`).

`/health` is exempt from app-context checks, but still IP-filtered.

## Expected app contexts

Examples used by the PHP client:

- `intranet-login`: login (`/auth`),
- `self-service`: standard user endpoints,
- `admin-user`: user administration endpoints,
- `admin-domain`: domain/explorer administration endpoints,
- `forgot-reset`: forgot-password flow.

Wrong context can return `403`.

## Health and metadata

### `GET /health`

- Verifies LDAP bind status.
- `200` when healthy, `500` otherwise.

### `GET /meta/ad`

- Returns metadata such as `baseDn`, `groupBaseDn`, `rootDn`.

## Authentication and self-service

### `POST /auth`

Body:

```json
{
  "username": "jdoe",
  "password": "Password"
}
```

Returns `success`, `user`, `mustChangePassword`, `isAdmin`.

### `GET /user/{sam}`

- Reads a user profile.

### `POST /user/updateProfile`

Body:

```json
{
  "dn": "CN=John Doe,OU=Infra,DC=example,DC=local",
  "modifications": {
    "mail": "john.doe@example.local",
    "telephoneNumber": "+33102030405"
  }
}
```

### `POST /user/changePassword`

Body:

```json
{
  "username": "jdoe",
  "currentPassword": "OldPassword",
  "newPassword": "NewPassword"
}
```

## Forgot-password flow

### `GET /recovery/lookup?identifier=<email|phone>`

- Dedicated lookup endpoint for the reset flow.
- Response:
  - `{"found": false}` when no account matches,
  - or `{"found": true, "sam": "...", "givenName": "...", ...}`.

## List endpoints

### `GET /users`

Query:

- `includeBuiltins=true|false`,
- `groups=none|direct|effective`,
- `page`, `pageSize` (when pagination enabled).

### `GET /groups`

Query:

- `baseDn` (optional),
- `search` (optional),
- `page`, `pageSize`.

### `GET /tree`

Query:

- `baseDn` (optional),
- `depth` (1-10),
- `includeLeaves=true|false`,
- `maxChildren` (max 2000).

## AD explorer (unified contract)

### `GET /explorer/search`

- Multi-type search under explorer base DN.

### `GET /explorer/group-search?q=&scope=&max=`

- Group search.
- `scope`:
  - `all` => under `RootDn`,
  - `groups` => under `GroupBaseDn`,
  - `explorer` => under explorer `BaseDn`.

### `GET /explorer/user-search?q=&max=`

- User search endpoint.

### `GET /explorer/user-groups?user=`

- Returns direct groups for a user.

### `POST /explorer/user-groups/set`

Body:

```json
{
  "user": "jdoe",
  "groups": [
    "CN=ADSyncAdmins,CN=Users,DC=example,DC=local",
    "CN=IT,OU=Groups,DC=example,DC=local"
  ]
}
```

### `GET /explorer/group-members?group=`

- Returns direct members of a group.

### `POST /explorer/group-members/set`

Body:

```json
{
  "group": "CN=IT,OU=Groups,DC=example,DC=local",
  "members": [
    "CN=John Doe,OU=Infra,DC=example,DC=local"
  ]
}
```

### `GET /explorer/object?dn=`

- Returns object details.

### `GET /explorer/children?dn=...`

- Returns direct children of an object.

## User administration

### `POST /admin/createUser`
### `POST /admin/updateUser`
### `POST /admin/deleteUser`
### `POST /admin/moveUser`
### `POST /admin/renameUserCn`
### `POST /admin/changePassword`
### `POST /admin/setAccountExpiration`
### `POST /admin/setUserEnabled`
### `POST /admin/enableUser`
### `POST /admin/disableUser`
### `POST /admin/unlockUser`

All use explicit JSON payloads (`user`, `dn`, `attributes`, etc.), depending on the action.

## Group administration

### `POST /admin/createGroup`
### `DELETE /admin/deleteGroup`
### `POST /admin/deleteGroup` (alias)

`deleteGroup` accepts either `dn` or `group` in body.

## OU administration

### `POST /admin/ou/create`
### `POST /admin/ou/update`
### `POST /admin/ou/delete`

Key rules:

- scope limited to `BaseDn`,
- OU protection rules enforced,
- non-empty OUs cannot be deleted.

## Removed legacy endpoints

These are no longer part of the active contract:

- `/admin/addToGroup`
- `/admin/removeFromGroup`
- `/explorer/groupMembers`

## Common HTTP status codes

- `200`: success,
- `400`: invalid payload / LDAP constraint,
- `401`: authentication failure,
- `403`: forbidden (IP, secret, context, scope),
- `404`: resource not found,
- `409`: conflict (for example non-empty OU),
- `500`: server/LDAP bind error.
