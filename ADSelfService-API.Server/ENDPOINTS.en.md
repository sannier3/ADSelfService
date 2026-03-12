## Endpoint reference

All endpoints return JSON. This API does not include JWT or HTTP session handling.

### Transport security

Before any endpoint logic runs, the API applies:

- IP filtering based on `Security.AllowedIps`
- an optional shared‑secret check on the `X-Internal-Auth` header when `InternalSharedSecret` is configured

`GET /health` is the only endpoint that does not require `X-Internal-Auth`, but it is still IP‑filtered.

Important: the `isAdmin` flag returned by `/auth` is intended for clients. The `/admin/*` routes must only be reachable from trusted internal callers.

### Common conventions

- Many user parameters accept either a `sAMAccountName` or a full DN.
- Group identifiers may be resolved as DN, CN, `sAMAccountName`, or `name` depending on the endpoint.
- Dates are expected in ISO 8601 format.
- When pagination is enabled, `GET /users` and `GET /groups` expose `X-Page`, `X-Page-Size`, and `X-Has-More` headers.

## Health

### `GET /health`

Checks that the API can still bind to Active Directory with the service account.

Success:

```json
{
  "status": "ok"
}
```

Typical status codes:

- `200` – service healthy
- `500` – LDAP bind failed

## Authentication and profile

### `POST /auth`

Request body:

```json
{
  "username": "jdoe",
  "password": "MyPassword"
}
```

Success:

```json
{
  "success": true,
  "user": {
    "dn": "CN=John Doe,OU=Users,DC=example,DC=local",
    "sAMAccountName": "jdoe",
    "givenName": "John",
    "sn": "Doe",
    "mail": "john.doe@example.local",
    "memberOf": [ "ADSyncAdmins" ],
    "memberOfEffective": [ "ADSyncAdmins", "IT" ],
    "objectGUID": "guid-or-null",
    "telephoneNumber": "0102030405",
    "wwwhomepage": "",
    "streetAddress": ""
  },
  "mustChangePassword": false,
  "isAdmin": true
}
```

Typical status codes:

- `200` – authentication succeeded
- `400` – `username` or `password` missing
- `401` – user not found, invalid or expired password
- `403` – account disabled
- `500` – LDAP or server error

### `GET /user/{sam}`

Returns information about the requested user.

Typical status codes:

- `200` – user found
- `404` – user not found
- `500` – server error

### `POST /user/updateProfile`

Updates profile attributes on a user DN.

Request body:

```json
{
  "dn": "CN=John Doe,OU=Users,DC=example,DC=local",
  "modifications": {
    "mail": "john.doe@example.local",
    "telephoneNumber": "0102030405",
    "streetAddress": ""
  }
}
```

Notes:

- an empty string removes the attribute
- if no modifications are provided, the API still returns `success: true` with a note
- `description` is limited to 1024 characters

Typical status codes:

- `200` – profile updated or already up‑to‑date
- `400` – invalid body or LDAP modification error
- `500` – server error

### `POST /user/changePassword`

Request body:

```json
{
  "username": "jdoe",
  "currentPassword": "OldPassword",
  "newPassword": "NewPassword"
}
```

Typical status codes:

- `200` – password changed
- `400` – invalid body
- `401` – current password invalid
- `404` – user not found
- `500` – LDAP or server error

## Users

### `GET /users`

Query string:

- `includeBuiltins` – `true` or `false`, defaults to `false`
- `groups` – `none`, `direct`, or `effective`, defaults to `direct`
- `page`, `pageSize` – when pagination is enabled

Success:

```json
[
  {
    "dn": "CN=John Doe,OU=Users,DC=example,DC=local",
    "sAMAccountName": "jdoe",
    "givenName": "John",
    "sn": "Doe",
    "mail": "john.doe@example.local",
    "telephoneNumber": "0102030405",
    "wwwhomepage": "",
    "streetAddress": "",
    "objectGUID": "guid-or-null",
    "disabled": false,
    "memberOf": [ "IT" ]
  }
]
```

Typical status codes:

- `200` – list returned
- `500` – server error

## Groups

### `GET /groups`

Query string:

- `baseDn` – optional, defaults to `GroupBaseDn` then `RootDn`
- `search` – filter on `cn` or `sAMAccountName`
- `page`, `pageSize` – when pagination is enabled

Success:

```json
[
  {
    "id": "guid-or-null",
    "name": "ADSyncAdmins",
    "dn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local",
    "sam": "ADSyncAdmins"
  }
]
```

Typical status codes:

- `200` – list returned
- `500` – server error

## Directory tree

### `GET /tree`

Query string:

- `baseDn` – optional, defaults to `BaseDn` then `RootDn`
- `depth` – between `1` and `10`, default `3`
- `includeLeaves` – `true` or `false`, default `false`
- `maxChildren` – default `200`, maximum `2000`

Success:

```json
{
  "baseDn": "DC=example,DC=local",
  "depth": 3,
  "includeLeaves": false,
  "maxChildren": 200,
  "nodes": [
    {
      "name": "Users",
      "dn": "OU=Users,DC=example,DC=local",
      "type": "ou",
      "hasChildren": true,
      "children": []
    }
  ]
}
```

Typical status codes:

- `200` – tree returned
- `500` – server error

## User administration

### `POST /admin/createUser`

Request body:

```json
{
  "OuDn": "OU=Users,DC=example,DC=local",
  "Cn": "John Doe",
  "Sam": "jdoe",
  "GivenName": "John",
  "Sn": "Doe",
  "UserPrincipalName": "jdoe@example.local",
  "Mail": "john.doe@example.local",
  "Password": "InitialPassword",
  "Enabled": true,
  "Description": "Intranet account",
  "ExpiresAt": "2026-12-31T23:59:59Z",
  "NeverExpires": false
}
```

Success:

```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=local"
}
```

### `POST /admin/deleteUser`

Request body:

```json
{
  "user": "jdoe"
}
```

### `POST /admin/updateUser`

Request body:

```json
{
  "user": "jdoe",
  "attributes": {
    "mail": "john.doe@example.local",
    "telephoneNumber": "0102030405",
    "description": "Admin account"
  }
}
```

Notes:

- an empty value removes the attribute
- `description` is limited to 1024 characters

### `POST /admin/moveUser`

Request body:

```json
{
  "user": "jdoe",
  "newOuDn": "OU=Support,DC=example,DC=local"
}
```

### `POST /admin/renameUserCn`

Request body:

```json
{
  "user": "jdoe",
  "newCn": "John Doe"
}
```

### `POST /admin/setAccountExpiration`

Request body:

```json
{
  "user": "jdoe",
  "expiresAt": "2026-12-31T23:59:59Z",
  "never": false
}
```

Or to clear expiration:

```json
{
  "user": "jdoe",
  "never": true
}
```

### `POST /admin/changePassword`

Request body:

```json
{
  "username": "jdoe",
  "newPassword": "NewPassword",
  "mustChangeAtNextLogon": true
}
```

### `POST /admin/setUserEnabled`

Request body:

```json
{
  "user": "jdoe",
  "enabled": true
}
```

### `POST /admin/enableUser`

Human‑readable alias of `setUserEnabled` to enable an account.

### `POST /admin/disableUser`

Human‑readable alias of `setUserEnabled` to disable an account.

### `POST /admin/unlockUser`

Request body:

```json
{
  "user": "jdoe"
}
```

Typical status codes for user admin endpoints:

- `200` – operation successful
- `400` – invalid body or LDAP business error
- `404` – user or target not found
- `500` – server error

## Group administration

### `POST /admin/createGroup`

Request body:

```json
{
  "OuDn": "OU=Groups,DC=example,DC=local",
  "Cn": "Support Team",
  "Sam": "SupportTeam",
  "Scope": "Global",
  "SecurityEnabled": true,
  "Description": "Support group"
}
```

### `POST /admin/addToGroup`

Request body:

```json
{
  "user": "jdoe",
  "groupDn": "SupportTeam"
}
```

### `POST /admin/removeFromGroup`

Request body:

```json
{
  "user": "jdoe",
  "groupDn": "SupportTeam"
}
```

### `DELETE /admin/deleteGroup`

Or `POST /admin/deleteGroup` with a JSON body.

Request body accepts one of:

```json
{
  "dn": "CN=Support Team,OU=Groups,DC=example,DC=local"
}
```

or:

```json
{
  "group": "SupportTeam"
}
```

Typical status codes:

- `200` – operation successful
- `400` – invalid parameter or LDAP error
- `404` – group not found
- `500` – server error

## OU administration

### `POST /admin/ou/create`

Request body:

```json
{
  "ParentDn": "OU=Users,DC=example,DC=local",
  "Name": "Contractors",
  "Description": "Contractor OU",
  "Protected": true
}
```

When `Protected=true`, the API tags the OU with `adminDescription="API_PROTECTED=1"`.

### `POST /admin/ou/update`

Request body:

```json
{
  "OuDn": "OU=Contractors,OU=Users,DC=example,DC=local",
  "NewName": "External Contractors",
  "Description": "Renamed OU",
  "Protected": true,
  "NewParentDn": "OU=HR,DC=example,DC=local"
}
```

Notes:

- `Description = null` leaves the field unchanged
- `Description = ""` removes the description
- `NewParentDn` must remain under `BaseDn`

### `POST /admin/ou/delete`

Request body:

```json
{
  "OuDn": "OU=Contractors,OU=Users,DC=example,DC=local"
}
```

Conditions:

- OU must be under `BaseDn`
- OU must be empty
- OU must not be protected

Typical status codes:

- `200` – deletion successful
- `403` – OU outside scope or protected
- `404` – OU not found
- `409` – OU not empty
- `500` – server error

## Common error codes

- `400` – validation or invalid LDAP operation
- `401` – user authentication failure
- `403` – IP not allowed, missing internal secret, or forbidden operation
- `404` – resource not found
- `409` – conflict, for example non‑empty OU
- `500` – server or LDAP bind error

