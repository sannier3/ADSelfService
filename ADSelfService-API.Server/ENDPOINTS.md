# Référence des endpoints API

Tous les endpoints renvoient du JSON.

## Sécurité d'accès (avant endpoint)

Avant tout traitement métier:

- filtrage IP via `Security.AllowedIps`,
- contrôle du secret `X-Internal-Auth` (si `InternalSharedSecret` est configuré),
- contrôle de contexte applicatif via `X-App-Context` (si `RequireAppContextHeader=true`).

Le endpoint `/health` reste exempté du contexte applicatif, mais toujours filtré par IP.

## Contextes applicatifs attendus

Exemples de contextes utilisés par le client PHP:

- `intranet-login`: login (`/auth`),
- `self-service`: endpoints utilisateur standard,
- `admin-user`: administration utilisateurs,
- `admin-domain`: administration domaine/explorer,
- `forgot-reset`: flux mot de passe oublié.

Un contexte incohérent peut produire `403`.

## Santé et métadonnées

### `GET /health`

- Vérifie le bind LDAP.
- `200` si OK, `500` sinon.

### `GET /meta/ad`

- Retourne notamment `baseDn`, `groupBaseDn`, `rootDn`.

## Authentification et self-service

### `POST /auth`

Body:

```json
{
  "username": "jdupont",
  "password": "MotDePasse"
}
```

Retourne `success`, `user`, `mustChangePassword`, `isAdmin`.

### `GET /user/{sam}`

- Lecture des informations d'un utilisateur.

### `POST /user/updateProfile`

Body:

```json
{
  "dn": "CN=Jean Dupont,OU=Infra,DC=example,DC=local",
  "modifications": {
    "mail": "jean.dupont@example.local",
    "telephoneNumber": "+33102030405"
  }
}
```

### `POST /user/changePassword`

Body:

```json
{
  "username": "jdupont",
  "currentPassword": "Ancien",
  "newPassword": "Nouveau"
}
```

## Flux mot de passe oublié

### `GET /recovery/lookup?identifier=<email|telephone>`

- Endpoint dédié au lookup contrôlé du flux reset.
- Réponse:
  - `{"found": false}` si aucun compte,
  - ou `{"found": true, "sam": "...", "givenName": "...", ...}`.

## Endpoints de listes

### `GET /users`

Query:

- `includeBuiltins=true|false`,
- `groups=none|direct|effective`,
- `page`, `pageSize` (si pagination activée).

### `GET /groups`

Query:

- `baseDn` (optionnel),
- `search` (optionnel),
- `page`, `pageSize`.

### `GET /tree`

Query:

- `baseDn` (optionnel),
- `depth` (1-10),
- `includeLeaves=true|false`,
- `maxChildren` (max 2000).

## Explorer AD (contrat unifié)

### `GET /explorer/search`

- Recherche multi-types sous l'explorer base.

### `GET /explorer/group-search?q=&scope=&max=`

- Recherche de groupes.
- `scope`:
  - `all` => sous `RootDn`,
  - `groups` => sous `GroupBaseDn`,
  - `explorer` => sous `BaseDn`.

### `GET /explorer/user-search?q=&max=`

- Recherche utilisateurs.

### `GET /explorer/user-groups?user=`

- Groupes directs d'un utilisateur.

### `POST /explorer/user-groups/set`

Body:

```json
{
  "user": "jdupont",
  "groups": [
    "CN=ADSyncAdmins,CN=Users,DC=example,DC=local",
    "CN=IT,OU=Groups,DC=example,DC=local"
  ]
}
```

### `GET /explorer/group-members?group=`

- Membres directs d'un groupe.

### `POST /explorer/group-members/set`

Body:

```json
{
  "group": "CN=IT,OU=Groups,DC=example,DC=local",
  "members": [
    "CN=Jean Dupont,OU=Infra,DC=example,DC=local"
  ]
}
```

### `GET /explorer/object?dn=`

- Détails d'un objet AD.

### `GET /explorer/children?dn=...`

- Enfants directs d'un objet AD.

## Administration utilisateurs

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

Ces endpoints attendent des payloads JSON explicites (`user`, `dn`, `attributes`, etc.) selon l'action.

## Administration groupes

### `POST /admin/createGroup`
### `DELETE /admin/deleteGroup`
### `POST /admin/deleteGroup` (alias)

`deleteGroup` accepte un body contenant `dn` ou `group`.

## Administration OU

### `POST /admin/ou/create`
### `POST /admin/ou/update`
### `POST /admin/ou/delete`

Règles principales:

- périmètre limité sous `BaseDn`,
- protections OU respectées,
- suppression OU refusée si non vide.

## Endpoints legacy supprimés

Ces endpoints ne font plus partie du contrat actif:

- `/admin/addToGroup`
- `/admin/removeFromGroup`
- `/explorer/groupMembers`

## Codes HTTP usuels

- `200`: succès,
- `400`: payload invalide / contrainte LDAP,
- `401`: authentification invalide,
- `403`: non autorisé (IP, secret, contexte, périmètre),
- `404`: ressource introuvable,
- `409`: conflit (ex. OU non vide),
- `500`: erreur serveur/bind LDAP.
