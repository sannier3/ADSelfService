# Référence des endpoints

Tous les endpoints renvoient du JSON. Cette API n'embarque pas de mécanisme JWT ou de session HTTP.

## Sécurité du transport

Avant même d'entrer dans les endpoints, l'API applique :

- un filtrage par IP via `Security.AllowedIps`
- un contrôle optionnel de l'en-tête `X-Internal-Auth` si `InternalSharedSecret` est configuré

Le endpoint `GET /health` est le seul à ne pas exiger `X-Internal-Auth`, mais il reste filtré par IP.

Important : le booléen `isAdmin` retourné par `/auth` sert au client. Les routes `/admin/*` doivent être exposées uniquement à des appels internes de confiance.

## Conventions communes

- Les identifiants utilisateur acceptent souvent un `sAMAccountName` ou un DN complet.
- Les groupes peuvent être résolus selon le endpoint par DN, CN, `sAMAccountName` ou `name`.
- Les dates sont attendues au format ISO 8601.
- Quand la pagination est activée, `GET /users` et `GET /groups` ajoutent `X-Page`, `X-Page-Size` et `X-Has-More`.

## Santé

### `GET /health`

Vérifie que l'API peut encore se connecter à Active Directory avec le compte de service.

Succès :

```json
{
  "status": "ok"
}
```

Codes typiques :

- `200` : service operationnel
- `500` : bind LDAP impossible

## Authentification et profil

### `POST /auth`

Body :

```json
{
  "username": "jdupont",
  "password": "MonMotDePasse"
}
```

Succès :

```json
{
  "success": true,
  "user": {
    "dn": "CN=Jean Dupont,OU=Users,DC=example,DC=local",
    "sAMAccountName": "jdupont",
    "givenName": "Jean",
    "sn": "Dupont",
    "mail": "jean.dupont@example.local",
    "memberOf": [ "ADSyncAdmins" ],
    "memberOfEffective": [ "ADSyncAdmins", "IT" ],
    "objectGUID": "guid-ou-null",
    "telephoneNumber": "0102030405",
    "wwwhomepage": "",
    "streetAddress": ""
  },
  "mustChangePassword": false,
  "isAdmin": true
}
```

Codes typiques :

- `200` : authentification réussie
- `400` : `username` ou `password` manquant
- `401` : utilisateur introuvable, mot de passe invalide ou expire
- `403` : compte desactive
- `500` : erreur LDAP ou serveur

### `GET /user/{sam}`

Retourne les informations de l'utilisateur demandé.

Codes typiques :

- `200` : utilisateur trouvé
- `404` : utilisateur introuvable
- `500` : erreur serveur

### `POST /user/updateProfile`

Met à jour des attributs de profil sur un DN utilisateur.

Body :

```json
{
  "dn": "CN=Jean Dupont,OU=Users,DC=example,DC=local",
  "modifications": {
    "mail": "jean.dupont@example.local",
    "telephoneNumber": "0102030405",
    "streetAddress": ""
  }
}
```

Notes :

- une valeur vide supprime l'attribut
- si aucune modification n'est fournie, l'API renvoie `success: true` avec une note
- `description` est limitée à 1024 caractères

Codes typiques :

- `200` : mise à jour effectuée ou déjà conforme
- `400` : body invalide ou erreur LDAP de modification
- `500` : erreur serveur

### `POST /user/changePassword`

Body :

```json
{
  "username": "jdupont",
  "currentPassword": "AncienMotDePasse",
  "newPassword": "NouveauMotDePasse"
}
```

Codes typiques :

- `200` : mot de passe change
- `400` : body invalide
- `401` : mot de passe actuel invalide
- `404` : utilisateur introuvable
- `500` : erreur LDAP ou serveur

## Utilisateurs

### `GET /users`

Query string :

- `includeBuiltins` : `true` ou `false`, `false` par défaut
- `groups` : `none`, `direct` ou `effective`, `direct` par défaut
- `page`, `pageSize` : si pagination activée

Succès :

```json
[
  {
    "dn": "CN=Jean Dupont,OU=Users,DC=example,DC=local",
    "sAMAccountName": "jdupont",
    "givenName": "Jean",
    "sn": "Dupont",
    "mail": "jean.dupont@example.local",
    "telephoneNumber": "0102030405",
    "wwwhomepage": "",
    "streetAddress": "",
    "objectGUID": "guid-ou-null",
    "disabled": false,
    "memberOf": [ "IT" ]
  }
]
```

Codes typiques :

- `200` : liste retournée
- `500` : erreur serveur

## Groupes

### `GET /groups`

Query string :

- `baseDn` : facultatif, sinon `GroupBaseDn` puis `RootDn`
- `search` : filtre sur `cn` ou `sAMAccountName`
- `page`, `pageSize` : si pagination activée

Succès :

```json
[
  {
    "id": "guid-ou-null",
    "name": "ADSyncAdmins",
    "dn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local",
    "sam": "ADSyncAdmins"
  }
]
```

Codes typiques :

- `200` : liste retournée
- `500` : erreur serveur

## Arborescence

### `GET /tree`

Query string :

- `baseDn` : facultatif, sinon `BaseDn` puis `RootDn`
- `depth` : de `1` à `10`, `3` par défaut
- `includeLeaves` : `true` ou `false`, `false` par défaut
- `maxChildren` : `200` par défaut, maximum `2000`

Succès :

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

Codes typiques :

- `200` : arborescence retournée
- `500` : erreur serveur

## Administration des utilisateurs

### `POST /admin/createUser`

Body :

```json
{
  "OuDn": "OU=Users,DC=example,DC=local",
  "Cn": "Jean Dupont",
  "Sam": "jdupont",
  "GivenName": "Jean",
  "Sn": "Dupont",
  "UserPrincipalName": "jdupont@example.local",
  "Mail": "jean.dupont@example.local",
  "Password": "MotDePasseInitial",
  "Enabled": true,
  "Description": "Compte intranet",
  "ExpiresAt": "2026-12-31T23:59:59Z",
  "NeverExpires": false
}
```

Succès :

```json
{
  "success": true,
  "dn": "CN=Jean Dupont,OU=Users,DC=example,DC=local"
}
```

### `POST /admin/deleteUser`

Body :

```json
{
  "user": "jdupont"
}
```

### `POST /admin/updateUser`

Body :

```json
{
  "user": "jdupont",
  "attributes": {
    "mail": "jean.dupont@example.local",
    "telephoneNumber": "0102030405",
    "description": "Compte admin"
  }
}
```

Notes :

- une valeur vide supprime l'attribut
- `description` est limitée à 1024 caractères

### `POST /admin/moveUser`

Body :

```json
{
  "user": "jdupont",
  "newOuDn": "OU=Support,DC=example,DC=local"
}
```

### `POST /admin/renameUserCn`

Body :

```json
{
  "user": "jdupont",
  "newCn": "Jean Dupont"
}
```

### `POST /admin/setAccountExpiration`

Body :

```json
{
  "user": "jdupont",
  "expiresAt": "2026-12-31T23:59:59Z",
  "never": false
}
```

Ou pour supprimer l'expiration :

```json
{
  "user": "jdupont",
  "never": true
}
```

### `POST /admin/changePassword`

Body :

```json
{
  "username": "jdupont",
  "newPassword": "NouveauMotDePasse",
  "mustChangeAtNextLogon": true
}
```

### `POST /admin/setUserEnabled`

Body :

```json
{
  "user": "jdupont",
  "enabled": true
}
```

### `POST /admin/enableUser`

Alias lisible de `setUserEnabled` pour activer un compte.

### `POST /admin/disableUser`

Alias lisible de `setUserEnabled` pour désactiver un compte.

### `POST /admin/unlockUser`

Body :

```json
{
  "user": "jdupont"
}
```

Codes typiques pour les endpoints admin utilisateur :

- `200` : opération réussie
- `400` : body invalide ou erreur LDAP métier
- `404` : utilisateur ou destination introuvable
- `500` : erreur serveur

## Administration des groupes

### `POST /admin/createGroup`

Body :

```json
{
  "OuDn": "OU=Groups,DC=example,DC=local",
  "Cn": "Equipe Support",
  "Sam": "EquipeSupport",
  "Scope": "Global",
  "SecurityEnabled": true,
  "Description": "Groupe Support"
}
```

### `POST /admin/addToGroup`

Body :

```json
{
  "user": "jdupont",
  "groupDn": "EquipeSupport"
}
```

### `POST /admin/removeFromGroup`

Body :

```json
{
  "user": "jdupont",
  "groupDn": "EquipeSupport"
}
```

### `DELETE /admin/deleteGroup`

Ou `POST /admin/deleteGroup` avec un body JSON.

Body accepte l'un des formats suivants :

```json
{
  "dn": "CN=Equipe Support,OU=Groups,DC=example,DC=local"
}
```

ou

```json
{
  "group": "EquipeSupport"
}
```

Codes typiques :

- `200` : operation reussie
- `400` : parametre ou operation LDAP invalide
- `404` : groupe introuvable
- `500` : erreur serveur

## Administration des OU

### `POST /admin/ou/create`

Body :

```json
{
  "ParentDn": "OU=Users,DC=example,DC=local",
  "Name": "Prestataires",
  "Description": "OU des prestataires",
  "Protected": true
}
```

Quand `Protected=true`, l'API marque l'OU avec `adminDescription="API_PROTECTED=1"`.

### `POST /admin/ou/update`

Body :

```json
{
  "OuDn": "OU=Prestataires,OU=Users,DC=example,DC=local",
  "NewName": "Prestataires Externes",
  "Description": "OU renommee",
  "Protected": true,
  "NewParentDn": "OU=RH,DC=example,DC=local"
}
```

Notes :

- `Description = null` ne modifie pas le champ
- `Description = ""` supprime la description
- `NewParentDn` doit rester sous `BaseDn`

### `POST /admin/ou/delete`

Body :

```json
{
  "OuDn": "OU=Prestataires,OU=Users,DC=example,DC=local"
}
```

Conditions :

- l'OU doit être sous `BaseDn`
- l'OU doit être vide
- l'OU ne doit pas être protégée

Codes typiques :

- `200` : suppression réussie
- `403` : OU hors périmètre ou protégée
- `404` : OU introuvable
- `409` : OU non vide
- `500` : erreur serveur

## Codes d'erreur usuels

- `400` : validation ou opération LDAP invalide
- `401` : échec d'authentification utilisateur
- `403` : IP non autorisée, secret interne manquant ou opération interdite
- `404` : ressource introuvable
- `409` : conflit, par exemple OU non vide
- `500` : erreur serveur ou bind LDAP impossible
