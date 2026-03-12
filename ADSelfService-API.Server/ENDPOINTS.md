ok, voilà la doc d’API complète extraite de ton code — endpoints, méthodes, paramètres (query + body) et réponses (succès/erreurs). Tout est JSON. Sécurité : **autorisation par liste d’IP** uniquement (middleware `IsIpAllowed`), pas de token.

# Santé

**GET `/health`**
200 → `{ "status": "ok" }` (bind LDAP OK)
500 → service indisponible

---

# Authentification & profil

**POST `/auth`**
Body → `{ "username": string, "password": string }`
200 →

```json
{
  "success": true,
  "user": {
    "dn": "...",
    "sAMAccountName": "...",
    "givenName": "...",
    "sn": "...",
    "mail": "...",
    "memberOf": [ "CN1", "CN2", ... ],               // groupes directs (CN)
    "memberOfEffective": [ "CNx", ... ],             // directs + imbriqués + primaire
    "objectGUID": "guid-or-null",
    "telephoneNumber": "...",
    "wwwhomepage": "...",
    "streetAddress": "..."
  },
  "mustChangePassword": bool,
  "isAdmin": bool
}
```

401 → utilisateur introuvable ou mot de passe invalide/expiré
403 → compte désactivé
500 → échec bind LDAP / erreur serveur

**GET `/user/{sam}`**
Path → `{sam}` = sAMAccountName
200 → objet utilisateur (comme ci-dessus) + `mustChangePassword`, `isAdmin`, `disabled`
404 → introuvable
500 → erreur

**POST `/user/updateProfile`**
Body → `{ "dn": string, "modifications": { "<attr>": string|null|"" , ... } }`

> Valeur `null` ou `""` ⇒ suppression de l’attribut.
> 200 → `{ "success": true }`
> 400/500 → erreur

**POST `/user/changePassword`**
Body → `{ "username": string, "currentPassword": string, "newPassword": string }`
200 → `{ "success": true }`
401 → `currentPassword` invalide
404 → utilisateur introuvable
500 → erreur

---

# Admin — Mots de passe & état

**POST `/admin/changePassword`**
Body → `{ "username": string, "newPassword": string, "mustChangeAtNextLogon": bool? }`
200 → `{ "success": true }`
404 → introuvable
500 → erreur / impossible de définir `pwdLastSet`

**POST `/admin/setUserEnabled`**
Body → `{ "user": "<sAM|DN>", "enabled": bool }`
200 → `{ "success": true, "dn": "...", "enabled": bool }`
404/500 → erreur

**POST `/admin/enableUser`** *(alias clair)*
Body → `{ "user": "<sAM|DN>" }`
200 → `{ "success": true, "dn": "...", "enabled": true }`

**POST `/admin/disableUser`** *(alias clair)*
Body → `{ "user": "<sAM|DN>" }`
200 → `{ "success": true, "dn": "...", "enabled": false }`

**POST `/admin/unlockUser`**
Body → `{ "user": "<sAM|DN>" }`
200 → `{ "success": true }` (ou `note: "Compte déjà déverrouillé."`)
404/400/500 → erreur

---

# Admin — Comptes utilisateurs (CRUD, groupes, déplacement, renommage)

**POST `/admin/createUser`**
Body →

```json
{
  "OuDn": "OU=...,DC=...",
  "Cn": "Nom affiché",
  "Sam": "login",
  "GivenName": "Prénom",
  "Sn": "Nom",
  "UserPrincipalName": "user@domaine",
  "Mail": "user@exemple.tld",               // optional
  "Password": "xxxx",
  "Enabled": true,                          // default: true (créé désactivé puis activé si true)
  "Description": "..." ,                    // optional
  "ExpiresAt": "2025-12-31T23:59:59Z",     // optional (ISO 8601)
  "NeverExpires": false                     // optional
}
```

200 → `{ "success": true, "dn": "CN=...,OU=..." }`
400 → erreur annuaire (ex. doublon)
500 → erreur

**POST `/admin/deleteUser`**
Body → `{ "user": "<sAM|DN>" }`
200 → `{ "success": true, "dn": "..." }`
404/400/500 → erreur

**POST `/admin/addToGroup`**
Body → `{ "user": "<sAM|DN>", "groupDn": "<DN|CN|sAM|name>" }`

> `groupDn` est résolu automatiquement par DN/CN/sAM/name.
> 200 → `{ "success": true }` (ou `note: "Déjà membre du groupe."`)
> 404/400/500 → erreur

**POST `/admin/removeFromGroup`**
Body → `{ "user": "<sAM|DN>", "groupDn": "<DN|CN|sAM|name>" }`
200 → `{ "success": true }` (ou `note: "L’utilisateur n’était pas membre du groupe."`)
404/400/500 → erreur

**POST `/admin/updateUser`**
Body → `{ "user": "<sAM|DN>", "attributes": { "<attr>": string|null|"" , ... } }`
200 → `{ "success": true, "dn": "..." }`
404/400/500 → erreur

**POST `/admin/moveUser`**
Body → `{ "user": "<sAM|DN>", "newOuDn": "OU=...,DC=..." }`
200 → `{ "success": true, "dn": "CN=...,<newOuDn>" }`
404 → utilisateur ou OU cible introuvable
400/500 → erreur

**POST `/admin/renameUserCn`**
Body → `{ "user": "<sAM|DN>", "newCn": "Nouveau CN" }`
200 → `{ "success": true, "newDn": "CN=Nouveau CN,..." }`
404/400/500 → erreur

**POST `/admin/setAccountExpiration`**
Body → `{ "user": "<sAM|DN>", "expiresAt": "ISO8601"?, "never": true|false? }`

> Requis : `user` et (`never=true` **ou** `expiresAt`).
> 200 → `{ "success": true, "dn": "...", "expiresNever": bool, "expiresAt": "..."? }`
> 404/400/500 → erreur

---

# Groupes

**GET `/groups`**
Query →

* `baseDn` (optionnel; défaut = `GroupBaseDn` ou `RootDn`)
* `search` (filtre sur `cn` ou `sAMAccountName`)
* `page`, `pageSize` (si pagination activée)
  200 → `[{ "id": "guid-or-null", "name": "CN", "dn": "...", "sam": "..." }, ... ]`
  Headers pagination → `X-Page`, `X-Page-Size`, `X-Has-More`
  500 → erreur

**DELETE|POST `/admin/deleteGroup`**
Body → `{ "dn": "<DN>" }` **ou** `{ "group": "<DN|CN|sAM|name>" }`
200 → `{ "success": true, "dn": "..." }`
404/400/500 → erreur

**POST `/admin/createGroup`**
Body →

```json
{
  "OuDn": "OU=...,DC=...",
  "Cn": "Nom du groupe",
  "Sam": "samOptionnel",
  "Scope": "Global|DomainLocal|Universal",  // default: Global
  "SecurityEnabled": true,                  // default: true
  "Description": "..."                      // optional
}
```

200 → `{ "success": true, "dn": "CN=...,OU=..." }`
404/400/500 → erreur

---

# OU (Organizational Units)

**POST `/admin/ou/create`**
Body → `{ "ParentDn": "OU|CN|DC=...", "Name": "Nom OU", "Description": "..."?, "Protected": true|false? }`

> `ParentDn` doit être sous `BaseDn`. `Protected` ajoute `adminDescription="API_PROTECTED=1"`.
> 200 → `{ "success": true, "dn": "OU=Name,<ParentDn>" }`
> 403/404/400/500 → erreur

**POST `/admin/ou/update`**
Body → `{ "OuDn": "OU=...,DC=...", "NewName": "..."?, "Description": ""|string|null?, "Protected": true|false? }`

> `Description: ""` supprime, `null` ne touche pas.
> 200 → `{ "success": true, "dn": "<nouveau-ou-ancien DN>" }`
> 403/404/400/500 → erreur

**POST `/admin/ou/delete`**
Body → `{ "OuDn": "OU=...,DC=..." }`

> Doit être sous `BaseDn`, **vide** et **non protégée**.
> 200 → `{ "success": true, "dn": "..." }`
> 403 → protégée ou hors périmètre
> 409 → non vide
> 404/400/500 → erreur

---

# Arborescence annuaire

**GET `/tree`**
Query →

* `baseDn` (défaut = `BaseDn` sinon `RootDn`)
* `depth` (1–10, défaut 3)
* `includeLeaves` (bool, défaut false)
* `maxChildren` (défaut 200, max 2000)
  200 →

```json
{
  "baseDn": "...",
  "depth": 3,
  "includeLeaves": false,
  "maxChildren": 200,
  "nodes": [
    { "name": "...", "dn": "...", "type": "ou|group|user|computer|container|domain|other", "hasChildren": true, "children": [ ... ] }
  ]
}
```

500 → erreur

---

# Liste / recherche d’utilisateurs

**GET `/users`**
Query →

* `includeBuiltins` (bool, défaut false) — exclut Guest si false
* `groups` = `none` | `direct` | `effective` (défaut `direct`)
* `page`, `pageSize` (si pagination activée)
  200 → `[{ dn, sAMAccountName, givenName, sn, mail, telephoneNumber, wwwhomepage, streetAddress, objectGUID, disabled, memberOf?, memberOfEffective? }, ...]`
  Headers pagination → `X-Page`, `X-Page-Size`, `X-Has-More`
  500 → erreur

---

# Notes communes

* **Identification user** : beaucoup d’endpoints acceptent **sAMAccountName ou DN** (`user` ou `User`).
* **Groupes** : `groupDn` peut être DN, **CN**, **sAMAccountName** ou `name` (résolution côté serveur).
* **Dates d’expiration** : côté AD c’est `accountExpires` (FILETIME). L’API accepte `expiresAt` en **ISO 8601** et `never=true`.
* **Pagination** : si activée dans la conf, en **GET** `/users` et `/groups` — en-têtes `X-Page`, `X-Page-Size`, `X-Has-More`.
* **Masquage logs** : mots de passe masqués par défaut.
* **Codes d’erreur typiques** : `400` (validation/LDAP op), `401` (auth ratée), `403` (accès/compte/OU interdit), `404` (introuvable), `409` (conflit OU non vide), `500` (bind LDAP/exception).

Si tu veux, je te fais un **OpenAPI (Swagger) YAML** prêt à coller, à partir de ce mapping.
