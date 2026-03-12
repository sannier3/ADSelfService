# Options de configuration

Ce document reference les options lues par l'API dans `config.json`.

## Comment la configuration est chargee

- Si `config.json` n'existe pas dans le dossier du binaire, l'application cree automatiquement un `config.json` par defaut puis s'arrete.

Pour un demarrage depuis les sources, vous pouvez aussi partir du fichier `config.example.json`.

## Exemple minimal

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 636,
    "Ssl": true,
    "UseKerberosSealing": false,
    "IgnoreCertificate": false,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "mot-de-passe-a-remplacer",
    "BaseDn": "OU=Users,DC=example,DC=local",
    "GroupBaseDn": "DC=example,DC=local",
    "RootDn": "DC=example,DC=local",
    "AdminGroupDn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local"
  },
  "Security": {
    "AllowedIps": [ "127.0.0.1", "::1", "192.168.1.0/24" ],
    "InternalSharedSecret": null
  },
  "Server": {
    "Urls": [ "http://0.0.0.0:5000" ]
  }
}
```

## Section `Ldap`

Cette section pilote la connexion a Active Directory.

| Option | Type | Description |
|--------|------|-------------|
| `Url` | `string` | Nom du controleur de domaine. En mode Kerberos sur le port `389`, utilisez obligatoirement le FQDN. |
| `Port` | `int` | `389` pour LDAP ou LDAP + Kerberos, `636` pour LDAPS. |
| `Ssl` | `bool` | `true` pour LDAPS, `false` pour LDAP. |
| `UseKerberosSealing` | `bool` | Active Sign & Seal en LDAP non TLS pour permettre notamment les changements de mot de passe sur le port `389`. Ignore en LDAPS. |
| `IgnoreCertificate` | `bool` | Ignore la validation du certificat en LDAPS. Reserve au labo ou au developpement. |
| `BindDn` | `string` | Identifiant du compte de service LDAP. Format recommande : `user@domaine.local` ou `DOMAINE\user`. |
| `BindPassword` | `string` | Mot de passe du compte de service. |
| `BaseDn` | `string` | DN de base pour les recherches utilisateur. |
| `GroupBaseDn` | `string` | DN de base pour les recherches de groupes. |
| `RootDn` | `string` | DN racine du domaine. |
| `AdminGroupDn` | `string` | Groupe AD considere comme groupe administrateur par la logique metier de l'API. |

Voir aussi [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md).

## Section `Debug`

Cette section regle les journaux de l'application.

| Option | Type | Description |
|--------|------|-------------|
| `Enabled` | `bool` | Active les logs detailles des requetes et reponses. |
| `ShowPasswords` | `bool` | Affiche les mots de passe dans certains logs de debug. Laissez `false` en production. |
| `LogDir` | `string` | Dossier de sortie des fichiers de logs. |
| `Console` | `bool` | Affiche aussi les logs dans la console. |

## Section `Security`

Cette section controle qui peut appeler l'API.

| Option | Type | Description |
|--------|------|-------------|
| `AllowedIps` | `string[]` | Liste d'IP ou de plages CIDR autorisees. Toute autre origine recoit une reponse `403`. |
| `InternalSharedSecret` | `string?` | Secret optionnel compare a l'en-tete `X-Internal-Auth`. Si renseigne, tous les appels sauf `/health` doivent fournir cette valeur exacte. |

Important :

- Ce filtrage s'applique au niveau HTTP avant le traitement des endpoints.
- Les endpoints `/admin/*` doivent donc rester derriere ce perimetre reseau de confiance.

## Section `Pagination`

Cette section pilote `GET /users` et `GET /groups`.

| Option | Type | Description |
|--------|------|-------------|
| `Enabled` | `bool` | Active la pagination sur les endpoints de liste. |
| `PageSize` | `int` | Taille de page par defaut. Doit etre strictement positive. |

## Section `Server`

Cette section regle les URL d'ecoute Kestrel.

| Option | Type | Description |
|--------|------|-------------|
| `Urls` | `string[]` | Liste des URL a ecouter, par exemple `http://0.0.0.0:5000` ou `https://0.0.0.0:5001`. |

## Section `StartupCheck`

Cette section controle les verifications faites au demarrage.

| Option | Type | Description |
|--------|------|-------------|
| `Enabled` | `bool` | Active le test TCP LDAP puis le bind du compte de service au demarrage. |
| `FailFast` | `bool` | Si `true`, l'application s'arrete si le test ou le bind echoue. |
| `ShowDetailsInConsole` | `bool` | Ajoute le detail de l'exception dans la console en cas d'echec de startup check. |

## Recommandations

- En production, preferez `Ssl=true` et `Port=636`.
- Si vous restez en `389`, activez `UseKerberosSealing=true`.
- Gardez `IgnoreCertificate=false` hors environnement de test.
- Restreignez `AllowedIps` au serveur PHP, au reverse proxy ou aux outillages internes.
- Ne versionnez jamais `config.json` ou toute variante contenant de vrais secrets.
