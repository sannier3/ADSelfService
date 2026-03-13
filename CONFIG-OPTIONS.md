# Options de configuration (`config.json`)

Ce document décrit les options lues par `ADSelfService-API.Server` et les contraintes réellement appliquées au démarrage.

## Chargement de la configuration

- Si `config.json` n'existe pas à côté du binaire, l'application crée un fichier par défaut puis s'arrête.
- Vous devez ensuite compléter ce fichier avant redémarrage.

## Exemple de base (à adapter)

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
    "BaseDn": "OU=Infra,DC=example,DC=local",
    "GroupBaseDn": "DC=example,DC=local",
    "RootDn": "DC=example,DC=local",
    "AdminGroupDn": "CN=ADSyncAdmins,CN=Users,DC=example,DC=local"
  },
  "Security": {
    "AllowedIps": ["127.0.0.1", "::1", "192.168.1.0/24"],
    "InternalSharedSecret": "secret-long-et-unique-32-caracteres-minimum",
    "RequireAppContextHeader": true
  },
  "Debug": {
    "Enabled": false,
    "ShowPasswords": false,
    "LogDir": "logs",
    "Console": true
  },
  "Pagination": {
    "Enabled": true,
    "PageSize": 200
  },
  "Server": {
    "Urls": ["http://0.0.0.0:5001"]
  },
  "StartupCheck": {
    "Enabled": true,
    "FailFast": false,
    "ShowDetailsInConsole": true
  }
}
```

## Section `Ldap`

| Option | Type | Description |
|---|---|---|
| `Url` | `string` | Contrôleur de domaine. En Kerberos sur `389`, utilisez le FQDN. |
| `Port` | `int` | `389` (LDAP/Kerberos) ou `636` (LDAPS). |
| `Ssl` | `bool` | Active LDAPS. |
| `UseKerberosSealing` | `bool` | Active Sign & Seal en LDAP non TLS. |
| `IgnoreCertificate` | `bool` | Ignore la validation TLS LDAPS (tests uniquement). |
| `BindDn` | `string` | Compte de service LDAP (`user@domaine` ou `DOMAINE\\user` recommandé). |
| `BindPassword` | `string` | Mot de passe du compte de service. |
| `BaseDn` | `string` | Base de recherche utilisateurs/explorateur. |
| `GroupBaseDn` | `string` | Base de recherche groupes. |
| `RootDn` | `string` | Racine de domaine. |
| `AdminGroupDn` | `string` | Groupe AD de référence admin logique. |

### Règle de sécurité importante

Au moins un mode de transport protégé doit être actif:

- `Ssl=true`, ou
- `UseKerberosSealing=true`.

Sinon, la configuration est rejetée au démarrage.

## Section `Security`

| Option | Type | Description |
|---|---|---|
| `AllowedIps` | `string[]` | IP/plages CIDR autorisées à appeler l'API. |
| `InternalSharedSecret` | `string` | Clé partagée interne. Doit être robuste. |
| `RequireAppContextHeader` | `bool` | Exige le header `X-App-Context` (recommandé: `true`). |

### Contraintes appliquées

- Si `InternalSharedSecret` est défini avec moins de 32 caractères, démarrage refusé.
- Les appels hors `/health` doivent fournir `X-Internal-Auth` si la clé est configurée.
- Les appels sensibles sont filtrés par contexte applicatif (`X-App-Context`) quand `RequireAppContextHeader=true`.

## Section `Debug`

| Option | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Active les logs détaillés requêtes/réponses. |
| `ShowPasswords` | `bool` | Affichage des mots de passe en logs. |
| `LogDir` | `string` | Dossier des logs. |
| `Console` | `bool` | Sortie console des logs. |

### Interdiction

- `ShowPasswords=true` est refusé par validation configuration.

## Section `Pagination`

| Option | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Active la pagination des listes API. |
| `PageSize` | `int` | Taille de page par défaut, strictement positive. |

## Section `Server`

| Option | Type | Description |
|---|---|---|
| `Urls` | `string[]` | URLs d'écoute Kestrel. |

## Section `StartupCheck`

| Option | Type | Description |
|---|---|---|
| `Enabled` | `bool` | Teste connectivité LDAP + bind au démarrage. |
| `FailFast` | `bool` | Arrête l'application si le test échoue. |
| `ShowDetailsInConsole` | `bool` | Affiche le détail des erreurs en console. |

## Obligatoire / Interdit (résumé)

### Obligatoire

- `InternalSharedSecret` cohérent côté API et client PHP.
- `AllowedIps` strict.
- LDAP protégé (`Ssl=true` ou `UseKerberosSealing=true`).

### Interdit

- `Debug.ShowPasswords=true`.
- Modes LDAP non protégés (ni SSL, ni Kerberos sealing).

## Références utiles

- [README.md](README.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
