# Options de configuration (config.json)

Copiez `config.example.json` vers `config.json` puis adaptez les valeurs. Référence des options :

## Ldap

| Option | Type | Description |
|--------|------|-------------|
| **Url** | string | FQDN du contrôleur de domaine (ex. `dc01.domaine.local`). Pour Kerberos : **obligatoirement le FQDN**, pas l’IP. |
| **Port** | int | `389` (LDAP / Kerberos) ou `636` (LDAPS). |
| **Ssl** | bool | `true` = LDAPS (port 636), `false` = LDAP (port 389). |
| **UseKerberosSealing** | bool | Si `Ssl` = false : `true` active Sign & Seal Kerberos (permet les changements de mot de passe sur port 389). Ignoré en LDAPS. |
| **IgnoreCertificate** | bool | En LDAPS : `true` pour accepter un certificat non validé (dév / labo). À mettre à `false` en production. |
| **BindDn** | string | Compte de connexion LDAP. Kerberos : format UPN (`user@domaine.local`) ou `DOMAINE\user`. LDAPS : DN ou UPN. |
| **BindPassword** | string | Mot de passe du compte BindDn. |
| **BaseDn** | string | DN de base pour la recherche des **utilisateurs** (ex. `OU=Users,DC=domaine,DC=local`). |
| **GroupBaseDn** | string | DN de base pour la recherche des **groupes** (souvent `DC=domaine,DC=local` ou `CN=Users,...`). |
| **RootDn** | string | DN racine du domaine (ex. `DC=domaine,DC=local`). |
| **AdminGroupDn** | string | DN du groupe AD dont les membres sont considérés comme administrateurs par l’API (ex. `CN=ADSyncAdmins,CN=Users,DC=domaine,DC=local`). |

Voir aussi `ADSelfService-API.Server/LDAP-CONFIG.md` pour LDAPS vs LDAP + Kerberos.

---

## Debug

| Option | Type | Description |
|--------|------|-------------|
| **Enabled** | bool | Active les logs de niveau Debug. |
| **ShowPasswords** | bool | **À garder à false en production.** Inclut les mots de passe dans les logs en cas d’erreur. |
| **LogDir** | string | Dossier des fichiers de log (ex. `logs`). |
| **Console** | bool | Écrit aussi les logs sur la console. |

---

## Security

| Option | Type | Description |
|--------|------|-------------|
| **AllowedIps** | string[] | Liste des IP ou CIDR autorisées à appeler l’API (ex. `127.0.0.1`, `::1`, `192.168.1.0/24`). Toute autre IP reçoit 403. |

---

## Pagination

| Option | Type | Description |
|--------|------|-------------|
| **Enabled** | bool | Active la pagination sur les endpoints `GET /users` et `GET /groups`. |
| **PageSize** | int | Nombre d’éléments par page (ex. `200`). |

---

## Server

| Option | Type | Description |
|--------|------|-------------|
| **Urls** | string[] | URLs d’écoute Kestrel (ex. `http://0.0.0.0:5000`, `https://0.0.0.0:5001`). |

---

## StartupCheck

| Option | Type | Description |
|--------|------|-------------|
| **Enabled** | bool | Au démarrage, tente un bind LDAP ; si échec, log (et arrêt si FailFast). |
| **FailFast** | bool | Si `true` et bind LDAP en échec au démarrage, l’application s’arrête. |
| **ShowDetailsInConsole** | bool | Affiche le détail de l’échec du bind dans la console au démarrage. |
