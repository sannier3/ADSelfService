# Configuration LDAP — LDAPS ou LDAP + Kerberos

L’API supporte deux modes pour parler à Active Directory de manière sécurisée :

## 1. LDAPS (recommandé en production)

- **Port** : 636  
- **config.json** : `"Ssl": true`, `"Port": 636`  
- **Url** : FQDN du contrôleur de domaine (ex. `dc01.domaine.local`) ou IP.  
- **BindDn** : utiliser de préférence un format **UPN** (`utilisateur@domaine.local`) ou **Down-Level** (`DOMAINE\utilisateur`).  
  - Avec l’authentification `Negotiate` (valeur utilisée par l’API en LDAPS), un DN complet (`CN=...,OU=...`) peut provoquer `The supplied credential is invalid (code 49)` même si le mot de passe est correct.  
- Connexion chiffrée TLS ; les changements de mot de passe sont autorisés.

## 2. LDAP + Kerberos (sans LDAPS)

Si vous ne pouvez pas utiliser LDAPS (port 636), vous pouvez utiliser le **port 389 avec Kerberos** (Sign & Seal). Les changements de mot de passe sont alors possibles grâce au chiffrement et à la signature des paquets.

- **Port** : 389  
- **config.json** :
  - `"Ssl": false`
  - `"Port": 389`
  - `"UseKerberosSealing": true` (valeur par défaut si absent)
  - **Url** : **obligatoirement le FQDN** du contrôleur (ex. `dc01.domaine.local`), **pas l’IP** (Kerberos utilise le SPN basé sur le nom de la machine).
  - **BindDn** : au format **UPN** (`utilisateur@domaine.local`) ou **Down-Level** (`DOMAINE\utilisateur`). Éviter un DN complet (`CN=...,OU=...`) pour que Kerberos fonctionne correctement.

Exemple pour LDAP + Kerberos :

```json
"Ldap": {
  "Url": "dc01.domaine.local",
  "Port": 389,
  "Ssl": false,
  "UseKerberosSealing": true,
  "BindDn": "administrateur@domaine.local",
  "BindPassword": "...",
  "BaseDn": "OU=Users,DC=domaine,DC=local",
  ...
}
```

Prérequis côté infrastructure : le serveur qui héberge l’API doit pouvoir obtenir des tickets Kerberos (domaine Windows ou machine jointe au domaine, ou compte de service configuré correctement).
