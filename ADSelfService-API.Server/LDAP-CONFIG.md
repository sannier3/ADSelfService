# Connexion LDAP

L'API peut se connecter a Active Directory de deux facons :

- `LDAPS` sur le port `636`
- `LDAP + Kerberos` sur le port `389`

Le choix depend surtout de votre infrastructure. Si vous avez un doute, choisissez `LDAPS`.

## Recommandation rapide

| Scenario | Recommandation |
|----------|----------------|
| vous avez des certificats AD valides et le port 636 ouvert | utilisez `LDAPS` |
| vous ne pouvez pas activer LDAPS mais votre serveur peut utiliser Kerberos | utilisez `LDAP + Kerberos` |
| vous avez seulement du LDAP simple non securise | non recommande pour cette API |

## Option 1. LDAPS

`LDAPS` est le mode recommande en production.

### Quand l'utiliser

- vous pouvez joindre le controleur de domaine en `636`
- le certificat du controleur est valide ou acceptable dans votre environnement
- vous voulez un transport TLS classique

### Reglages attendus

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 636,
    "Ssl": true,
    "UseKerberosSealing": false,
    "IgnoreCertificate": false,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "mot-de-passe"
  }
}
```

### Notes importantes

- `Url` peut etre un FQDN ou une IP, mais le FQDN reste preferable.
- `BindDn` doit idealement etre au format `user@domaine.local` ou `DOMAINE\user`.
- Evitez un DN complet du type `CN=...,OU=...` pour `BindDn`.
- `IgnoreCertificate=true` n'est a utiliser qu'en environnement de test.

## Option 2. LDAP + Kerberos

Ce mode permet de rester sur le port `389` tout en utilisant Kerberos avec Sign & Seal.

### Quand l'utiliser

- vous ne pouvez pas activer LDAPS
- le serveur qui heberge l'API peut obtenir des tickets Kerberos
- vous avez besoin de changements de mot de passe sans passer par TLS

### Reglages attendus

```json
{
  "Ldap": {
    "Url": "dc01.example.local",
    "Port": 389,
    "Ssl": false,
    "UseKerberosSealing": true,
    "IgnoreCertificate": true,
    "BindDn": "svc-adselfservice@example.local",
    "BindPassword": "mot-de-passe"
  }
}
```

### Notes importantes

- `Url` doit etre le FQDN du controleur de domaine, pas son IP.
- `BindDn` doit etre au format `user@domaine.local` ou `DOMAINE\user`.
- La machine ou le compte de service doit etre correctement integre dans l'environnement Kerberos.
- Sans `UseKerberosSealing=true`, certaines operations sensibles comme le changement de mot de passe peuvent etre refusees.

## Symptomes frequents

| Probleme | Cause probable |
|----------|----------------|
| `The supplied credential is invalid (49)` avec un bon mot de passe | `BindDn` fourni sous forme de DN complet au lieu d'un UPN ou `DOMAIN\user` |
| echec de connexion sur `389` | FQDN incorrect, SPN non resolu, ou Kerberos indisponible |
| changement de mot de passe refuse | utilisation de LDAP non chiffre sans Kerberos sealing |
| echec de startup check | port bloque, certificat invalide, bind incorrect, ou AD inaccessible |

## Conseils pratiques

- Testez toujours en console avant d'installer le service Windows.
- Si vous utilisez `LDAPS`, commencez avec `IgnoreCertificate=false`.
- Si vous utilisez Kerberos, verifiez d'abord la resolution DNS du FQDN du controleur.
- Gardez les vrais DN de travail dans `BaseDn`, `GroupBaseDn` et `RootDn`, pas dans `BindDn`.
