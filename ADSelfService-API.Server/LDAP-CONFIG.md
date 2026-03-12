# Connexion LDAP

L'API peut se connecter à Active Directory de deux façons :

- `LDAPS` sur le port `636`
- `LDAP + Kerberos` sur le port `389`

Le choix dépend surtout de votre infrastructure. Si vous avez un doute, choisissez `LDAPS`.

## Recommandation rapide

| Scénario | Recommandation |
|----------|----------------|
| vous avez des certificats AD valides et le port 636 ouvert | utilisez `LDAPS` |
| vous ne pouvez pas activer LDAPS mais votre serveur peut utiliser Kerberos | utilisez `LDAP + Kerberos` |
| vous avez seulement du LDAP simple non sécurisé | non recommandé pour cette API |

## Option 1. LDAPS

`LDAPS` est le mode recommandé en production.

### Quand l'utiliser

- vous pouvez joindre le contrôleur de domaine en `636`
- le certificat du controleur est valide ou acceptable dans votre environnement
- vous voulez un transport TLS classique

### Réglages attendus

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

- `Url` peut être un FQDN ou une IP, mais le FQDN reste préférable.
- `BindDn` doit idéalement être au format `user@domaine.local` ou `DOMAINE\user`.
- Évitez un DN complet du type `CN=...,OU=...` pour `BindDn`.
- `IgnoreCertificate=true` n'est à utiliser qu'en environnement de test.

## Option 2. LDAP + Kerberos

Ce mode permet de rester sur le port `389` tout en utilisant Kerberos avec Sign & Seal.

### Quand l'utiliser

- vous ne pouvez pas activer LDAPS
- le serveur qui héberge l'API peut obtenir des tickets Kerberos
- vous avez besoin de changements de mot de passe sans passer par TLS

### Réglages attendus

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

- `Url` doit être le FQDN du contrôleur de domaine, pas son IP.
- `BindDn` doit être au format `user@domaine.local` ou `DOMAINE\user`.
- La machine ou le compte de service doit être correctement intégrée dans l'environnement Kerberos.
- Sans `UseKerberosSealing=true`, certaines opérations sensibles comme le changement de mot de passe peuvent être refusées.

## Symptômes fréquents

| Problème | Cause probable |
|----------|----------------|
| `The supplied credential is invalid (49)` avec un bon mot de passe | `BindDn` fourni sous forme de DN complet au lieu d'un UPN ou `DOMAIN\user` |
| échec de connexion sur `389` | FQDN incorrect, SPN non résolu, ou Kerberos indisponible |
| changement de mot de passe refusé | utilisation de LDAP non chiffré sans Kerberos sealing |
| échec de startup check | port bloqué, certificat invalide, bind incorrect, ou AD inaccessible |

## Conseils pratiques

- Testez toujours en console avant d'installer le service Windows.
- Si vous utilisez `LDAPS`, commencez avec `IgnoreCertificate=false`.
- Si vous utilisez Kerberos, vérifiez d'abord la résolution DNS du FQDN du contrôleur.
- Gardez les vrais DN de travail dans `BaseDn`, `GroupBaseDn` et `RootDn`, pas dans `BindDn`.
