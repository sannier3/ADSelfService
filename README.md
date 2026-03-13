# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-blue.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-lightgrey.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` est une solution intranet open source pour Active Directory.
Elle fournit un parcours utilisateur simple, une administration centralisée pour l'IT, et un cadre de sécurité strict côté API et côté client web.

## Vue d'ensemble

Le projet contient deux composants principaux :

- `ADSelfService-API.Server` : API .NET 8 pour authentifier et administrer Active Directory.
- `WEB-CLIENT-PHP` : client intranet PHP pour les parcours utilisateur et administrateur.

## Fonctionnalités principales

- Authentification AD (`POST /auth`).
- Consultation et mise à jour du profil utilisateur.
- Changement de mot de passe utilisateur.
- Réinitialisation de mot de passe via un flux dédié.
- Administration des comptes AD : création, modification, suppression, activation, désactivation, déblocage, renommage, déplacement, expiration.
- Administration des groupes et des membres.
- Administration des OU (création, mise à jour, suppression).
- Explorateur AD et recherche d'objets.
- Accès aux outils filtré selon les droits utilisateur.

## Sécurité obligatoire

Le comportement actuel du code impose :

- Filtrage des appels via `Security.AllowedIps`.
- Clé partagée interne obligatoire et robuste : `Security.InternalSharedSecret`.
- En-tête de contexte applicatif requis sur les routes sensibles : `X-App-Context`.
- Transport LDAP protégé obligatoire :
  - `Ldap.Ssl=true` (LDAPS), ou
  - `Ldap.UseKerberosSealing=true` (LDAP + Kerberos sealing).
- `Debug.ShowPasswords=true` interdit.

Si ces contraintes ne sont pas respectées, l'API peut refuser de démarrer ou rejeter les appels.

## Séparation des rôles

- **Utilisateur standard** : profil, mot de passe, outils autorisés.
- **Admin utilisateurs** : gestion des comptes et appartenances.
- **Admin domaine** : actions avancées (OU, groupes, explorateur AD).

Le client PHP filtre l'interface selon le rôle, et l'API applique aussi les contrôles côté serveur.

## Installation rapide

### Option 1 — Depuis une release (recommandé)

1. Télécharger les archives depuis [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Déployer `ADSelfService-API-Server.zip` sur l'hôte API.
3. Lancer `ADSelfService-API.Server.exe` une première fois pour générer `config.json`.
4. Compléter `config.json` (LDAP, sécurité, écoute serveur).
5. Redémarrer l'API puis vérifier `GET /health`.
6. Déployer `ADSelfService-WEBSERVER-Files.zip` sur l'hôte web.
7. Créer `WEB-CLIENT-PHP/config-intranet.php` depuis `config-intranet-default.php`.
8. Vérifier la cohérence entre `API_BASE` et `INTERNAL_SHARED_SECRET`.

### Option 2 — Construire depuis le code source

```bash
git clone <url-du-repo>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Conseils production

- Ne pas exposer directement l'API sur Internet public.
- Garder `AllowedIps` au plus strict.
- Utiliser un secret long, unique et non réutilisé.
- Préférer LDAPS en production.
- Activer le debug uniquement pour diagnostic ponctuel.
- Ne jamais versionner les fichiers de configuration sensibles.

## Vérifications après déploiement

1. `GET /health` retourne `200`.
2. Connexion utilisateur fonctionnelle.
3. Changement de mot de passe fonctionnel.
4. Réinitialisation de mot de passe fonctionnelle.
5. Outils correctement filtrés selon les droits.
6. Actions admin visibles et effectives selon le rôle.
7. Recherches AD cohérentes avec `BaseDn`, `GroupBaseDn` et `RootDn`.

## Dépannage rapide

| Problème | Vérification prioritaire |
|---|---|
| `403` sur les appels API | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API ne démarre pas | `config.json` invalide/incomplet, contrainte sécurité non respectée |
| Échec LDAP bind | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, DNS/réseau |
| Changement de mot de passe refusé | vérifier LDAPS ou Kerberos sealing |
| Client PHP bloqué | `config-intranet.php`, `API_BASE`, secret partagé |

## Endpoints clés

- `GET /health` : état API + bind LDAP.
- `POST /auth` : authentification AD.
- `POST /user/changePassword` : changement de mot de passe utilisateur.
- `POST /user/updateProfile` : mise à jour du profil utilisateur.
- `GET /tree` : arborescence AD.
- `GET /users`, `GET /groups` : vues de base.
- `POST /admin/*` et `GET/POST /explorer/*` : administration avancée selon le rôle et le contexte.

## Documentation associée

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)
