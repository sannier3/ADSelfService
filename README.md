# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-blue.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-lightgrey.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` est une solution intranet open source pour Active Directory, conçue pour offrir:

- une expérience simple et sûre pour les utilisateurs,
- une administration centralisée pour les équipes IT,
- un socle de sécurité strict côté API et côté client web.

## Vue d'ensemble

Le projet contient deux briques principales:

- `ADSelfService-API.Server` : API .NET 8 pour l'authentification et l'administration AD.
- `WEB-CLIENT-PHP` : client intranet PHP pour les parcours utilisateur et administrateur.

## Fonctionnalités principales

- Authentification AD (`POST /auth`).
- Consultation et mise à jour du profil utilisateur.
- Changement de mot de passe utilisateur.
- Flux de réinitialisation de mot de passe dédié.
- Administration des utilisateurs AD:
  - création, modification, suppression,
  - activation, désactivation, déblocage,
  - renommage, déplacement, expiration.
- Administration des groupes et des membres.
- Administration des OU (création, mise à jour, suppression).
- Explorateur AD et recherche d'objets.
- Accès aux outils filtré selon les droits de l'utilisateur.

## Sécurité mise en avant

Le comportement actuel du code impose un cadre clair:

- filtrage réseau via `Security.AllowedIps`,
- clé partagée interne (`InternalSharedSecret`) attendue et robuste,
- contexte applicatif (`X-App-Context`) contrôlé sur les routes sensibles,
- transport LDAP protégé requis:
  - LDAPS (`Ldap.Ssl=true`), ou
  - LDAP + Kerberos sealing (`Ldap.UseKerberosSealing=true`),
- `Debug.ShowPasswords=true` interdit.

## Séparation des usages

- **Utilisateur standard**: profil, mot de passe, outils autorisés.
- **Admin utilisateurs**: gestion des comptes et appartenances.
- **Admin domaine**: opérations avancées (OU, groupes, explorateur).

Le client PHP filtre l'interface et l'API applique également les contrôles côté serveur.

## Installation rapide

### Option 1 - Depuis une release (recommandé)

1. Télécharger les archives depuis [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Déployer `ADSelfService-API-Server.zip` sur l'hôte API.
3. Lancer `ADSelfService-API.Server.exe` une première fois pour générer `config.json`.
4. Compléter `config.json` (LDAP, sécurité, écoute serveur).
5. Redémarrer et vérifier `GET /health`.
6. Déployer `ADSelfService-WEBSERVER-Files.zip` côté web.
7. Créer `WEB-CLIENT-PHP/config-intranet.php` depuis `config-intranet-default.php`.
8. Vérifier la cohérence `API_BASE` + `INTERNAL_SHARED_SECRET`.

### Option 2 - Depuis le code source

```bash
git clone <url-du-repo>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Conseils pratiques

- N'exposez pas directement l'API sur Internet.
- Limitez `AllowedIps` aux serveurs internes nécessaires.
- Utilisez un secret long et unique pour `InternalSharedSecret`.
- Préférez LDAPS en production.
- N'activez les logs de debug qu'en diagnostic contrôlé.
- Ne versionnez jamais les fichiers de configuration sensibles.

## Checklist de validation

1. `GET /health` retourne `200`.
2. Connexion utilisateur fonctionnelle.
3. Changement de mot de passe utilisateur fonctionnel.
4. Réinitialisation de mot de passe fonctionnelle.
5. Outils correctement filtrés par droits.
6. Actions admin visibles et effectives selon le rôle.
7. Recherches AD cohérentes avec `BaseDn`, `GroupBaseDn` et `RootDn`.

## Dépannage rapide

| Problème | Vérification prioritaire |
|---|---|
| `403` sur les appels API | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| API qui ne démarre pas | `config.json` incomplet/invalide |
| Échec bind LDAP | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, DNS/réseau |
| Changement de mot de passe refusé | activer LDAPS ou Kerberos sealing |
| Client PHP bloqué au démarrage | `config-intranet.php`, `API_BASE`, secret partagé |

## Documentation liée

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-blue.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-lightgrey.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` est une solution intranet complète pour Active Directory:

- une API .NET 8 pour l'authentification et l'administration AD,
- un client PHP pour les utilisateurs et les administrateurs,
- un modèle sécurité strict (périmètre IP, clé partagée, contexte applicatif).

Le projet est open source, modifiable, et pensé pour être déployé rapidement sans perdre en contrôle.

## Pourquoi ADSelfService

- **Pour les utilisateurs:** accès uniquement aux actions et outils nécessaires (profil, mot de passe, outils autorisés).
- **Pour les administrateurs:** gestion centralisée des utilisateurs, groupes, OU, et exploration AD.
- **Pour les équipes IT:** code lisible, endpoints JSON clairs, configuration explicite.

## Composants

- `ADSelfService-API.Server`: API HTTP qui dialogue avec Active Directory.
- `WEB-CLIENT-PHP`: intranet PHP qui consomme l'API.

## Fonctionnalités principales

- Connexion utilisateur AD (`/auth`).
- Consultation et mise à jour du profil.
- Changement de mot de passe utilisateur.
- Réinitialisation de mot de passe (flux dédié et protégé).
- Administration des comptes AD:
  - création, suppression, activation, désactivation, déblocage,
  - renommage, déplacement, expiration.
- Administration des groupes et membres.
- Administration des OU (création, mise à jour, suppression).
- Explorateur AD avec recherche d'objets.
- Outils intranet visibles selon les droits utilisateur.

## Sécurité (obligatoire et non optionnelle)

Le comportement actuel du code impose un socle strict:

- `Security.AllowedIps` limite les origines autorisées.
- `Security.InternalSharedSecret` doit être défini et robuste.
- chaque appel API sensible doit fournir un `X-App-Context` valide.
- `/health` reste l'exception de contexte, mais reste filtré par IP.
- LDAP doit être protégé:
  - `Ldap.Ssl=true` (LDAPS),
  - ou `Ldap.UseKerberosSealing=true`.
- `Debug.ShowPasswords=true` est refusé.

Conséquence pratique: sans configuration sécurité correcte, le démarrage est bloqué.

## Séparation des rôles

- **Utilisateur standard:** profil, mot de passe, outils autorisés.
- **Admin utilisateurs:** opérations sur comptes et appartenances.
- **Admin domaine:** opérations avancées (OU, groupes, exploration domaine).

Le client PHP affiche les actions selon les droits, et l'API applique aussi des contrôles côté serveur.

## Démarrage rapide

### Option 1 - Installation depuis une release (recommandé)

1. Télécharger les archives depuis [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Déployer `ADSelfService-API-Server.zip` sur l'hôte API.
3. Lancer une première fois `ADSelfService-API.Server.exe` pour générer `config.json`.
4. Compléter `config.json` (LDAP, sécurité, URLs).
5. Redémarrer l'API et vérifier `GET /health`.
6. Déployer `ADSelfService-WEBSERVER-Files.zip` côté serveur web.
7. Créer `WEB-CLIENT-PHP/config-intranet.php` depuis `config-intranet-default.php`.
8. Vérifier la cohérence `API_BASE` + `INTERNAL_SHARED_SECRET`.

### Option 2 - Construire depuis le code source

```bash
git clone <url-du-repo>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Conseils de mise en production

- N'exposez jamais l'API directement sur Internet.
- Gardez `AllowedIps` minimal (serveurs internes seulement).
- Utilisez un secret long et unique pour `InternalSharedSecret`.
- Préférez LDAPS (`636`) avec certificat valide.
- Activez les logs debug uniquement pour diagnostiquer un incident.
- Ne versionnez jamais vos fichiers de configuration sensibles.

## Validation après installation

Checklist recommandée:

1. `GET /health` répond `200`.
2. Login utilisateur fonctionnel.
3. Changement de mot de passe utilisateur fonctionnel.
4. Flux mot de passe oublié fonctionnel (sans fuite d'information).
5. Outils utilisateur correctement filtrés.
6. Actions admin visibles et opérantes selon le bon rôle.
7. Recherches AD (utilisateurs/groupes/OU) cohérentes avec `RootDn` et `BaseDn`.

## Dépannage rapide

| Problème | Vérification prioritaire |
|---|---|
| `403` sur la plupart des appels | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| L'API ne démarre pas | `config.json` incomplet, valeurs interdites, secret absent/faible |
| Bind LDAP en échec | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, réseau |
| Changement mot de passe refusé | activer LDAPS ou Kerberos sealing |
| Le client PHP refuse de démarrer | `config-intranet.php`, secret, `API_BASE` |

## Documentation associée

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-blue.svg)](README.md) [![English](https://img.shields.io/badge/lang-English-lightgrey.svg)](README.en.md) ![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

`ADSelfService` est une solution intranet complète pour Active Directory:

- une API .NET 8 pour l'authentification et l'administration AD,
- un client PHP pour les utilisateurs et les administrateurs,
- un modèle sécurité strict (périmètre IP, clé partagée, contexte applicatif).

Le projet est open source, modifiable, et pensé pour être déployé rapidement sans perdre en contrôle.

## Pourquoi ADSelfService

- **Pour les utilisateurs:** accès uniquement aux actions et outils nécessaires (profil, mot de passe, outils autorisés).
- **Pour les administrateurs:** gestion centralisée des utilisateurs, groupes, OU, et exploration AD.
- **Pour les équipes IT:** code lisible, endpoint JSON clairs, configuration explicite.

## Composants

- `ADSelfService-API.Server`: API HTTP qui dialogue avec Active Directory.
- `WEB-CLIENT-PHP`: intranet PHP qui consomme l'API.

## Fonctionnalités principales

- Connexion utilisateur AD (`/auth`).
- Consultation et mise à jour du profil.
- Changement de mot de passe utilisateur.
- Réinitialisation de mot de passe (flux dédié et protégé).
- Administration des comptes AD:
  - création, suppression, activation, désactivation, déblocage,
  - renommage, déplacement, expiration.
- Administration des groupes et membres.
- Administration des OU (création, mise à jour, suppression).
- Explorateur AD avec recherche d'objets.
- Outils intranet visibles selon les droits utilisateur.

## Sécurité (obligatoire et non optionnelle)

Le comportement actuel du code impose un socle strict:

- `Security.AllowedIps` limite les origines autorisées.
- `Security.InternalSharedSecret` doit être défini et robuste.
- chaque appel API sensible doit fournir un `X-App-Context` valide.
- `/health` reste l'exception de contexte, mais reste filtré par IP.
- LDAP doit être protégé:
  - `Ldap.Ssl=true` (LDAPS),
  - ou `Ldap.UseKerberosSealing=true`.
- `Debug.ShowPasswords=true` est refusé.

Conséquence pratique: sans configuration sécurité correcte, le démarrage est bloqué.

## Séparation des rôles

- **Utilisateur standard:** profil, mot de passe, outils autorisés.
- **Admin utilisateurs:** opérations sur comptes et appartenances.
- **Admin domaine:** opérations avancées (OU, groupes, explorer domaine).

Le client PHP affiche les actions selon les droits, et l'API applique aussi des contrôles côté serveur.

## Démarrage rapide

### Option 1 - Installation depuis une release (recommandé)

1. Télécharger les archives depuis [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Déployer `ADSelfService-API-Server.zip` sur l'hôte API.
3. Lancer une première fois `ADSelfService-API.Server.exe` pour générer `config.json`.
4. Compléter `config.json` (LDAP, sécurité, URLs).
5. Redémarrer l'API et vérifier `GET /health`.
6. Déployer `ADSelfService-WEBSERVER-Files.zip` côté serveur web.
7. Créer `WEB-CLIENT-PHP/config-intranet.php` depuis `config-intranet-default.php`.
8. Vérifier la cohérence `API_BASE` + `INTERNAL_SHARED_SECRET`.

### Option 2 - Construire depuis le code source

```bash
git clone <url-du-repo>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

## Conseils de mise en production

- N'exposez jamais l'API directement sur Internet.
- Gardez `AllowedIps` minimal (serveurs internes seulement).
- Utilisez un secret long et unique pour `InternalSharedSecret`.
- Préférez LDAPS (`636`) avec certificat valide.
- Activez les logs debug uniquement pour diagnostiquer un incident.
- Ne versionnez jamais vos fichiers de configuration sensibles.

## Validation après installation

Checklist recommandée:

1. `GET /health` répond `200`.
2. Login utilisateur fonctionnel.
3. Changement de mot de passe utilisateur fonctionnel.
4. Flux mot de passe oublié fonctionnel (sans fuite d'information).
5. Outils utilisateur correctement filtrés.
6. Actions admin visibles et opérantes selon le bon rôle.
7. Recherches AD (utilisateurs/groupes/OU) cohérentes avec `RootDn` et `BaseDn`.

## Dépannage rapide

| Problème | Vérification prioritaire |
|---|---|
| `403` sur la plupart des appels | `AllowedIps`, `InternalSharedSecret`, `X-App-Context` |
| L'API ne démarre pas | `config.json` incomplet, valeurs interdites, secret absent/faible |
| Bind LDAP en échec | `Ldap.Url`, `Port`, `BindDn`, `BindPassword`, réseau |
| Changement mot de passe refusé | activer LDAPS ou Kerberos sealing |
| Le client PHP refuse de démarrer | `config-intranet.php`, secret, `API_BASE` |

## Documentation associée

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)
# ADSelfService

**__Readme Languages__** [![Français](https://img.shields.io/badge/lang-Français-blue.svg)](README.md)
[![English](https://img.shields.io/badge/lang-English-lightgrey.svg)](README.en.md)

![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)

Solution de self-service Active Directory moderne et personnalisable, `ADSelfService` permet de proposer aux utilisateurs un espace simple pour gérer leur identité AD tout en donnant aux administrateurs une interface centralisée pour piloter les comptes, groupes et OU. Le projet est pensé pour un usage intranet, mais reste suffisamment souple pour être adapté à votre organisation, votre interface web et vos processus internes.

## Vue d’ensemble

Le projet contient deux briques principales :

- `ADSelfService-API.Server` : l'API HTTP qui parle à Active Directory en LDAP, LDAPS ou LDAP + Kerberos.
- `WEB-CLIENT-PHP` : un client intranet PHP qui consomme l'API et expose une interface utilisateur.

Fonctionnalites couvertes :

- Authentification d'un utilisateur du domaine via `/auth`.
- Consultation du profil utilisateur, mise a jour des informations et changement de mot de passe.
- Acces aux outils mis a disposition par l'administrateur via le client web, selon les droits de l'utilisateur.
- Changement de mot de passe possible y compris lors de la premiere connexion si le compte l'exige.
- Administration des comptes AD : creation, suppression, activation, desactivation, deblocage, renommage, deplacement, expiration.
- Administration des groupes : consultation, creation, suppression, ajout et retrait de membres.
- Administration des OU : creation, mise a jour, protection logique et suppression.
- Exploration de l'arborescence AD via `/tree`.

En pratique :

- un utilisateur peut se connecter, consulter son profil, le modifier, changer son mot de passe et acceder a ses outils autorises
- un administrateur conserve tous les droits utilisateur de base et dispose en plus de toutes les fonctions d'administration

## Pour qui

- Pour un administrateur qui veut deployer rapidement une solution prete a l'emploi via les releases.
- Pour un developpeur ou integrateur qui veut construire le projet depuis les sources, le modifier ou l'integrer dans un intranet existant.

## Architecture

```text
Client PHP / scripts / outils HTTP
            |
            v
   ADSelfService (.NET 8)
            |
            v
       Active Directory
```

L'API ne gère pas de JWT ni de session serveur. Elle s'appuie sur :

- une liste d'IP autorisées via `Security.AllowedIps`
- un secret partagé optionnel via l'en-tête `X-Internal-Auth`
- les permissions effectives du compte de service LDAP utilisé par l'application

Le booléen `isAdmin` retourné par `/auth` sert à informer le client. Les endpoints `/admin/*` doivent donc être exposés uniquement à des clients internes de confiance.

## Démarrage rapide

### Option 1. Installer depuis une release

C’est le parcours recommandé pour la production.

1. Télécharger les archives depuis les [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Déployer `ADSelfService-API-Server.zip` sur le serveur qui hébergera l’API.
3. Lancer une première fois l’exécutable publié.
4. Compléter le `config.json` généré automatiquement au premier démarrage.
5. Relancer l’API et vérifier `GET /health`.
6. Déployer si besoin `ADSelfService-WEBSERVER-Files.zip` sur le serveur web PHP.
7. Créer `config-intranet.php` à partir de `config-intranet-default.php` et renseigner `API_BASE` et `INTERNAL_SHARED_SECRET`.

### Option 2. Construire le projet et l’exécuter

Ce parcours est destiné au développement, aux tests ou à la personnalisation.

```bash
git clone <url-du-repo>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

Au premier lancement depuis une publication, l’application crée `config.json` si aucun `config.json` n’est présent dans le dossier du binaire. Depuis les sources, vous pouvez partir de `config.example.json`.

## Installation depuis une release

### Serveur API

1. Télécharger `ADSelfService-API-Server.zip`.
2. Décompresser l’archive dans un dossier dédié.
3. Lancer `ADSelfService-API.Server.exe` une première fois.
4. Ouvrir le `config.json` généré et remplacer les valeurs d’exemple.
5. Relancer en console pour vérifier :
   - la connectivité LDAP
   - le bind du compte de service
   - la réponse `200` sur `/health`
6. En production Windows, installer si besoin le service :
   - `ADSelfService-API.Server.exe --add-service`
   - suppression : `ADSelfService-API.Server.exe --remove-service`

Le service Windows créé s’appelle `ADSelfServiceAPI`.

### Client PHP

1. Télécharger `ADSelfService-WEBSERVER-Files.zip`.
2. Décompresser les fichiers dans le répertoire publié par Apache, IIS ou nginx + PHP.
3. Copier `config-intranet-default.php` vers `config-intranet.php`.
4. Renseigner au minimum :
   - `API_BASE`
   - `INTERNAL_SHARED_SECRET` si l’API l’exige
   - la configuration base de données si vous utilisez les outils intégrés
5. Conserver les fichiers de protection fournis comme `.htaccess` et `web.config`.

## Construire le projet et l'executer

### Prérequis

- .NET 8 SDK
- Windows recommandé pour `System.DirectoryServices`
- accès à un Active Directory en LDAP ou LDAPS
- compte de service AD avec les droits nécessaires
- PHP 8+ si vous utilisez le client web

### API .NET

Depuis la racine du dépôt :

```bash
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

Pour une publication :

```bash
cd ADSelfService-API.Server
dotnet publish -c Release
```

Placez ensuite `config.json` à côté du binaire publié.

### Client PHP

Le dossier `WEB-CLIENT-PHP` peut être déployé tel quel sur votre serveur web. La configuration locale doit se faire dans `config-intranet.php`, jamais dans `config-intranet-default.php`.

## Configuration

Documents utiles :

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md) : référence complète de `config.json`
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md) : choisir entre LDAPS et LDAP + Kerberos
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md) : référence HTTP des endpoints

Points d’attention :

- `Ldap.Url` doit être un FQDN de préférence si vous utilisez Kerberos sur le port `389`.
- `Ldap.BindDn` doit de préférence être au format `user@domaine.local` ou `DOMAINE\user`.
- `Security.AllowedIps` doit contenir les IP du serveur PHP, du reverse proxy (déconseillé) ou des outils internes autorisés.
- `InternalSharedSecret` doit être renseigné côté API et côté PHP si vous activez le contrôle par en-tête.

## Utilisation

Au quotidien, l’utilisateur final peut :

- se connecter avec son compte Active Directory
- consulter et modifier son profil
- accéder aux outils que l’administrateur lui a attribués
- changer son mot de passe, y compris lors d’une première connexion avec changement obligatoire

Un administrateur bénéficie de toutes ces fonctions utilisateur, avec en plus l’ensemble des fonctions d’administration de l’annuaire exposées par l’API et le client web.

### Endpoints principaux

- `GET /health` : vérification de disponibilité et de bind LDAP
- `POST /auth` : authentification d’un utilisateur du domaine
- `GET /users` : liste des utilisateurs
- `GET /groups` : liste des groupes
- `GET /tree` : lecture de l’arborescence annuaire
- `POST /user/updateProfile` : mise à jour du profil
- `POST /user/changePassword` : changement de mot de passe
- `POST /admin/*` : operations d'administration

Exemple d'authentification :

```json
{
  "username": "jdupont",
  "password": "MonMotDePasse"
}
```

## Sécurité

- N’exposez pas l’API publiquement sur Internet.
- Limitez strictement `Security.AllowedIps`.
- Activez `InternalSharedSecret` si le client PHP ou un autre intégrateur l’utilise.
- Préférez LDAPS en production.
- N’activez `Debug.ShowPasswords` qu’en environnement de diagnostic très contrôlé.
- Ne versionnez jamais `config.json` ou `config-intranet.php`.

## Dépannage rapide

| Problème | Vérification |
|----------|--------------|
| `403 Forbidden` sur tous les appels | vérifier `AllowedIps` et, si configuré, l’en-tête `X-Internal-Auth` |
| l’API s’arrête au démarrage | vérifier les valeurs d’exemple encore présentes dans `config.json` |
| bind LDAP en échec | vérifier `Url`, `Port`, `Ssl`, `BindDn`, `BindPassword` |
| changement de mot de passe refusé | vérifier que vous utilisez LDAPS ou `UseKerberosSealing=true` |
| le client PHP refuse de démarrer | vérifier `config-intranet.php`, `API_BASE` et `INTERNAL_SHARED_SECRET` |

## Documentation détaillée

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)

## Langues

- Français : `README.md`
- English : [README.en.md](README.en.md)
