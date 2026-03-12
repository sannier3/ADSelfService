# ADSelfService-API

<p align="right">
  <a href="README.md" style="display:inline-block;padding:6px 12px;margin:0 4px;border-radius:6px;background:#2563eb;color:#fff;text-decoration:none;font-weight:500;">Français</a>
  <a href="README.en.md" style="display:inline-block;padding:6px 12px;margin:0 4px;border-radius:6px;background:#374151;color:#e5e7eb;text-decoration:none;">English</a>
</p>

API REST .NET 8 pour l'auto-service Active Directory et l'administration d'annuaire, pensée pour un usage intranet avec un client web PHP, des scripts ou des intégrations internes.

## Vue d'ensemble

Le projet contient deux briques principales :

- `ADSelfService-API.Server` : l'API HTTP qui parle a Active Directory en LDAP, LDAPS ou LDAP + Kerberos.
- `WEB-CLIENT-PHP` : un client intranet PHP qui consomme l'API et expose une interface utilisateur.

Fonctionnalites couvertes :

- Authentification d'un utilisateur du domaine via `/auth`.
- Consultation et mise a jour du profil utilisateur.
- Changement de mot de passe utilisateur.
- Administration des comptes AD : creation, suppression, activation, desactivation, deblocage, renommage, deplacement, expiration.
- Administration des groupes : consultation, creation, suppression, ajout et retrait de membres.
- Administration des OU : creation, mise a jour, protection logique et suppression.
- Exploration de l'arborescence AD via `/tree`.

## Pour qui

- Pour un administrateur qui veut deployer rapidement une solution prete a l'emploi via les releases.
- Pour un developpeur ou integrateur qui veut construire le projet depuis les sources, le modifier ou l'integrer dans un intranet existant.

## Architecture

```text
Client PHP / scripts / outils HTTP
            |
            v
   ADSelfService-API (.NET 8)
            |
            v
       Active Directory
```

L'API ne gere pas de JWT ni de session serveur. Elle s'appuie sur :

- une liste d'IP autorisees via `Security.AllowedIps`
- un secret partage optionnel via l'en-tete `X-Internal-Auth`
- les permissions effectives du compte de service LDAP utilise par l'application

Le booleen `isAdmin` retourne par `/auth` sert a informer le client. Les endpoints `/admin/*` doivent donc etre exposes uniquement a des clients internes de confiance.

## Demarrage rapide

### Option 1. Installer depuis une release

C'est le parcours recommande pour la production.

1. Telecharger les archives depuis les [GitHub Releases](https://github.com/sannier3/ADSelfService/releases).
2. Deployer `ADSelfService-API-Server.zip` sur le serveur qui hebergera l'API.
3. Lancer une premiere fois l'executable publie.
4. Completer le `config.json` genere automatiquement au premier demarrage.
5. Relancer l'API et verifier `GET /health`.
6. Deployer si besoin `ADSelfService-WEBSERVER-Files.zip` sur le serveur web PHP.
7. Creer `config-intranet.php` a partir de `config-intranet-default.php` et renseigner `API_BASE` et `INTERNAL_SHARED_SECRET`.

### Option 2. Construire le projet et l'executer

Ce parcours est destine au developpement, aux tests ou a la personnalisation.

```bash
git clone <url-du-repo>
cd ADSelfService-API
copy config.example.json config.json
cd ADSelfService-API.Server
dotnet run
```

Au premier lancement depuis une publication, l'application cree `config.json` si aucun `config.json` ni `config.yaml` n'est present dans le dossier du binaire. Depuis les sources, vous pouvez partir de `config.example.json`.

## Installation depuis une release

### Serveur API

1. Telecharger `ADSelfService-API-Server.zip`.
2. Decompresser l'archive dans un dossier dedie.
3. Lancer `ADSelfService-API.Server.exe` une premiere fois.
4. Ouvrir le `config.json` genere et remplacer les valeurs d'exemple.
5. Relancer en console pour verifier :
   - la connectivite LDAP
   - le bind du compte de service
   - la reponse `200` sur `/health`
6. En production Windows, installer si besoin le service :
   - `ADSelfService-API.Server.exe --add-service`
   - suppression : `ADSelfService-API.Server.exe --remove-service`

Le service Windows cree s'appelle `ADSelfServiceAPI`.

### Client PHP

1. Telecharger `ADSelfService-WEBSERVER-Files.zip`.
2. Decompresser les fichiers dans le repertoire publie par Apache, IIS ou nginx + PHP.
3. Copier `config-intranet-default.php` vers `config-intranet.php`.
4. Renseigner au minimum :
   - `API_BASE`
   - `INTERNAL_SHARED_SECRET` si l'API l'exige
   - la configuration base de donnees si vous utilisez les outils integres
5. Conserver les fichiers de protection fournis comme `.htaccess` et `web.config`.

## Construire le projet et l'executer

### Prerequis

- .NET 8 SDK
- Windows recommande pour `System.DirectoryServices`
- acces a un Active Directory en LDAP ou LDAPS
- compte de service AD avec les droits necessaires
- PHP 8+ si vous utilisez le client web

### API .NET

Depuis la racine du depot :

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

Placez ensuite `config.json` ou `config.yaml` a cote du binaire publie.

### Client PHP

Le dossier `WEB-CLIENT-PHP` peut etre deploye tel quel sur votre serveur web. La configuration locale doit se faire dans `config-intranet.php`, jamais dans `config-intranet-default.php`.

## Configuration

Documents utiles :

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md) : reference complete de `config.json` et `config.yaml`
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md) : choisir entre LDAPS et LDAP + Kerberos
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md) : reference HTTP des endpoints

Points d'attention :

- `Ldap.Url` doit etre un FQDN de préférence si vous utilisez Kerberos sur le port `389`.
- `Ldap.BindDn` doit de preference etre au format `user@domaine.local` ou `DOMAINE\user`.
- `Security.AllowedIps` doit contenir les IP du serveur PHP, du reverse proxy (déconseillé) ou des outils internes autorises.
- `InternalSharedSecret` doit etre renseigne cote API et cote PHP si vous activez le controle par en-tete.

## Utilisation

### Endpoints principaux

- `GET /health` : verification de disponibilite et de bind LDAP
- `POST /auth` : authentification d'un utilisateur du domaine
- `GET /users` : liste des utilisateurs
- `GET /groups` : liste des groupes
- `GET /tree` : lecture de l'arborescence annuaire
- `POST /user/updateProfile` : mise a jour du profil
- `POST /user/changePassword` : changement de mot de passe
- `POST /admin/*` : operations d'administration

Exemple d'authentification :

```json
{
  "username": "jdupont",
  "password": "MonMotDePasse"
}
```

## Securite

- N'exposez pas l'API publiquement sur Internet.
- Limitez strictement `Security.AllowedIps`.
- Activez `InternalSharedSecret` si le client PHP ou un autre integrateur l'utilise.
- Preferez LDAPS en production.
- N'activez `Debug.ShowPasswords` qu'en environnement de diagnostic tres controle.
- Ne versionnez jamais `config.json`, `config.yaml` ou `config-intranet.php`.

## Depannage rapide

| Probleme | Verification |
|----------|--------------|
| `403 Forbidden` sur tous les appels | verifier `AllowedIps` et, si configure, l'en-tete `X-Internal-Auth` |
| l'API s'arrete au demarrage | verifier les valeurs d'exemple encore presentes dans `config.json` |
| bind LDAP en echec | verifier `Url`, `Port`, `Ssl`, `BindDn`, `BindPassword` |
| changement de mot de passe refuse | verifier que vous utilisez LDAPS ou `UseKerberosSealing=true` |
| le client PHP refuse de demarrer | verifier `config-intranet.php`, `API_BASE` et `INTERNAL_SHARED_SECRET` |

## Documentation detaillee

- [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md)
- [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)
- [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md)
- [ADSelfService-API.Server/CHANGELOG.md](ADSelfService-API.Server/CHANGELOG.md)

## Langues

- Francais : `README.md`
- English : [README.en.md](README.en.md)
