# ADSelfService-API

<p align="right">
  <a href="README.md" style="display:inline-block;padding:6px 12px;margin:0 4px;border-radius:6px;background:#2563eb;color:#fff;text-decoration:none;font-weight:500;">Français</a>
  <a href="README.en.md" style="display:inline-block;padding:6px 12px;margin:0 4px;border-radius:6px;background:#374151;color:#e5e7eb;text-decoration:none;">English</a>
</p>

**API REST d’auto-service et d’administration Active Directory** — authentification, profil, changement de mot de passe, gestion des utilisateurs, groupes et unités d’organisation (OU). Utilisable par un client web (ex. intranet PHP), des scripts ou tout outil capable d’appeler une API HTTP.

Destiné aux **administrateurs réseau** qui déploient et configurent le service, et aux **utilisateurs passionnés** qui souhaitent comprendre le fonctionnement ou intégrer l’API dans leur propre outillage.

---

## Sommaire

- [Présentation du projet](#présentation-du-projet)
- [Fonctionnalités](#fonctionnalités)
- [Architecture et fonctionnement](#architecture-et-fonctionnement)
- [Prérequis](#prérequis)
- [Installation et démarrage](#installation-et-démarrage)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Sécurité](#sécurité)
- [Déploiement](#déploiement)
- [Dépannage](#dépannage)
- [Documentation détaillée](#documentation-détaillée)
- [Langues](#langues)

---

## Présentation du projet

ADSelfService-API est un **serveur HTTP** (API REST) qui se connecte à **Active Directory** via LDAP (ou LDAPS / Kerberos). Il permet :

- Aux **utilisateurs du domaine** : de se connecter avec leur identifiant AD, de consulter et modifier leur profil (email, téléphone, adresse, etc.) et de **changer leur mot de passe**.
- Aux **administrateurs** (définis par un groupe AD) : de gérer les comptes (création, suppression, activation/désactivation, déverrouillage, déplacement, renommage, expiration), les **groupes** (création, suppression, ajout/retrait de membres) et les **unités d’organisation** (OU) : création, modification, protection, suppression.

L’API ne stocke pas les mots de passe : elle valide les connexions et les changements de mot de passe **directement contre Active Directory**. La sécurité d’accès à l’API repose sur une **liste d’IP autorisées** (et éventuellement un secret partagé côté client), ce qui convient à un déploiement en intranet derrière un reverse proxy ou un serveur web (ex. client PHP).

---

## Fonctionnalités

### Côté utilisateur (self-service)

| Fonction | Description |
|----------|-------------|
| **Connexion** | Authentification avec identifiant et mot de passe du domaine (endpoint `/auth`). |
| **Profil** | Consultation et mise à jour des attributs (nom, prénom, email, téléphone, site web, adresse). |
| **Changement de mot de passe** | Modification du mot de passe AD par l’utilisateur (mot de passe actuel + nouveau). |
| **Groupes** | Affichage des groupes dont l’utilisateur est membre (directs et effectifs). |

### Côté administration

| Catégorie | Actions |
|-----------|---------|
| **Comptes utilisateurs** | Création, suppression, activation/désactivation, déverrouillage, réinitialisation mot de passe, modification des attributs, renommage du CN, déplacement dans une autre OU, gestion de l’expiration du compte. |
| **Groupes** | Liste/recherche, création, suppression, ajout et retrait de membres. |
| **Unités d’organisation (OU)** | Création, modification (nom, description, déplacement), protection (empêche la suppression par l’API), suppression (OU vide et non protégée). |
| **Arborescence** | Endpoint `/tree` pour obtenir la structure du domaine (OU, groupes, utilisateurs, ordinateurs) et alimenter des listes déroulantes (choix d’OU, etc.). |

Les droits « admin » sont déterminés par l’API selon l’appartenance au groupe AD configuré (`AdminGroupDn`). Un client (ex. intranet PHP) peut en plus distinguer **admin utilisateurs** et **admin domaine** via des groupes optionnels pour afficher ou masquer des onglets et actions.

---

## Architecture et fonctionnement

```
┌─────────────────┐      HTTP (JSON)       ┌──────────────────────┐      LDAP/LDAPS      ┌─────────────────────┐
│  Client(s)      │  ───────────────────►  │  ADSelfService-API   │  ─────────────────►  │  Active Directory   │
│  (PHP, scripts, │   IP autorisées         │  (.NET 8, Kestrel)   │   port 389 ou 636    │  (contrôleur(s))    │
│   Postman, …)   │                         │                      │   Kerberos ou TLS    │                     │
└─────────────────┘                         └──────────────────────┘                      └─────────────────────┘
```

- **Client** : envoie des requêtes HTTP (GET/POST/DELETE) avec un body JSON. L’API n’utilise pas de token JWT : l’accès est restreint par **liste d’IP** (config `Security.AllowedIps`). Un client comme l’intranet PHP gère la **session** (login via `/auth`, puis appels au nom de l’utilisateur connecté).
- **API** : reçoit la requête, vérifie l’IP, effectue les opérations LDAP (bind avec un compte de service, recherche, modification, etc.) et renvoie du JSON.
- **Active Directory** : source de vérité pour les comptes, groupes et OU.

**Connexion LDAP** : deux modes possibles (détails dans [LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)) :

1. **LDAPS** (recommandé) : port 636, TLS.  
2. **LDAP + Kerberos** (sans LDAPS) : port 389, avec Sign & Seal pour autoriser les changements de mot de passe.

---

## Prérequis

- **Serveur .NET 8** (Windows recommandé pour `System.DirectoryServices` ; le projet cible `net8.0-windows`).
- **Active Directory** accessible en LDAP (389) ou LDAPS (636).
- Un **compte de service** AD (BindDn/BindPassword) avec les droits nécessaires pour lire/écrire les utilisateurs, groupes et OU dans les DN configurés.
- Pour le **client PHP** (intranet) : PHP 8+, extensions curl, json, pdo (SQLite ou MySQL pour la partie « outils »), et un serveur web (IIS, Apache, nginx).

---

## Installation et démarrage

### 1. Récupérer le code

```bash
git clone <url-du-repo>
cd ADSelfService-API
```

### 2. Configurer l’API

- Copier le fichier d’exemple de configuration :
  ```bash
  copy config.example.json config.json
  ```
- Éditer **config.json** avec les valeurs de votre environnement (LDAP, IP autorisées, etc.). **Ne jamais committer config.json** (il contient des secrets) ; le fichier est ignoré par Git (voir [.gitignore](.gitignore)).
- Référence des options : [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md).

### 3. Lancer l’API

```bash
cd ADSelfService-API.Server
dotnet run
```

Par défaut, l’API écoute sur les URLs indiquées dans `config.json` (ex. `http://localhost:5000`). Vérifier que le **bind LDAP** réussit (logs au démarrage, ou `GET https://localhost:5000/health`).

### 4. (Optionnel) Client intranet PHP

Si vous utilisez le client PHP (dossier **WEB-CLIENT-PHP** dans ce dépôt, ou déployé ailleurs) :

- Copier `WEB-CLIENT-PHP/config-intranet-default.php` vers `WEB-CLIENT-PHP/config-intranet.php`.
- Renseigner `API_BASE` (URL de l’API), `INTERNAL_SHARED_SECRET` (si utilisé), et les autres paramètres (proxy, hCaptcha, etc.).
- Placer les fichiers sur un serveur web et ouvrir `intranet.php` dans le navigateur.
- **Sécurité** : le dossier contient un **.htaccess** (Apache) et un **web.config** (IIS) pour interdire l’accès direct au fichier SQLite, au dossier `rl_logs`, aux fichiers de config et aux `.env`/`.log`. Les laisser en place en production.

---

## Configuration

| Fichier | Rôle |
|---------|------|
| **config.json** | Configuration de l’API (LDAP, sécurité, pagination, URLs, démarrage). À créer à partir de **config.example.json**. |
| **CONFIG-OPTIONS.md** | Liste de toutes les options avec description. |
| **ADSelfService-API.Server/LDAP-CONFIG.md** | Choix LDAPS vs LDAP + Kerberos et paramètres associés. |

Points importants :

- **Ldap.Url** : pour Kerberos (port 389), utiliser le **FQDN** du contrôleur, pas l’IP.
- **Ldap.BindDn** : pour Kerberos, préférer le format UPN (`user@domaine.local`) ou `DOMAINE\user`.
- **Security.AllowedIps** : liste des IP (ou CIDR) autorisées à appeler l’API. Toute autre IP reçoit 403.

---

## Utilisation

### Appels API directs

- **Documentation des endpoints** : [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md) (méthodes, paramètres, réponses).
- **Swagger** : si activé, disponible à `/swagger` lorsque l’API tourne.
- Exemples rapides :
  - Santé : `GET /health`
  - Connexion : `POST /auth` avec `{ "username": "...", "password": "..." }`
  - Profil : `GET /user/{sAMAccountName}`

### Via le client intranet PHP

1. Se connecter avec son identifiant et mot de passe du domaine.
2. **Mon profil** : consulter et modifier ses infos, changer son mot de passe.
3. **Mes outils** : accès à des liens (ex. Synology, Proxmox) selon les groupes AD.
4. **Administration** (si membre du groupe admin) : onglets « Admin utilisateurs » (comptes, groupes utilisateur, outils) et « Admin domaine » (groupes, OU).

Les droits affichés (admin utilisateurs / admin domaine) dépendent de la configuration PHP (`ADM_USER_GROUPS`, `ADM_DOMAIN_GROUPS`) et du groupe admin de l’API (`AdminGroupDn`).

---

## Sécurité

- **Config et secrets** : ne jamais versionner **config.json** ni **config-intranet.php** (ils contiennent mots de passe et secrets). Utiliser **config.example.json** et **config-intranet-default.php** comme modèles.
- **Accès à l’API** : restreint par **liste d’IP** (`AllowedIps`). En production, n’autoriser que les IP des serveurs ou réseaux de confiance (ex. reverse proxy, serveur PHP).
- **HTTPS** : en production, exposer l’API derrière HTTPS (reverse proxy ou Kestrel avec certificat).
- **LDAP** : en production, privilégier **LDAPS** (port 636) ; en l’absence de LDAPS, utiliser **LDAP + Kerberos** (Sign & Seal) comme décrit dans [LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md).

---

## Déploiement

### Méthode 1 — via les releases GitHub (recommandé en production)

Des archives prêtes à l’emploi sont publiées dans les **Releases GitHub** du projet :

- **Serveur API** : `ADSelfService-API-Server.zip`  
  Contient l’exécutable .NET publié ainsi que tous les fichiers nécessaires au fonctionnement autonome de l’API.
- **Client intranet PHP** : `ADSelfService-WEBSERVER-Files.zip`  
  Contient uniquement les fichiers PHP/HTML/CSS/JS à déposer sur un serveur web (Apache2 + PHP, ou IIS + module PHP).

#### 1. Déployer le serveur API (ADSelfService-API-Server.zip)

1. Télécharger l’archive `ADSelfService-API-Server.zip` depuis la page des releases :  
   `https://github.com/sannier3/ADSelfService/releases`
2. Décompresser dans un dossier dédié sur le serveur (ex. `C:\ADSelfService-API` ou `/opt/adselfservice-api`).
3. Lancer une première fois le binaire (ou le script de démarrage fourni) :  
   - au **premier démarrage**, si aucun `config.json` n’est présent, l’API génère un fichier de configuration à partir de l’exemple et s’arrête, en loguant un message du type :  
     « Fichier `config.json` créé, merci de le compléter puis relancez. »
4. Éditer `config.json` :
   - section **Ldap** : URL/port, BindDn/BindPassword, DN de base, etc.  
   - section **Security** : `AllowedIps`, éventuel `InternalSharedSecret` partagé avec le client PHP.  
   - voir [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md) pour le détail.
5. Relancer l’API en **mode console** pour valider la configuration :
   - vérifier dans les logs que le **bind LDAP** est OK et que le **StartupCheck** passe.  
   - tester `GET /health` depuis une IP autorisée.
6. (Optionnel) Installer le serveur en **service Windows** :
   - ouvrir une invite de commandes **en tant qu’administrateur** dans le dossier de publication, puis exécuter :  
     - `ADSelfService-API.Server.exe --add-service`  
     - cela crée un service `ADSelfServiceAPI` (démarrage automatique) **et le démarre immédiatement**.
   - pour le supprimer plus tard :  
     - `ADSelfService-API.Server.exe --remove-service`
   - le comportement de redémarrage automatique en cas de plantage peut ensuite être ajusté dans `services.msc` (onglet **Récupération**).
7. Intégrer ensuite le binaire dans votre supervision/hébergement habituel :
   - service Windows, unité systemd, ou lancement via un gestionnaire de services (NSSM, etc.)  
   - veiller à ce que le compte de service ait accès au réseau LDAP/LDAPS.

#### 2. Déployer le client PHP (ADSelfService-WEBSERVER-Files.zip)

1. Télécharger `ADSelfService-WEBSERVER-Files.zip` depuis les releases GitHub.
2. Décompresser le contenu dans un répertoire servi par votre serveur web, par exemple :
   - Apache2/Linux : `/var/www/adselfservice`
   - IIS/Windows : `C:\inetpub\wwwroot\adselfservice`
3. Vérifier que les fichiers de protection sont bien pris en compte :
   - `.htaccess` sous Apache (bloque `.sqlite`, `rl_logs`, `data`, fichiers de config, `.env`, `.log`).
   - `web.config` sous IIS (règles équivalentes).
4. Créer la configuration du client :
   - copier `config-intranet-default.php` vers `config-intranet.php`.
   - éditer `config-intranet.php` :
     - `API_BASE` : URL publique de l’API (ex. `http://192.168.100.10:5000`).  
     - `INTERNAL_SHARED_SECRET` : secret partagé identique à `InternalSharedSecret` côté API (si utilisé).  
     - options hCaptcha, limite IP, mode d’envoi des mails (`MAIL_MODE`, `MAILER_API_URL`, `MAILER_API_KEY`, `MAIL_FROM`), Twilio, etc.
5. S’assurer que le répertoire de base de données / logs est **écrivable** par PHP si vous utilisez SQLite pour les « outils » :
   - fichier `intranet.sqlite` (ou équivalent) et dossier `rl_logs` doivent pouvoir être créés.
6. Accéder à `intranet.php` depuis un navigateur :
   - tester la connexion avec un compte utilisateur du domaine.  
   - tester l’onglet **Admin** avec un compte membre du groupe AD d’administration.

### Méthode 2 — depuis les sources (développement / personnalisation)

- **API** : cloner le dépôt, modifier si besoin, puis publier avec `dotnet publish` (ou depuis Visual Studio). Placer **config.json** à côté de l’exécutable (ou au chemin lu au démarrage). S’assurer que le compte qui exécute le service peut accéder au réseau (LDAP/LDAPS) et que les **AllowedIps** incluent l’IP du (des) client(s).
- **Client PHP** : utiliser le dossier `WEB-CLIENT-PHP` du dépôt, le déployer sur un serveur web (IIS, Apache, nginx), PHP 8+, et configurer **config-intranet.php** (API_BASE, secret, etc.). Conserver le **.htaccess** (Apache) et le **web.config** (IIS) fournis pour bloquer l’accès au SQLite, à `rl_logs` et aux configs. Idéalement, le serveur PHP et l’API sont sur un réseau interne et seuls les utilisateurs passent par le navigateur (HTTPS).

---

## Dépannage

| Problème | Piste |
|----------|--------|
| **403 Forbidden** sur l’API | Vérifier que l’IP du client (ou du proxy) est dans **Security.AllowedIps**. |
| **Échec de connexion LDAP au démarrage** | Vérifier Url, Port, Ssl, BindDn/BindPassword, et pour Kerberos : FQDN, format UPN. Voir [LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md). |
| **Changement de mot de passe refusé** | En LDAP non chiffré (389 sans Kerberos), AD peut refuser. Activer **UseKerberosSealing** ou utiliser LDAPS. |
| **Client PHP : « Configuration introuvable »** | Vérifier que **config-intranet.php** existe et que **API_BASE** et **INTERNAL_SHARED_SECRET** sont renseignés (pas de valeurs par défaut). |
| **Service Windows ne démarre pas / s’arrête immédiatement** | Lancer `ADSelfService-API.Server.exe` **sans argument** en mode console pour voir les erreurs au démarrage (config invalide, LDAP KO, IP non autorisée, etc.). Vérifier aussi les logs dans `Debug.LogDir`. |

Les logs de l’API (dossier configuré par **Debug.LogDir**) et les logs du serveur web/PHP aident au diagnostic. En cas de doute, toujours tester d’abord en mode console avant de remettre à jour le service Windows.

---

## Documentation détaillée

| Document | Contenu |
|----------|---------|
| [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md) | Toutes les options de **config.json**. |
| [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md) | LDAPS vs LDAP + Kerberos. |
| [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md) | Liste complète des endpoints, paramètres et réponses. |

---

## Langues

- **Français** : ce fichier ([README.md](README.md)).
- **English** : [README.en.md](README.en.md).
