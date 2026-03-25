# WEB-CLIENT-PHP

Client intranet PHP de `ADSelfService`.

Ce composant fournit l'interface web pour :

- l'authentification utilisateur
- la consultation et mise à jour du profil
- le changement de mot de passe
- le flux mot de passe oublié
- l'administration AD selon les rôles
- l'explorateur AD
- les outils visibles selon les droits

## Fichiers principaux

- `intranet.php` : portail principal utilisateur/admin.
- `forgot_password.php` : flux de récupération/réinitialisation.
- `intranet-i18n.php` : bootstrap i18n et gestion de la langue UI.
- `intranet-i18n-messages.php` : catalogue FR/EN.
- `config-intranet-default.php` : modèle de configuration.
- `config-intranet.php` : configuration locale à créer, ne pas versionner.
- `.htaccess` / `web.config` : intégration serveur web Apache / IIS.

## Configuration

1. Copier `config-intranet-default.php` vers `config-intranet.php`.
2. Passer `__IS_DEFAULT` à `false`.
3. Renseigner au minimum :
   - `API_BASE`
   - `INTERNAL_SHARED_SECRET`
   - paramètres LDAP API côté backend déjà cohérents
   - options session / captcha / mail selon l'environnement
4. Vérifier que `config-intranet.php` n'est pas versionné.

## Dépendances côté serveur web

- PHP avec `curl`, `json`, `mbstring`, `pdo`
- `pdo_sqlite` si vous utilisez SQLite pour le module tools
- `DOMDocument` recommandé : le rendu HTML riche des instructions tools est assaini côté serveur avec cette extension

## Sécurité intégrée

- CSRF sur les formulaires sensibles
- cookie de session PHP configuré avec `HttpOnly`, `SameSite=Lax`, `Secure` si HTTPS
- cookie applicatif `Intra-Sync-Key` couplé à la session
- rotation optionnelle de clé sur `GET` via `INTRA_SYNC_KEY_ROTATE_MINUTES`
- fenêtre de grâce courte pour éviter les désynchronisations entre requêtes concurrentes
- expiration glissante des cookies de session et de sync key sur les requêtes authentifiées valides
- filtrage HTML strict pour les instructions tools

## Déploiement

### IIS

- utiliser `web.config`
- pointer le site vers le dossier `WEB-CLIENT-PHP`
- vérifier les droits d'écriture si SQLite / logs locaux sont utilisés

### Apache

- utiliser `.htaccess`
- vérifier les modules nécessaires selon votre hébergement

## Notes d'exploitation

- `config-intranet.php`, `intranet.sqlite`, `rl_logs/` et les logs locaux ne doivent pas être commités
- le client PHP attend une API accessible sur `API_BASE`
- `INTERNAL_SHARED_SECRET` doit correspondre à la valeur de l'API si l'en-tête interne est utilisé
- la configuration d'i18n et de session se fait côté PHP, pas dans l'API

## Liens utiles

- [README racine](../README.md)
- [Configuration API](../CONFIG-OPTIONS.md)
- [Configuration LDAP API](../ADSelfService-API.Server/LDAP-CONFIG.md)
- [Référence endpoints API](../ADSelfService-API.Server/ENDPOINTS.md)
