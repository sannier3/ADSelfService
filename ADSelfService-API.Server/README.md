# ADSelfService-API.Server

API .NET 8 de `ADSelfService`.

Ce composant centralise :

- l'authentification Active Directory
- les opérations LDAP/AD utilisateur, groupe, OU, explorateur
- les contrôles d'accès serveur
- les validations de configuration de sécurité au démarrage

## Fichiers principaux

- `Program.cs` : bootstrap, configuration, endpoints, logique principale.
- `ADSelfService-API.Server.csproj` : projet .NET 8.
- `LDAP-CONFIG.md` : guide LDAP / AD.
- `ENDPOINTS.md` : référence des routes.
- `CHANGELOG.md` : évolutions majeures.

## Configuration runtime

L'API lit `config.json` ou `config.yaml` à côté du binaire.

Au premier lancement :

- si aucun fichier de configuration n'existe, l'application peut générer un modèle
- vous devez ensuite compléter la configuration avant usage réel

Pour les options disponibles :

- [../CONFIG-OPTIONS.md](../CONFIG-OPTIONS.md)

## Contraintes sécurité appliquées

- `Security.AllowedIps`
- `Security.InternalSharedSecret`
- `Security.RequireAppContextHeader`
- transport LDAP protégé obligatoire :
  - `Ldap.Ssl=true`, ou
  - `Ldap.UseKerberosSealing=true`
- `Debug.ShowPasswords=true` interdit

## Démarrage local

```bash
copy ..\config.example.json .\config.json
dotnet run --project ADSelfService-API.Server
```

Puis vérifier :

- `GET /health`

## Publication

Le projet peut être publié en dossier ou empaqueté pour release.

Exemple :

```bash
dotnet publish ADSelfService-API.Server -c Release -r win-x64 --self-contained false
```

## Note sur `SpaRoot`

Le `.csproj` contient encore des propriétés `SpaRoot` / `SpaProxy*`.
Dans l'état actuel du dépôt, le client réellement maintenu et livré est `WEB-CLIENT-PHP`, pas un frontend SPA versionné dans ce repo.

Ces propriétés doivent être lues comme un reliquat technique / historique tant qu'aucun dossier frontend dédié n'est présent.

## Documentation associée

- [README racine](../README.md)
- [Configuration API](../CONFIG-OPTIONS.md)
- [Configuration LDAP](./LDAP-CONFIG.md)
- [Référence endpoints](./ENDPOINTS.md)
- [Changelog](./CHANGELOG.md)
