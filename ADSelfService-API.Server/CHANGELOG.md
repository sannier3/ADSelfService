# Changelog

Ce fichier résume les évolutions fonctionnelles majeures visibles dans le dépôt. Pour les binaires prêts à l'emploi, consultez aussi les releases publiées du projet.

## Unreleased

- Documentation restructurée pour distinguer clairement l'installation depuis une release de l'exécution depuis le code source.
- Références API, configuration et LDAP réalignées sur le comportement réel du code.

## 1.00.00

Version visible dans `ADSelfService-API.Server`.

Fonctionnalités principales :

- API REST .NET 8 ciblée `net8.0-windows`
- authentification AD via `/auth`
- lecture et mise à jour du profil utilisateur
- changement de mot de passe utilisateur et administrateur
- gestion des utilisateurs : création, suppression, activation, désactivation, déblocage, renommage, déplacement, expiration
- gestion des groupes : liste, création, suppression, ajout et retrait de membres
- gestion des OU : création, modification, protection logique, suppression
- endpoint `/tree` pour l'exploration de l'annuaire
- filtrage réseau par `AllowedIps`
- secret interne optionnel via `X-Internal-Auth`
- génération automatique de `config.json` au premier lancement si aucun fichier de configuration n'est présent
- prise en charge de `config.json`
- installation possible en service Windows via `--add-service` et suppression via `--remove-service`

## Format recommandé pour les prochaines entrées

```md
## x.y.z

- ajout :
- changement :
- correction :
```
