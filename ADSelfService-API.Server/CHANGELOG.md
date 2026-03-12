# Changelog

Ce fichier resume les evolutions fonctionnelles majeures visibles dans le depot. Pour les binaires prets a l'emploi, consultez aussi les releases publiees du projet.

## Unreleased

- Documentation restructuree pour distinguer clairement l'installation depuis une release de l'execution depuis le code source.
- Reference API, configuration et LDAP realignees sur le comportement reel du code.

## 1.00.00

Version visible dans `ADSelfService-API.Server`.

Fonctionnalites principales :

- API REST .NET 8 ciblee `net8.0-windows`
- authentification AD via `/auth`
- lecture et mise a jour du profil utilisateur
- changement de mot de passe utilisateur et administrateur
- gestion des utilisateurs : creation, suppression, activation, desactivation, deblocage, renommage, deplacement, expiration
- gestion des groupes : liste, creation, suppression, ajout et retrait de membres
- gestion des OU : creation, modification, protection logique, suppression
- endpoint `/tree` pour l'exploration de l'annuaire
- filtrage reseau par `AllowedIps`
- secret interne optionnel via `X-Internal-Auth`
- generation automatique de `config.json` au premier lancement si aucun fichier de configuration n'est present
- prise en charge de `config.json`
- installation possible en service Windows via `--add-service` et suppression via `--remove-service`

## Format recommande pour les prochaines entrees

```md
## x.y.z

- ajout :
- changement :
- correction :
```
