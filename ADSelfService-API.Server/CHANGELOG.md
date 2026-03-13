# Changelog

Ce changelog résume les évolutions majeures visibles dans le dépôt.

## Unreleased

### Sécurité

- Renforcement du modèle d'accès API:
  - contrôle de contexte applicatif via `X-App-Context`,
  - validations de configuration durcies (`InternalSharedSecret`, transport LDAP protégé),
  - blocage des configurations non conformes au démarrage.
- Durcissement du flux mot de passe oublié:
  - endpoint API dédié `/recovery/lookup`,
  - réduction des risques d'énumération,
  - anti-bruteforce côté client PHP.
- Assainissement du rendu HTML des instructions outils (whitelist stricte).

### API et contrat endpoints

- Consolidation des routes explorer/groupes/membres autour des endpoints unifiés:
  - `/explorer/group-search`,
  - `/explorer/user-groups`,
  - `/explorer/user-groups/set`,
  - `/explorer/group-members`,
  - `/explorer/group-members/set`.
- Suppression du legacy documenté pour la gestion groupes (`addToGroup/removeFromGroup/groupMembers`).
- Correction du périmètre de recherche groupes en `scope=all` pour inclure correctement les groupes sous `RootDn` et sous-répertoires.

### Interface et logique PHP

- Simplification des écrans de gestion groupes/membres.
- Meilleure lisibilité des groupes utilisateur.
- Harmonisation des appels API côté intranet et endpoints AJAX.

### Documentation

- Refonte complète des documents Markdown (FR/EN):
  - lisibilité renforcée,
  - alignement strict sur le code actuel,
  - guides de mise en place et dépannage enrichis.

## 1.00.00

Version de base du projet:

- API .NET 8 pour Active Directory.
- Authentification, profil, changement de mot de passe.
- Gestion utilisateurs, groupes, OU.
- Client intranet PHP.

## Format conseillé pour les prochaines entrées

```md
## x.y.z

### Sécurité
- ...

### API
- ...

### UI / Intégration
- ...

### Documentation
- ...
```
