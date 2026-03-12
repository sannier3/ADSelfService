<?php
/**********************************************************************************
 *  ⚠️  NE PAS MODIFIER CE FICHIER  —  FICHIER MODÈLE / TEMPLATE                    *
 *                                                                                 *
 *  Nom : config-intranet-default.php                                              *
 *                                                                                 *
 *  ➜ Ce fichier fournit des VALEURS D'EXEMPLE.                                    *
 *  ➜ L’application s’ARRÊTE si ce fichier est utilisé tel quel.                   *
 *                                                                                 *
 *  ✅ PROCÉDURE CORRECTE                                                           *
 *  1) Copier ce fichier vers "config-intranet.php"                                *
 *     - Linux/macOS :  cp config-intranet-default.php config-intranet.php         *
 *     - Windows     :  copy config-intranet-default.php config-intranet.php       *
 *                                                                                 *
 *  2) ÉDITER UNIQUEMENT "config-intranet.php"                                     *
 *     - Ouvre config-intranet.php dans ton éditeur                                *
 *     - Remplace __IS_DEFAULT => true par __IS_DEFAULT => false                   *
 *     - Renseigne tes vraies valeurs (API_BASE, INTERNAL_SHARED_SECRET, etc.)     *
 *                                                                                 *
 *  3) (Recommandé) NE PAS versionner config-intranet.php                          *
 *     - Ajoute "config-intranet.php" à ton .gitignore/.dockerignore               *
 *                                                                                 *
 *  ℹ️  L’application refusera de démarrer si :                                     *
 *     - "__IS_DEFAULT" vaut true                                                  *
 *     - "config-intranet.php" est manquant                                        *
 *     - "INTERNAL_SHARED_SECRET" ressemble à une valeur placeholder               *
 *     - "API_BASE" est vide                                                       *
 *                                                                                 *
 *  🧩 Exemple MINIMAL de config-intranet.php (à partir de ce modèle) :            *
 *  --------------------------------------------------------------------------------
 *  <?php
 *  return [
 *      '__IS_DEFAULT' => false,
 *      'API_BASE' => 'http://192.168.100.2:5000',
 *      'INTERNAL_SHARED_SECRET' => 'un-secret-long-et-solide-ici',
 *      // … adapte le reste selon ton environnement …
 *  ];
 *  --------------------------------------------------------------------------------
 *                                                                                 *
 *  🔒 Points d’attention                                                            *
 *  - INTERNAL_SHARED_SECRET : choisis une chaîne longue/entropique (>32 chars).   *
 *  - API_INSECURE_SKIP_VERIFY : laisse false en production.                        *
 *  - HCAPTCHA : remplace les clés de test par tes clés réelles en prod.           *
 *  - TRUSTED_PROXIES : liste stricte des IP/CIDR de tes reverse proxies.          *
 *                                                                                 *
 *  ✋ Encore une fois : NE MODIFIE PAS ce fichier. Copie-le -> config-intranet.php *
 **********************************************************************************/

/**
 * Fichier par défaut — valeurs de démonstration.
 * L’app s’arrêtera si __IS_DEFAULT === true.
 */
return [
    '__IS_DEFAULT' => true,

    // --- Base de données (outils) ---
    // Soit tu renseignes un DSN MySQL :
    //   'DB_DSN'  => 'mysql:host=127.0.0.1;dbname=intranet;charset=utf8mb4',
    //   'DB_USER' => 'intranet',
    //   'DB_PASS' => 'motdepasse',
    //
    // Soit tu laisses vide et on utilisera SQLite via DB_PATH :
    'DB_DSN'  => '',
    'DB_USER' => '',
    'DB_PASS' => '',

    // SQLite : chemin du fichier (écriture requise par PHP)
    'DB_PATH' => __DIR__ . '/intranet.sqlite',

    // --- UI / liens ---
    // Afficher le lien "Mot de passe oublié ?" (true = on, false = off)
    'FORGOT_PASSWORD_ENABLED' => true,

    // Affichage optionnel de l'IP dans la barre de navigation
    'SHOW_CLIENT_IP' => true, // ou false pour masquer
    
    // ===== Réseau / Proxy =====
    // Liste d’IP/CIDR de proxies de confiance ; l’en-tête CLIENT_IP_HEADER
    // ne sera pris en compte que si la requête vient d’une de ces adresses.
    'TRUSTED_PROXIES' => '192.168.100.32,127.0.0.1,::1',
    'CLIENT_IP_HEADER' => 'X-Forwarded-For',

    // ===== API .NET (ADSelfService_API.Server) =====
    // Base URL de l’API backend (expose /auth, /users, /admin/*)
    'API_BASE' => 'http://127.0.0.1:5000',

    // Facultatif : si renseigné, le PHP enverra l’en-tête X-Internal-Auth.
    // ⚠️ PLACEHOLDER — doit être remplacé dans config-intranet.php
    'INTERNAL_SHARED_SECRET' => 'change-me-please-32+chars',

    // Si l’API est en HTTPS self-signed en dev (déconseillé en prod)
    'API_INSECURE_SKIP_VERIFY' => false,

    // ===== hCaptcha =====
    // Activer ou non le captcha sur la page de connexion (et sur mot de passe oublié si utilisé)
    'HCAPTCHA_ENABLED' => true,
    // Clés (test par défaut) : SiteKey 10000000-ffff-ffff-ffff-000000000001 / Secret 0x0000...
    'HCAPTCHA_SITEKEY' => '10000000-ffff-ffff-ffff-000000000001',
    'HCAPTCHA_SECRET'  => '0x0000000000000000000000000000000000000000',

    // ===== Blocage IP (rate limit fichier) =====
    // Activer le blocage IP après trop d’échecs de connexion (fenêtre 30 min, blocage à 15)
    'RL_FILE_ENABLED' => true,
    'RL_LOG_DIR'      => null,  // null = __DIR__ . '/rl_logs'
    'RL_WINDOW_SECONDS' => 1800,
    'RL_BLOCK_AFTER'  => 15,
    'RL_WARN_AFTER'   => 5,

    // ===== Envoi de mails (mot de passe oublié, etc.) =====
    // 'internal' = PHP mail() / serveur SMTP local ; 'api' = ton API mailer (MAILER_API_URL + clé)
    'MAIL_MODE' => 'internal',
    // Pour mode 'api' :
    'MAILER_API_URL' => 'https://jbsan.fr/api/private/mailer/mailer.php',
    'MAILER_API_KEY' => '',  // ou getenv('MAILER_API_KEY') côté serveur
    // Pour mode 'internal' : expéditeur (From)
    'MAIL_FROM' => 'Intranet <no-reply@exemple.local>',

    // ===== SMS Twilio (mot de passe oublié par téléphone) =====
    // Tous les identifiants dans la config (ou getenv), jamais en dur dans le code.
    'TWILIO_SMS_ENABLED'   => false,
    'TWILIO_ACCOUNT_SID'   => '',  // Compte Twilio
    'TWILIO_AUTH_TOKEN'    => '',  // ou getenv('TWILIO_AUTH_TOKEN')
    'TWILIO_FROM_NUMBER'   => '',  // Numéro d’envoi (ex. +33600000000 ou SID d’un Twilio number)

    // ===== UI / Pagination =====
    'ADMIN_LIST_PAGE_SIZE' => 50,

    // ===== Anti brute-force login =====
    // Fenêtre d’observation (sec), max tentatives, durée de blocage (sec)
    'LOGIN_RL_WINDOW'  => 1200,
    'LOGIN_RL_MAX'     => 10,
    'LOGIN_RL_BLOCK'   => 1200,
    // Backend du rate-limit : 'auto' | 'apcu' | 'session'
    'LOGIN_RL_BACKEND' => 'auto',

    // peuvent gérer les comptes
    'ADM_USER_GROUPS'   => ['ADSyncAdmins','UserAdmins'],
    // peuvent gérer OU & groupes
    'ADM_DOMAIN_GROUPS' => ['ADSyncAdmins','OUAdmins'],
];
