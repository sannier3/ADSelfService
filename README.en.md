# ADSelfService-API

<p align="right">
  <a href="README.md" style="display:inline-block;padding:6px 12px;margin:0 4px;border-radius:6px;background:#374151;color:#e5e7eb;text-decoration:none;">Français</a>
  <a href="README.en.md" style="display:inline-block;padding:6px 12px;margin:0 4px;border-radius:6px;background:#2563eb;color:#fff;text-decoration:none;font-weight:500;">English</a>
</p>

**REST API for Active Directory self-service and administration** — authentication, profile, password change, user/group/organizational unit (OU) management. Usable from a web client (e.g. PHP intranet), scripts, or any tool that can call an HTTP API.

Aimed at **network administrators** who deploy and configure the service, and at **enthusiast users** who want to understand how it works or integrate the API into their own tooling.

---

## Table of contents

- [Project overview](#project-overview)
- [Features](#features)
- [Architecture and how it works](#architecture-and-how-it-works)
- [Prerequisites](#prerequisites)
- [Installation and running](#installation-and-running)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security](#security)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Detailed documentation](#detailed-documentation)
- [Languages](#languages)

---

## Project overview

ADSelfService-API is an **HTTP server** (REST API) that connects to **Active Directory** via LDAP (or LDAPS / Kerberos). It allows:

- **Domain users**: to sign in with their AD credentials, view and update their profile (email, phone, address, etc.), and **change their password**.
- **Administrators** (defined by an AD group): to manage accounts (create, delete, enable/disable, unlock, move, rename, set expiration), **groups** (create, delete, add/remove members), and **organizational units (OU)**: create, update, protect, delete.

The API does not store passwords: it validates logins and password changes **directly against Active Directory**. Access to the API is secured by an **allowed IP list** (and optionally a shared secret on the client side), which fits an intranet deployment behind a reverse proxy or web server (e.g. PHP client).

---

## Features

### User side (self-service)

| Feature | Description |
|---------|-------------|
| **Login** | Authentication with domain username and password (endpoint `/auth`). |
| **Profile** | View and update attributes (name, email, phone, website, address). |
| **Password change** | User-initiated AD password change (current + new password). |
| **Groups** | Display groups the user belongs to (direct and effective). |

### Administration side

| Category | Actions |
|----------|---------|
| **User accounts** | Create, delete, enable/disable, unlock, reset password, update attributes, rename CN, move to another OU, set account expiration. |
| **Groups** | List/search, create, delete, add and remove members. |
| **Organizational units (OU)** | Create, update (name, description, move), protect (prevents deletion via API), delete (empty and non-protected OU only). |
| **Directory tree** | Endpoint `/tree` to get domain structure (OU, groups, users, computers) and feed dropdowns (OU selection, etc.). |

Admin rights are determined by the API based on membership in the configured AD group (`AdminGroupDn`). A client (e.g. PHP intranet) can further distinguish **user admin** and **domain admin** via optional groups to show or hide tabs and actions.

---

## Architecture and how it works

```
┌─────────────────┐      HTTP (JSON)       ┌──────────────────────┐      LDAP/LDAPS      ┌─────────────────────┐
│  Client(s)      │  ───────────────────►  │  ADSelfService-API   │  ─────────────────►  │  Active Directory   │
│  (PHP, scripts, │   Allowed IPs only     │  (.NET 8, Kestrel)   │  port 389 or 636     │  (domain ctrl(s))   │
│   Postman, …)   │                         │                      │  Kerberos or TLS     │                     │
└─────────────────┘                         └──────────────────────┘                      └─────────────────────┘
```

- **Client**: sends HTTP requests (GET/POST/DELETE) with JSON body. The API does not use JWT: access is restricted by **IP list** (config `Security.AllowedIps`). A client like the PHP intranet manages **session** (login via `/auth`, then calls on behalf of the logged-in user).
- **API**: receives the request, checks IP, performs LDAP operations (bind with service account, search, modify, etc.) and returns JSON.
- **Active Directory**: source of truth for accounts, groups, and OUs.

**LDAP connection**: two modes (details in [LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md)):

1. **LDAPS** (recommended): port 636, TLS.  
2. **LDAP + Kerberos** (without LDAPS): port 389, with Sign & Seal to allow password changes.

---

## Prerequisites

- **.NET 8** runtime (Windows recommended for `System.DirectoryServices`; project targets `net8.0-windows`).
- **Active Directory** reachable via LDAP (389) or LDAPS (636).
- A **service account** in AD (BindDn/BindPassword) with sufficient rights to read/write users, groups, and OUs in the configured DNs.
- For the **PHP client** (intranet): PHP 8+, curl, json, pdo extensions (SQLite or MySQL for the “tools” feature), and a web server (IIS, Apache, nginx).

---

## Installation and running

### 1. Get the code

```bash
git clone <repo-url>
cd ADSelfService-API
```

### 2. Configure the API

- Copy the example config:
  ```bash
  copy config.example.json config.json
  ```
- Edit **config.json** with your environment (LDAP, allowed IPs, etc.). **Never commit config.json** (it contains secrets); it is ignored by Git (see [.gitignore](.gitignore)).
- Option reference: [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md).

### 3. Run the API

```bash
cd ADSelfService-API.Server
dotnet run
```

By default the API listens on the URLs in `config.json` (e.g. `http://localhost:5000`). Ensure **LDAP bind** succeeds (startup logs or `GET https://localhost:5000/health`).

### 4. (Optional) PHP intranet client

If you use the PHP client (in a separate folder or same repo):

- Copy `WEB-CLIENT-PHP/config-intranet-default.php` to `WEB-CLIENT-PHP/config-intranet.php`.
- Set `API_BASE` (API URL), `INTERNAL_SHARED_SECRET` (if used), and other options (proxy, hCaptcha, etc.).
- Place files on a web server and open `intranet.php` in a browser.
- **Security**: the folder includes **.htaccess** (Apache) and **web.config** (IIS) to deny direct access to the SQLite file, `rl_logs` directory, config files, and `.env`/`.log`. Keep them in production.

---

## Configuration

| File | Purpose |
|------|---------|
| **config.json** | API configuration (LDAP, security, pagination, URLs, startup). Create from **config.example.json**. |
| **CONFIG-OPTIONS.md** | All options with descriptions. |
| **ADSelfService-API.Server/LDAP-CONFIG.md** | LDAPS vs LDAP + Kerberos and related settings. |

Important points:

- **Ldap.Url**: for Kerberos (port 389), use the controller **FQDN**, not the IP.
- **Ldap.BindDn**: for Kerberos, use UPN (`user@domain.local`) or `DOMAIN\user`.
- **Security.AllowedIps**: list of IPs (or CIDR) allowed to call the API. Any other IP gets 403.

---

## Usage

### Direct API calls

- **Endpoint documentation**: [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md) (methods, parameters, responses).
- **Swagger**: if enabled, available at `/swagger` when the API is running.
- Quick examples:
  - Health: `GET /health`
  - Login: `POST /auth` with `{ "username": "...", "password": "..." }`
  - Profile: `GET /user/{sAMAccountName}`

### Via the PHP intranet client

1. Log in with domain username and password.
2. **My profile**: view and edit your info, change password.
3. **My tools**: access to links (e.g. Synology, Proxmox) based on AD groups.
4. **Administration** (if in admin group): “User admin” tab (accounts, user groups, tools) and “Domain admin” tab (groups, OUs).

Displayed rights (user admin / domain admin) depend on PHP config (`ADM_USER_GROUPS`, `ADM_DOMAIN_GROUPS`) and the API admin group (`AdminGroupDn`).

---

## Security

- **Config and secrets**: never commit **config.json** or **config-intranet.php** (they contain passwords and secrets). Use **config.example.json** and **config-intranet-default.php** as templates.
- **API access**: restricted by **IP list** (`AllowedIps`). In production, only allow IPs of trusted servers or networks (e.g. reverse proxy, PHP server).
- **HTTPS**: in production, expose the API over HTTPS (reverse proxy or Kestrel with certificate).
- **LDAP**: in production, prefer **LDAPS** (port 636); without LDAPS, use **LDAP + Kerberos** (Sign & Seal) as described in [LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md).

---

## Deployment

### Method 1 — via GitHub releases (recommended for production)

Pre-built archives are published in the project **GitHub Releases**:

- **API server**: `ADSelfService-API-Server.zip`  
  Contains the published .NET binary and all files required to run the API standalone.
- **PHP intranet client**: `ADSelfService-WEBSERVER-Files.zip`  
  Contains only PHP/HTML/CSS/JS files to deploy on a web server (Apache2 + PHP, or IIS + PHP module).

#### 1. Deploy the API server (ADSelfService-API-Server.zip)

1. Download `ADSelfService-API-Server.zip` from the releases page:  
   `https://github.com/sannier3/ADSelfService/releases`
2. Extract it into a dedicated folder on the server (e.g. `C:\ADSelfService-API` or `/opt/adselfservice-api`).
3. Run the binary (or the provided start script) once:  
   - on **first run**, if no `config.json` is present, the API generates a configuration file based on the example and exits, logging a message such as:  
     “File `config.json` created, please fill it then restart.”
4. Edit `config.json`:
   - **Ldap** section: URL/port, BindDn/BindPassword, base DNs, etc.  
   - **Security** section: `AllowedIps`, optional `InternalSharedSecret` shared with the PHP client.  
   - see [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md) for details.
5. Run the API again in **console mode** to validate configuration:
   - check logs to ensure **LDAP bind** succeeds and **StartupCheck** passes.  
   - test `GET /health` from an allowed IP.
6. (Optional) Install the server as a **Windows service**:
   - open an elevated command prompt (**Run as administrator**) in the publish folder, then execute:  
     - `ADSelfService-API.Server.exe --add-service`  
     - this creates a `ADSelfServiceAPI` service (automatic start) **and starts it immediately**.
   - to remove it later:  
     - `ADSelfService-API.Server.exe --remove-service`
   - restart behaviour on failure can then be tuned in `services.msc` (tab **Recovery**).
7. Integrate the binary into your usual hosting:
   - Windows service, systemd unit, or a service manager (NSSM, etc.).  
   - ensure the service account can reach LDAP/LDAPS.

#### 2. Deploy the PHP client (ADSelfService-WEBSERVER-Files.zip)

1. Download `ADSelfService-WEBSERVER-Files.zip` from GitHub releases.
2. Extract it into a directory served by your web server, for example:
   - Apache2/Linux: `/var/www/adselfservice`
   - IIS/Windows: `C:\inetpub\wwwroot\adselfservice`
3. Ensure protection files are active:
   - `.htaccess` on Apache (blocks `.sqlite`, `rl_logs`, `data`, config files, `.env`, `.log`).  
   - `web.config` on IIS (equivalent rules).
4. Create the client configuration:
   - copy `config-intranet-default.php` to `config-intranet.php`.
   - edit `config-intranet.php`:
     - `API_BASE`: public URL of the API (e.g. `http://192.168.100.10:5000`).  
     - `INTERNAL_SHARED_SECRET`: shared secret identical to `InternalSharedSecret` on the API side (if used).  
     - hCaptcha options, IP rate-limit, mail sending mode (`MAIL_MODE`, `MAILER_API_URL`, `MAILER_API_KEY`, `MAIL_FROM`), Twilio, etc.
5. Ensure the database/log directory is **writable** by PHP if you use SQLite for the “tools” feature:
   - the `intranet.sqlite` file (or equivalent) and `rl_logs` directory must be creatable.
6. Browse to `intranet.php`:
   - test login with a domain user account.  
   - test the **Admin** tab with an account in the AD admin group.

### Method 2 — from source (development / customization)

- **API**: clone the repo, customize if needed, then publish with `dotnet publish` (or from Visual Studio). Place **config.json** next to the executable (or at the path read at startup). Ensure the service account can reach the network (LDAP/LDAPS) and that **AllowedIps** includes client IP(s).
- **PHP client**: use the `WEB-CLIENT-PHP` folder from the repo, deploy it on a web server (IIS, Apache, nginx), PHP 8+, and configure **config-intranet.php** (API_BASE, secret, etc.). Keep the provided **.htaccess** (Apache) and **web.config** (IIS) to block access to SQLite, `rl_logs`, and config files. Ideally the PHP server and API are on an internal network and only users hit the browser (HTTPS).

---

## Troubleshooting

| Issue | Check |
|-------|--------|
| **403 Forbidden** on API | Ensure client (or proxy) IP is in **Security.AllowedIps**. |
| **LDAP connection failure at startup** | Check Url, Port, Ssl, BindDn/BindPassword; for Kerberos use FQDN and UPN format. See [LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md). |
| **Password change rejected** | Over plain LDAP (389 without Kerberos), AD may refuse. Enable **UseKerberosSealing** or use LDAPS. |
| **PHP client: “Configuration not found”** | Ensure **config-intranet.php** exists and **API_BASE** and **INTERNAL_SHARED_SECRET** are set (no default placeholders). |
| **Windows service does not start / stops immediately** | Run `ADSelfService-API.Server.exe` **without arguments** in console mode to see startup errors (invalid config, LDAP failure, IP not allowed, etc.). Also check logs in `Debug.LogDir`. |

API logs (folder set by **Debug.LogDir**) and web/PHP server logs help with diagnosis. When in doubt, always test in console mode first before adjusting the Windows service.

---

## Detailed documentation

| Document | Content |
|----------|---------|
| [CONFIG-OPTIONS.md](CONFIG-OPTIONS.md) | All **config.json** options. |
| [ADSelfService-API.Server/LDAP-CONFIG.md](ADSelfService-API.Server/LDAP-CONFIG.md) | LDAPS vs LDAP + Kerberos. |
| [ADSelfService-API.Server/ENDPOINTS.md](ADSelfService-API.Server/ENDPOINTS.md) | Full endpoint list, parameters, and responses. |

---

## Languages

- **English**: this file (README.en.md).
- **Français**: [README.md](README.md).
