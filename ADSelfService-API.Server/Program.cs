using Serilog;
using Serilog.Events;
using System;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using static System.Net.WebRequestMethods;
using File = System.IO.File;
using LdapException = System.DirectoryServices.Protocols.LdapException;

namespace ADSelfService_API.Server;

public class Program
{
    public const string AppVersion = "1.00.00";
    // =======================
    //  Config models
    // =======================
    public class AppConfig
    {
        public LdapConfig Ldap { get; set; } = new();
        public DebugConfig Debug { get; set; } = new();
        public SecurityConfig Security { get; set; } = new();
        public PaginationConfig Pagination { get; set; } = new();
        public ServerConfig Server { get; set; } = new();
        public StartupCheckConfig StartupCheck { get; set; } = new();
    }

    public class LdapConfig
    {
        public string Url { get; set; } = "dc01.example.local"; // IMPORTANT: For Kerberos, use the FQDN, not the IP!
        public int Port { get; set; } = 389; // 389 for Kerberos, 636 for LDAPS
        public bool Ssl { get; set; } = false;

        // Enables "Sign & Seal" to simulate a secure connection on port 389
        public bool UseKerberosSealing { get; set; } = true;

        public bool IgnoreCertificate { get; set; } = true;

        // IMPORTANT: For Kerberos, BindDn must be "user@domain" or "DOMAIN\User"
        // If you use a full DN (CN=...), Kerberos may fail.
        public string BindDn { get; set; } = "administrateur@example.local";
        public string BindPassword { get; set; } = "ChangeMe!";

        // Default base DN for USERS
        public string BaseDn { get; set; } = "OU=Infra,DC=example,DC=local";
        // Dedicated base DN for GROUPS
        public string GroupBaseDn { get; set; } = "CN=Users,DC=example,DC=local";
        // Root (useful in some scenarios)
        public string RootDn { get; set; } = "DC=example,DC=local";
        public string AdminGroupDn { get; set; } = "CN=ADSyncAdmins,CN=Users,DC=example,DC=local";
    }

    public class DebugConfig
    {
        public bool Enabled { get; set; } = true;
        public bool ShowPasswords { get; set; } = false;
        public string LogDir { get; set; } = "logs";
        public bool Console { get; set; } = true;
    }

    public class SecurityConfig
    {
        public List<string> AllowedIps { get; set; } = new() { "127.0.0.1", "::1" };
        public string? InternalSharedSecret { get; set; } = null;
        public bool RequireAppContextHeader { get; set; } = true;
    }

    public class PaginationConfig
    {
        public bool Enabled { get; set; } = true;
        public int PageSize { get; set; } = 200;
    }

    public class ServerConfig
    {
        public List<string> Urls { get; set; } = new() { "http://0.0.0.0:5000" };
    }

    public class StartupCheckConfig
    {
        public bool Enabled { get; set; } = true;
        public bool FailFast { get; set; } = true;
        public bool ShowDetailsInConsole { get; set; } = false;
    }

    // =======================
    //  Request models
    // =======================
    public record AuthRequest(
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("password")] string Password);

    public record UpdateProfileRequest(
        [property: JsonPropertyName("dn")] string Dn,
        [property: JsonPropertyName("modifications")] Dictionary<string, string> Modifications);

    public record ChangePasswordRequest(
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("currentPassword")] string CurrentPassword,
        [property: JsonPropertyName("newPassword")] string NewPassword);

    public record ChangeAdminPasswordRequest(
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("newPassword")] string NewPassword,
        [property: JsonPropertyName("mustChangeAtNextLogon")] bool? MustChangeAtNextLogon);

    public record CreateUserRequest(
        string OuDn,
        string Cn,
        string Sam,
        string GivenName,
        string Sn,
        string UserPrincipalName,
        string? Mail,
        string Password,
        bool Enabled = true,
        string? Description = null,
        DateTimeOffset? ExpiresAt = null,   // ISO 8601 (ex: "2025-12-31T23:59:59Z")
        bool NeverExpires = false,
        /// <summary>Source user sAM (cloning) — used to recompute UPN when needed.</summary>
        string? CloneSourceSam = null,
        /// <summary>UPN de l’utilisateur source (clonage).</summary>
        string? CloneSourceUserPrincipalName = null
    );

    public record SetUserGroupsRequest(string User, List<string> Groups);
    public record SetGroupMembersRequest(string Group, List<string> Members);

    public record AdminUpdateUserRequest(string User, Dictionary<string, string?> Attributes);

    public record SetUserEnabledRequest(string User, bool Enabled);

    public record MoveUserRequest(string User, string NewOuDn);

    public record UnlockUserRequest(string User);

    public record RenameCnRequest(string User, string NewCn);

    public record DeleteUserRequest(string User);

    public record CreateGroupRequest(
        string OuDn,
        string Cn,
        string? Sam,
        string Scope = "Global",
        bool SecurityEnabled = true,
        string? Description = null
    );

    public record SetAccountExpirationRequest(
        string User,                 // sAMAccountName ou DN
        DateTimeOffset? ExpiresAt,   // si null et Never==true => jamais
        bool? Never                  // true => jamais, false => applique ExpiresAt
    );

    /// <summary>User (sAM or DN) and target group (sAM, CN, or DN) to set the AD primary group.</summary>
    public record SetUserPrimaryGroupRequest(string User, string Group);

    // === OU MODELS ===
    public record CreateOuRequest(
        string ParentDn,              // Parent DN (must be under baseDn)
        string Name,                  // nom de l'OU (RDN)
        string? Description = null,
        bool? Protected = null        // if true => mark protected (logical flag)
    );

    public sealed class UpdateOuRequest
    {
        public string OuDn { get; set; } = "";
        public string? NewName { get; set; }          // optional
        public string? Description { get; set; }      // null = leave unchanged; "" = remove
        public bool? Protected { get; set; }          // optional
        public string? NewParentDn { get; set; }      // optional
    }

    public record DeleteOuRequest(
        string OuDn                   // OU DN to delete (must be empty and not protected)
    );

    public record DeleteGroupRequest(string? Group, string? Dn);

    // =======================
    //  Helpers
    // =======================
    static string AppBase => AppContext.BaseDirectory;
    static string DefaultConfigJsonPath => Path.Combine(AppBase, "config.json");
    static string DefaultConfigYamlPath => Path.Combine(AppBase, "config.yaml");

    static bool TestLdapTcpConnectivity(AppConfig cfg, out string? error)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(cfg.Ldap.Url, cfg.Ldap.Port);
            if (!connectTask.Wait(TimeSpan.FromSeconds(5)))
            {
                error = $"Timeout de connexion TCP vers {cfg.Ldap.Url}:{cfg.Ldap.Port}.";
                return false;
            }

            if (!client.Connected)
            {
                error = $"Impossible de se connecter à {cfg.Ldap.Url}:{cfg.Ldap.Port}.";
                return false;
            }

            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    static int ComputeGroupType(string scope, bool security)
    {
        const int GLOBAL_GROUP = 0x00000002;
        const int DOMAIN_LOCAL_GROUP = 0x00000004;
        const int UNIVERSAL_GROUP = 0x00000008;
        const int SECURITY_ENABLED = unchecked((int)0x80000000);

        int baseFlag = scope.Equals("DomainLocal", StringComparison.OrdinalIgnoreCase) ? DOMAIN_LOCAL_GROUP
                     : scope.Equals("Universal", StringComparison.OrdinalIgnoreCase) ? UNIVERSAL_GROUP
                     : GLOBAL_GROUP; // default: Global

        return security ? (baseFlag | SECURITY_ENABLED) : baseFlag;
    }

    static void BootstrapLogger(string logDir)
    {
        Directory.CreateDirectory(logDir);
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.File(
                path: Path.Combine(logDir, "log-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30,
                restrictedToMinimumLevel: LogEventLevel.Debug,
                shared: true)
            .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
            .CreateLogger();
    }

    static string DefaultConfigJson(AppConfig c) =>
        JsonSerializer.Serialize(c, new JsonSerializerOptions { WriteIndented = true });

    static AppConfig CreateDefaultConfig() => new AppConfig();

    static (AppConfig? cfg, string? error, bool created) LoadConfig()
    {
        if (!File.Exists(DefaultConfigJsonPath) && !File.Exists(DefaultConfigYamlPath))
        {
            var def = CreateDefaultConfig();
            File.WriteAllText(DefaultConfigJsonPath, DefaultConfigJson(def));
            return (def, null, true);
        }

        try
        {
            if (File.Exists(DefaultConfigJsonPath))
            {
                var text = File.ReadAllText(DefaultConfigJsonPath);
                var cfg = JsonSerializer.Deserialize<AppConfig>(text);
                if (cfg == null) return (null, "Fichier config.json invalide (désérialisation nulle).", false);
                return (cfg, null, false);
            }
            else
            {
                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(CamelCaseNamingConvention.Instance)
                    .Build();
                using var reader = new StreamReader(DefaultConfigYamlPath);
                var ycfg = deserializer.Deserialize<AppConfig>(reader);
                if (ycfg == null) return (null, "Fichier config.yaml invalide (désérialisation nulle).", false);
                return (ycfg, null, false);
            }
        }
        catch (JsonException je)
        {
            return (null, $"Erreur de format JSON dans config.json : {je.Message}", false);
        }
        catch (YamlDotNet.Core.YamlException ye)
        {
            return (null, $"Erreur de format YAML dans config.yaml : {ye.Message}", false);
        }
        catch (Exception ex)
        {
            return (null, $"Erreur de lecture de configuration : {ex.Message}", false);
        }
    }

    static List<string> ValidateConfig(AppConfig c)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(c.Ldap.Url)) errors.Add("ldap.url manquant.");
        if (c.Ldap.Port <= 0 || c.Ldap.Port > 65535) errors.Add("ldap.port doit être entre 1 et 65535.");
        if (string.IsNullOrWhiteSpace(c.Ldap.BindDn)) errors.Add("ldap.bindDn manquant.");
        if (string.IsNullOrWhiteSpace(c.Ldap.BindPassword)) errors.Add("ldap.bindPassword manquant.");
        if (string.IsNullOrWhiteSpace(c.Ldap.BaseDn)) errors.Add("ldap.baseDn manquant.");
        if (string.IsNullOrWhiteSpace(c.Ldap.RootDn)) errors.Add("ldap.rootDn manquant.");
        if (string.IsNullOrWhiteSpace(c.Ldap.GroupBaseDn)) errors.Add("ldap.groupBaseDn manquant.");
        if (string.IsNullOrWhiteSpace(c.Ldap.AdminGroupDn)) errors.Add("ldap.adminGroupDn manquant.");
        if (c.Pagination.PageSize <= 0) errors.Add("pagination.pageSize doit être > 0.");
        if (!c.Ldap.Ssl && !c.Ldap.UseKerberosSealing)
            errors.Add("Activez ldap.ssl=true ou ldap.useKerberosSealing=true pour éviter un transport LDAP non protégé.");
        if (!string.IsNullOrWhiteSpace(c.Security.InternalSharedSecret) && c.Security.InternalSharedSecret.Trim().Length < 32)
            errors.Add("security.internalSharedSecret doit faire au moins 32 caractères.");
        if (c.Debug.ShowPasswords)
            errors.Add("debug.showPasswords=true est interdit pour des raisons de sécurité.");

        foreach (var ip in c.Security.AllowedIps)
        {
            if (ip.Equals("localhost", StringComparison.OrdinalIgnoreCase)) continue;
            if (ip.Contains('/'))
            {
                var parts = ip.Split('/');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out _) || !int.TryParse(parts[1], out _))
                    errors.Add($"security.allowedIps entrée CIDR invalide: {ip}");
            }
            else
            {
                if (!IPAddress.TryParse(ip, out _))
                    errors.Add($"security.allowedIps IP invalide: {ip}");
            }
        }
        return errors;
    }

    static bool IsLikelyDefault(AppConfig c)
    {
        bool placeholderPwd = string.Equals(c.Ldap.BindPassword, "ChangeMe!", StringComparison.Ordinal);
        bool placeholderSecret = string.IsNullOrWhiteSpace(c.Security.InternalSharedSecret) ||
            c.Security.InternalSharedSecret.Contains("example", StringComparison.OrdinalIgnoreCase);
        bool exampleDn =
            (c.Ldap.RootDn?.Contains("example", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (c.Ldap.BindDn?.Contains("example", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (c.Ldap.BaseDn?.Contains("example", StringComparison.OrdinalIgnoreCase) ?? false);
        return placeholderPwd || exampleDn || placeholderSecret;
    }
    static List<string> SecurityWarnings(AppConfig c)
    {
        var warnings = new List<string>();
        if (c.Ldap.Ssl && c.Ldap.IgnoreCertificate)
            warnings.Add("ldap.ignoreCertificate=true: vérification TLS désactivée.");
        if (c.Debug.Enabled && c.Server.Urls.Any(u =>
            !u.Contains("127.0.0.1", StringComparison.OrdinalIgnoreCase)
            && !u.Contains("localhost", StringComparison.OrdinalIgnoreCase)
            && !u.Contains("[::1]", StringComparison.OrdinalIgnoreCase)))
            warnings.Add("debug.enabled=true avec écoute non locale: désactivez debug en production.");
        return warnings;
    }
    static bool DnIsStrictlyUnder(string child, string parent)
    => !child.Equals(parent, StringComparison.OrdinalIgnoreCase)
       && DnIsUnder(child, parent);

    static string MaskPasswords(string body, bool showPasswords)
    {
        if (showPasswords) return body;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            Dictionary<string, object?> map = new();
            foreach (var p in root.EnumerateObject())
            {
                if (p.NameEquals("password") || p.NameEquals("newPassword") || p.NameEquals("currentPassword") || p.NameEquals("bindPassword"))
                    map[p.Name] = "***";
                else
                    map[p.Name] = p.Value.ValueKind switch
                    {
                        JsonValueKind.String => p.Value.GetString(),
                        JsonValueKind.Number => p.Value.GetDouble(),
                        JsonValueKind.True => true,
                        JsonValueKind.False => false,
                        _ => p.Value.GetRawText()
                    };
            }
            return JsonSerializer.Serialize(map);
        }
        catch
        {
            return body.Replace("password", "*****", StringComparison.OrdinalIgnoreCase);
        }
    }

    // RFC4515 escaping
    static string EscapeLdapFilterValue(string value)
    {
        if (value == null) return string.Empty;
        var sb = new StringBuilder();
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append(@"\5c"); break;
                case '*': sb.Append(@"\2a"); break;
                case '(': sb.Append(@"\28"); break;
                case ')': sb.Append(@"\29"); break;
                case '\0': sb.Append(@"\00"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    static string EscapeRdnValue(string value)
    {
        if (value is null) return "";
        var sb = new StringBuilder(value.Length);

        foreach (var c in value)
        {
            switch (c)
            {
                case ',':
                case '+':
                case '"':
                case '\\':
                case '<':
                case '>':
                case ';':
                case '=':
                    sb.Append('\\').Append(c); break;
                default:
                    sb.Append(c); break;
            }
        }

        // Escape leading spaces
        int i = 0;
        while (i < sb.Length && sb[i] == ' ')
        {
            sb.Insert(i, '\\');
            i += 2; // skip "\ "
        }

        // Escape trailing spaces
        int j = sb.Length - 1;
        while (j >= 0 && sb[j] == ' ')
        {
            sb.Insert(j, '\\'); // insert backslash BEFORE the space
            j -= 1;
        }

        // Per RFC4514: '#' only when at start of value
        if (sb.Length > 0 && sb[0] == '#')
            sb.Insert(0, '\\');

        return sb.ToString();
    }

    static LdapConnection GetLdapConnection(AppConfig cfg)
    {
        // For Kerberos, using the DNS name (FQDN) instead of the IP is critical.
        // Kerberos uses the SPN (Service Principal Name) derived from the machine name.
        var identifier = new LdapDirectoryIdentifier(cfg.Ldap.Url, cfg.Ldap.Port);

        // Build credentials
        // Note: if BindDn is a full DN (CN=...), it often forces NTLM or Basic.
        // For pure Kerberos, prefer UPN (user@domain.local) or Down-Level (DOMAIN\User).
        var credentials = new NetworkCredential(cfg.Ldap.BindDn, cfg.Ldap.BindPassword);

        var connection = new LdapConnection(identifier, credentials);

        connection.SessionOptions.ProtocolVersion = 3;
        connection.Timeout = TimeSpan.FromSeconds(30);

        if (cfg.Ldap.Ssl)
        {
            // Case 1: LDAPS (SSL on port 636)
            connection.SessionOptions.SecureSocketLayer = true;

            // With SSL, Negotiate (recommended) or Basic may be used.
            connection.AuthType = AuthType.Negotiate;

            if (cfg.Ldap.IgnoreCertificate)
            {
                connection.SessionOptions.VerifyServerCertificate = (con, cer) => true;
            }
        }
        else if (cfg.Ldap.UseKerberosSealing)
        {
            // Case 2: LDAP + Kerberos (secure channel simulation on port 389)
            connection.SessionOptions.SecureSocketLayer = false;

            // Here we "simulate" the secure bind path
            connection.AuthType = AuthType.Negotiate; // Force Kerberos/GSSAPI

            // Enable packet encryption (Seal) and signing (Sign)
            // AD will accept password changes when these are enabled.
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
        }
        else
        {
            // Case 3: plain LDAP (less secure; password changes not supported)
            connection.AuthType = AuthType.Basic;
            connection.SessionOptions.SecureSocketLayer = false;
        }

        return connection;
    }

    static bool BindServiceAccount(LdapConnection connection, AppConfig cfg)
    {
        try
        {
            Log.Debug("[BindServiceAccount] Tentative de bind sur {Host}:{Port} (SSL={Ssl}, Seal={Seal})",
                cfg.Ldap.Url, cfg.Ldap.Port, cfg.Ldap.Ssl, cfg.Ldap.UseKerberosSealing);

            // In Negotiate/Kerberos mode, Bind() with no args uses the constructor NetworkCredential
            if (connection.AuthType == AuthType.Negotiate)
            {
                connection.Bind();
            }
            else
            {
                // In Basic (or fallback) mode, pass credentials explicitly
                connection.Bind(new NetworkCredential(cfg.Ldap.BindDn, cfg.Ldap.BindPassword));
            }

            Log.Debug("[BindServiceAccount] Bind OK.");
            return true;
        }
        catch (LdapException lex)
        {
            Log.Error(lex, "[BindServiceAccount] Echec bind LDAP (Code: {Code}). Message: {Msg}", lex.ErrorCode, lex.Message);
            return false;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[BindServiceAccount] Echec bind générique.");
            return false;
        }
    }

    static byte[] EncodePassword(string newPassword) => Encoding.Unicode.GetBytes($"\"{newPassword}\"");

    static object? SearchUserBySam(AppConfig cfg, string sam)
    {
        try
        {
            using var connection = GetLdapConnection(cfg);
            if (!BindServiceAccount(connection, cfg)) return null;

            string safeSam = EscapeLdapFilterValue(sam);
            // People only (not computers). Disabled accounts are NOT excluded.
            string filter = $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safeSam}))";

            var request = new SearchRequest(
                cfg.Ldap.BaseDn,
                filter,
                SearchScope.Subtree,
                new[] { "dn", "sAMAccountName", "givenName", "sn", "mail", "memberOf", "pwdLastSet", "userAccountControl", "telephoneNumber", "wWWHomePage", "streetAddress", "objectGUID" }
            );
            var response = (SearchResponse)connection.SendRequest(request);
            if (response.Entries.Count == 0) return null;

            var entry = response.Entries[0];
            byte[]? guidBin = entry.Attributes["objectGUID"]?[0] as byte[];
            Guid? objectGuid = guidBin != null ? new Guid(guidBin) : null;

            return new
            {
                dn = entry.DistinguishedName,
                sAMAccountName = entry.Attributes["sAMAccountName"]?[0]?.ToString(),
                givenName = entry.Attributes["givenName"]?[0]?.ToString(),
                sn = entry.Attributes["sn"]?[0]?.ToString(),
                mail = entry.Attributes["mail"]?[0]?.ToString(),
                memberOf = entry.Attributes["memberOf"],
                pwdLastSet = entry.Attributes["pwdLastSet"]?[0]?.ToString(),
                userAccountControl = entry.Attributes["userAccountControl"]?[0]?.ToString(),
                telephoneNumber = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                wwwhomepage = entry.Attributes["wWWHomePage"]?[0]?.ToString(),
                streetAddress = entry.Attributes["streetAddress"]?[0]?.ToString(),
                objectGUID = objectGuid
            };
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[SearchUserBySam] Exception");
            return null;
        }
    }

    static void ChangeUserPassword(AppConfig cfg, string dn, string newPassword, Action<Exception?> cb)
    {
        try
        {
            Log.Information("[ChangeUserPassword] DN={DN}", dn);
            var change = new DirectoryAttributeModification
            {
                Operation = DirectoryAttributeOperation.Replace,
                Name = "unicodePwd"
            };
            change.Add(EncodePassword(newPassword));
            var request = new ModifyRequest(dn, change);

            using var connection = GetLdapConnection(cfg);
            if (!BindServiceAccount(connection, cfg)) { cb(new Exception("Bind LDAP échoué.")); return; }
            _ = (ModifyResponse)connection.SendRequest(request);
            cb(null);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[ChangeUserPassword] Exception");
            cb(ex);
        }
    }

    static bool SetPwdLastSet(AppConfig cfg, string dn, long value /* 0 => must change, -1 => not required */)
    {
        try
        {
            var mod = new DirectoryAttributeModification
            {
                Operation = DirectoryAttributeOperation.Replace,
                Name = "pwdLastSet"
            };
            mod.Add(value.ToString());
            using var connection = GetLdapConnection(cfg);
            if (!BindServiceAccount(connection, cfg)) return false;
            var req = new ModifyRequest(dn, mod);
            _ = (ModifyResponse)connection.SendRequest(req);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[SetPwdLastSet] Exception");
            return false;
        }
    }

    static bool SetUserEnabled(AppConfig cfg, string userDn, bool enabled, int? currentUac = null)
    {
        try
        {
            int uac = currentUac ?? 512; // NORMAL_ACCOUNT (fallback)
            if (enabled)
                uac = (uac & ~2); // clear ACCOUNTDISABLE (bit 2)
            else
                uac = (uac | 2);  // set ACCOUNTDISABLE

            var mod = new DirectoryAttributeModification
            {
                Operation = DirectoryAttributeOperation.Replace,
                Name = "userAccountControl"
            };
            mod.Add(uac.ToString());

            using var connection = GetLdapConnection(cfg);
            if (!BindServiceAccount(connection, cfg)) return false;
            var req = new ModifyRequest(userDn, mod);
            _ = (ModifyResponse)connection.SendRequest(req);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[SetUserEnabled] Exception");
            return false;
        }
    }

    static bool IsIpAllowed(IPAddress remoteIp, SecurityConfig sec)
    {
        var allowed = new HashSet<string>(sec.AllowedIps, StringComparer.OrdinalIgnoreCase);
        if (allowed.Contains("localhost"))
        {
            allowed.Add("127.0.0.1");
            allowed.Add("::1");
        }

        foreach (var a in allowed)
        {
            if (a.Equals("0.0.0.0")) return true;

            if (a.Contains('/'))
            {
                var parts = a.Split('/');
                if (!IPAddress.TryParse(parts[0], out var baseIp) || !int.TryParse(parts[1], out var cidr)) continue;
                if (baseIp.AddressFamily != remoteIp.AddressFamily) continue;
                if (remoteIp.AddressFamily == AddressFamily.InterNetwork && IsInSameSubnetIPv4(remoteIp, baseIp, cidr))
                    return true;
            }
            else
            {
                if (IPAddress.TryParse(a, out var ip) && ip.Equals(remoteIp)) return true;
            }
        }
        return false;
    }

    static bool IsInSameSubnetIPv4(IPAddress address, IPAddress subnet, int cidr)
    {
        var addr = BitConverter.ToUInt32(address.GetAddressBytes().Reverse().ToArray(), 0);
        var sub = BitConverter.ToUInt32(subnet.GetAddressBytes().Reverse().ToArray(), 0);
        uint mask = cidr == 0 ? 0 : uint.MaxValue << (32 - cidr);
        return (addr & mask) == (sub & mask);
    }
    static string GetRequestAppContext(HttpContext context)
        => (context.Request.Headers["X-App-Context"].FirstOrDefault() ?? "").Trim().ToLowerInvariant();

    static bool IsRequestContextAllowed(HttpContext context, SecurityConfig security)
    {
        if (!security.RequireAppContextHeader) return true;

        var path = (context.Request.Path.Value ?? "").ToLowerInvariant();
        if (path == "/health") return true;

        var appCtx = GetRequestAppContext(context);
        if (string.IsNullOrWhiteSpace(appCtx)) return false;

        if (path == "/auth") return appCtx == "intranet-login";
        if (path == "/recovery/lookup") return appCtx == "forgot-reset";

        if (path.StartsWith("/explorer/") || path == "/tree" || path == "/meta/ad" || path == "/groups" ||
            path.StartsWith("/admin/ou/") || path == "/admin/creategroup" || path == "/admin/deletegroup")
            return appCtx == "admin-domain";

        if (path.StartsWith("/admin/"))
        {
            if (path == "/admin/changepassword")
                return appCtx is "admin-user" or "admin-domain" or "forgot-reset";
            return appCtx is "admin-user" or "admin-domain";
        }

        if (path.StartsWith("/user/") || path.StartsWith("/users"))
            return appCtx is "self-service" or "admin-user" or "admin-domain";

        // By default, reject calls without a known application context.
        return false;
    }

    static string? NormalizeFrenchPhone(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var compact = Regex.Replace(raw, @"[^\d\+]", "");
        if (string.IsNullOrWhiteSpace(compact)) return null;

        if (compact.StartsWith("+"))
        {
            return Regex.IsMatch(compact, @"^\+33[1-9]\d{8}$") ? compact : null;
        }

        var digits = Regex.Replace(compact, @"\D+", "");
        if (digits.Length == 10 && digits[0] == '0')
        {
            var e164 = "+33" + digits[1..];
            return Regex.IsMatch(e164, @"^\+33[1-9]\d{8}$") ? e164 : null;
        }
        if (digits.Length == 11 && digits.StartsWith("33"))
        {
            var e164 = "+" + digits;
            return Regex.IsMatch(e164, @"^\+33[1-9]\d{8}$") ? e164 : null;
        }
        if (digits.Length == 12 && digits.StartsWith("0033"))
        {
            var e164 = "+" + digits[2..];
            return Regex.IsMatch(e164, @"^\+33[1-9]\d{8}$") ? e164 : null;
        }
        return null;
    }

    // Attributes accepted by /user/updateProfile (kept aligned with both PHP intranet clients).
    static readonly HashSet<string> UserProfileAllowedAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "mail",
        "givenName",
        "sn",
        "telephoneNumber",
        "wWWHomePage",
        "streetAddress",
        "description"
    };

    // Attributes accepted by /admin/updateUser.
    // Intentionally broader than self-service but limited to what current intranet clients use.
    static readonly HashSet<string> AdminUpdateAllowedAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "mail",
        "givenName",
        "sn",
        "telephoneNumber",
        "wWWHomePage",
        "streetAddress",
        "description",
        "manager"
    };
    static List<string> GetMemberOfDns(DirectoryAttribute? memberOfAttr)
    {
        var res = new List<string>();
        if (memberOfAttr == null) return res;

        foreach (var v in memberOfAttr)
        {
            switch (v)
            {
                case null:
                    break;
                case byte[] bytes:
                    // Values should be text DNs; try UTF-8 then UTF-16, else keep as base64.
                    try
                    {
                        res.Add(Encoding.UTF8.GetString(bytes));
                    }
                    catch
                    {
                        try { res.Add(Encoding.Unicode.GetString(bytes)); }
                        catch { res.Add(Convert.ToBase64String(bytes)); }
                    }
                    break;
                default:
                    res.Add(v.ToString() ?? "");
                    break;
            }
        }

        return res.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
    }

    static List<string> CnsFromDns(IEnumerable<string> dns)
    {
        var list = new List<string>();
        foreach (var dn in dns)
        {
            if (string.IsNullOrWhiteSpace(dn)) continue;
            var first = dn.Split(',')[0];
            var cn = first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? first.Substring(3) : first;
            if (!string.IsNullOrWhiteSpace(cn)) list.Add(cn);
        }
        return list;
    }

    static bool IsAdminFromMemberOfDns(IEnumerable<string> memberOfDns, AppConfig cfg)
    {
        var adminDn = cfg.Ldap.AdminGroupDn ?? string.Empty;

        // 1) match DN exact
        if (!string.IsNullOrEmpty(adminDn) &&
            memberOfDns.Any(dn => dn.Equals(adminDn, StringComparison.OrdinalIgnoreCase)))
            return true;

        // 2) match CN (when AdminGroupDn starts with CN=)
        var adminCn = adminDn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
            ? adminDn.Split(',')[0].Substring(3)
            : adminDn;

        if (string.IsNullOrWhiteSpace(adminCn)) return false;

        foreach (var dn in memberOfDns)
        {
            if (string.IsNullOrWhiteSpace(dn)) continue;
            var first = dn.Split(',')[0];
            var cn = first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? first.Substring(3) : first;
            if (cn.Equals(adminCn, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }
    public record LdapTreeNode(
        string name,
        string dn,
        string type,
        bool hasChildren,
        List<LdapTreeNode>? children,
        string? description = null,
        string[]? objectClasses = null,
        string? samAccountName = null
    );
    static string? DnToCn(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return null;
        var first = dn.Split(',')[0];
        if (first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ||
            first.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
            return first.Substring(3);
        return first;
    }

    static string GetNameFromEntry(SearchResultEntry e)
    {
        return e.Attributes["ou"]?[0]?.ToString()
            ?? e.Attributes["cn"]?[0]?.ToString()
            ?? e.Attributes["name"]?[0]?.ToString()
            ?? DnToCn(e.DistinguishedName) ?? e.DistinguishedName;
    }

    /// <summary>
    /// Reads <c>objectClass</c> via <c>DirectoryAttribute.GetValues(typeof(string))</c>: enumerating LDAP values
    /// directly can omit classes and misclassify everything as "other".
    /// </summary>
    static HashSet<string> GetObjectClassNameSet(SearchResultEntry e)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var oc = e.Attributes["objectClass"];
        if (oc is null) return set;
        try
        {
            foreach (var v in oc.GetValues(typeof(string)).Cast<string>())
            {
                if (!string.IsNullOrWhiteSpace(v)) set.Add(v);
            }
        }
        catch
        {
            for (int i = 0; i < oc.Count; i++)
            {
                var v = oc[i]?.ToString();
                if (!string.IsNullOrWhiteSpace(v)) set.Add(v);
            }
        }
        return set;
    }

    /// <summary>
    /// Fallback when <c>objectClass</c> is incomplete (<c>objectCategory</c> is reliable on AD).
    /// </summary>
    static string? InferTypeFromObjectCategory(SearchResultEntry e)
    {
        var cat = e.Attributes["objectCategory"]?[0]?.ToString();
        if (string.IsNullOrWhiteSpace(cat)) return null;
        if (cat.Contains("Organizational-Unit", StringComparison.OrdinalIgnoreCase)) return "ou";
        if (cat.Contains("Domain-DNS", StringComparison.OrdinalIgnoreCase)) return "domain";
        if (cat.Contains("CN=Group,", StringComparison.OrdinalIgnoreCase)) return "group";
        if (cat.Contains("CN=Computer,", StringComparison.OrdinalIgnoreCase)) return "computer";
        if (cat.Contains("CN=Container,", StringComparison.OrdinalIgnoreCase)) return "container";
        if (cat.Contains("Builtin-Domain", StringComparison.OrdinalIgnoreCase)) return "container";
        return null;
    }

    static string GetNodeTypeFromEntry(SearchResultEntry e)
    {
        var set = GetObjectClassNameSet(e);

        if (set.Contains("domainDNS")) return "domain";
        if (set.Contains("organizationalUnit")) return "ou";
        if (set.Contains("container") || set.Contains("builtinDomain")) return "container";
        if (set.Contains("group")) return "group";
        if (set.Contains("computer")) return "computer";
        if (set.Contains("inetOrgPerson")) return "inetOrgPerson";

        var inferred = InferTypeFromObjectCategory(e);
        // Computer account: "user" is often in objectClass; objectCategory distinguishes PC vs person.
        if (string.Equals(inferred, "computer", StringComparison.OrdinalIgnoreCase)) return "computer";
        if (set.Contains("user")) return "user";
        if (!string.IsNullOrWhiteSpace(inferred)) return inferred!;

        return "other";
    }

    static string[] GetObjectClassesFromEntry(SearchResultEntry e)
    {
        var oc = e.Attributes["objectClass"];
        if (oc is null) return Array.Empty<string>();
        try
        {
            return oc.GetValues(typeof(string)).Cast<string>().Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
        }
        catch
        {
            var list = new List<string>(oc.Count);
            for (int i = 0; i < oc.Count; i++)
            {
                var v = oc[i]?.ToString();
                if (!string.IsNullOrWhiteSpace(v)) list.Add(v);
            }
            return list.ToArray();
        }
    }

    static bool NodeHasChildContainers(LdapConnection conn, string dn)
    {
        var check = new SearchRequest(
            dn,
            "(|(objectClass=organizationalUnit)(objectClass=container))",
            SearchScope.OneLevel,
            new[] { "distinguishedName" });
        check.SizeLimit = 1;
        var r = (SearchResponse)conn.SendRequest(check);
        return r.Entries.Count > 0;
    }

    static bool NodeHasAnyChildren(LdapConnection conn, string dn)
    {
        var check = new SearchRequest(
            dn,
            "(objectClass=*)",
            SearchScope.OneLevel,
            new[] { "distinguishedName" });
        check.SizeLimit = 1;
        var r = (SearchResponse)conn.SendRequest(check);
        return r.Entries.Count > 0;
    }

    static List<LdapTreeNode> BuildTree(LdapConnection conn, string baseDn, int depth, bool includeLeaves, int maxChildren)
    {
        return BuildLevel(conn, baseDn, depth, includeLeaves, maxChildren);
    }

    static List<LdapTreeNode> BuildLevel(LdapConnection conn, string dn, int depth, bool includeLeaves, int maxChildren)
    {
        var nodes = new List<LdapTreeNode>();

        string filter = includeLeaves
            ? "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=group)(objectClass=user)(objectClass=computer)(objectClass=inetOrgPerson))"
            : "(|(objectClass=organizationalUnit)(objectClass=container))";

        var attrs = new[] { "ou", "cn", "name", "distinguishedName", "objectClass", "description", "sAMAccountName" };

        var req = new SearchRequest(dn, filter, SearchScope.OneLevel, attrs);
        req.Controls.Add(new PageResultRequestControl(maxChildren));

        var resp = (SearchResponse)conn.SendRequest(req);
        var entries = resp.Entries.Cast<SearchResultEntry>().ToList();
        entries.Sort((a, b) => string.Compare(GetNameFromEntry(a), GetNameFromEntry(b), StringComparison.OrdinalIgnoreCase));

        foreach (var e in entries)
        {
            var name = GetNameFromEntry(e);
            var type = GetNodeTypeFromEntry(e);
            var desc = e.Attributes["description"]?[0]?.ToString();
            var objectClasses = GetObjectClassesFromEntry(e);
            var sam = e.Attributes["sAMAccountName"]?[0]?.ToString();

            if (depth > 1)
            {
                var children = BuildLevel(conn, e.DistinguishedName, depth - 1, includeLeaves, maxChildren);
                var hasChildren = includeLeaves
                    ? (children.Count > 0 || NodeHasAnyChildren(conn, e.DistinguishedName))
                    : (children.Count > 0 || NodeHasChildContainers(conn, e.DistinguishedName));
                nodes.Add(new LdapTreeNode(name, e.DistinguishedName, type, hasChildren, children, desc, objectClasses, sam));
            }
            else
            {
                var hasChildren = includeLeaves
                    ? NodeHasAnyChildren(conn, e.DistinguishedName)
                    : NodeHasChildContainers(conn, e.DistinguishedName);
                nodes.Add(new LdapTreeNode(name, e.DistinguishedName, type, hasChildren, null, desc, objectClasses, sam));
            }
        }

        return nodes;
    }

    // True if the string looks like a DN
    static bool LooksLikeDn(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        return s.Contains("DC=", StringComparison.OrdinalIgnoreCase)
            || s.Contains("OU=", StringComparison.OrdinalIgnoreCase)
            || (s.Contains("CN=", StringComparison.OrdinalIgnoreCase) && s.Contains(","));
    }

    // Group search base
    static string EffectiveExplorerBaseDn(AppConfig cfg)
        => string.IsNullOrWhiteSpace(cfg.Ldap.BaseDn) ? cfg.Ldap.RootDn : cfg.Ldap.BaseDn;

    static string EffectiveGroupBaseDn(AppConfig cfg) =>
        string.IsNullOrWhiteSpace(cfg.Ldap.GroupBaseDn) ? cfg.Ldap.RootDn : cfg.Ldap.GroupBaseDn;

    // Resolve group DN from CN / sAM / name
    static string? ResolveGroupDn(AppConfig cfg, LdapConnection connection, string input)
    {
        if (LooksLikeDn(input)) return input;

        var baseDn = EffectiveGroupBaseDn(cfg);
        var safe = EscapeLdapFilterValue(input);
        var filter = $"(&(objectClass=group)(|(cn={safe})(sAMAccountName={safe})(name={safe})))";

        var req = new SearchRequest(baseDn, filter, SearchScope.Subtree, new[] { "distinguishedName" });
        var resp = (SearchResponse)connection.SendRequest(req);
        return resp.Entries.Count > 0 ? resp.Entries[0].DistinguishedName : null;
    }

    static string? ResolveUserDn(AppConfig cfg, LdapConnection connection, string input)
    {
        if (LooksLikeDn(input)) return input;
        var safe = EscapeLdapFilterValue(input);
        var req = new SearchRequest(
            EffectiveExplorerBaseDn(cfg),
            $"(&(&(objectCategory=person)(|(objectClass=user)(objectClass=inetOrgPerson)))(sAMAccountName={safe}))",
            SearchScope.Subtree,
            new[] { "distinguishedName" }
        );
        req.SizeLimit = 1;
        var resp = (SearchResponse)connection.SendRequest(req);
        return resp.Entries.Count > 0 ? resp.Entries[0].DistinguishedName : null;
    }

    /// <summary>
    /// DNs of groups the user is a <em>direct</em> member of, including the primary group
    /// (e.g. "Domain Users"), which is missing from LDAP <c>memberOf</c>.
    /// </summary>
    static List<string> GetDirectUserGroupDns(AppConfig cfg, LdapConnection connection, string userDn)
    {
        if (!TryGetEntry(connection, userDn, out var userEntry, new[] { "memberOf", "primaryGroupID", "objectSid" }) || userEntry is null)
            return new List<string>();
        var list = userEntry.Attributes["memberOf"]?.GetValues(typeof(string)).Cast<string>()
            .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            ?? new List<string>();
        string? primaryDn = null;
        try { primaryDn = GetPrimaryGroupDn(cfg, connection, userEntry); }
        catch { /* ignore */ }
        if (!string.IsNullOrWhiteSpace(primaryDn) && !list.Exists(d => d.Equals(primaryDn, StringComparison.OrdinalIgnoreCase)))
            list.Insert(0, primaryDn);
        return list;
    }

    static List<string> GetDirectGroupMemberDns(LdapConnection connection, string groupDn)
    {
        if (!TryGetEntry(connection, groupDn, out var groupEntry, new[] { "member" }) || groupEntry is null)
            return new List<string>();
        return groupEntry.Attributes["member"]?.GetValues(typeof(string)).Cast<string>().Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
               ?? new List<string>();
    }

    static object GroupDtoFromDn(LdapConnection connection, string dn)
    {
        if (!TryGetEntry(connection, dn, out var g, new[] { "objectGUID", "cn", "name", "sAMAccountName", "distinguishedName", "description", "objectClass" }) || g is null)
        {
            return new
            {
                id = (Guid?)null,
                name = DnToCn(dn) ?? dn,
                sam = (string?)null,
                dn,
                description = (string?)null,
                type = "group"
            };
        }
        byte[]? guidBin = g.Attributes["objectGUID"]?[0] as byte[];
        Guid? guid = guidBin != null ? new Guid(guidBin) : (Guid?)null;
        return new
        {
            id = guid,
            name = g.Attributes["cn"]?[0]?.ToString() ?? g.Attributes["name"]?[0]?.ToString() ?? DnToCn(dn) ?? dn,
            sam = g.Attributes["sAMAccountName"]?[0]?.ToString(),
            dn = g.Attributes["distinguishedName"]?[0]?.ToString() ?? dn,
            description = g.Attributes["description"]?[0]?.ToString(),
            type = GetNodeTypeFromEntry(g)
        };
    }

    // All group DNs for the user via transitive membership (matching rule IN_CHAIN)
    static List<string> GetTransitiveGroupDnsForUser(AppConfig cfg, LdapConnection conn, string userDn)
    {
        string baseDn = EffectiveGroupBaseDn(cfg);
        string safeUserDn = EscapeLdapFilterValue(userDn);
        // Groups whose member (direct or nested) includes this user
        string filter = $"(member:1.2.840.113556.1.4.1941:={safeUserDn})";

        var req = new SearchRequest(
            baseDn,
            filter,
            SearchScope.Subtree,
            new[] { "distinguishedName" }
        );
        var resp = (SearchResponse)conn.SendRequest(req);

        return resp.Entries
                  .Cast<SearchResultEntry>()
                  .Select(e => e.DistinguishedName)
                  .ToList();
    }

    /// <summary>
    /// Under System.DirectoryServices.Protocols, <c>primaryGroupID</c> is often a byte array;
    /// <c>[0].ToString()</c> does not yield a parseable integer.
    /// </summary>
    static bool TryReadPrimaryGroupRid(SearchResultEntry entry, out int rid)
    {
        rid = 0;
        var a = entry.Attributes["primaryGroupID"];
        if (a is null || a.Count == 0) return false;
        var v = a[0];
        switch (v)
        {
            case int i:
                rid = i;
                return true;
            case long lng:
                rid = checked((int)lng);
                return true;
            case uint ui:
                rid = checked((int)ui);
                return true;
            case byte[] bytes:
                if (bytes.Length == 0) return false;
                if (bytes.Length >= 4)
                {
                    rid = BitConverter.ToInt32(bytes, 0);
                    return true;
                }
                for (var k = 0; k < bytes.Length; k++)
                    rid |= (bytes[k] & 0xFF) << (8 * k);
                return true;
            default:
                var s = v?.ToString();
                if (string.IsNullOrWhiteSpace(s)) return false;
                if (s.StartsWith("System.", StringComparison.Ordinal)) return false;
                return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out rid);
        }
    }

    /// <summary>Reads a numeric LDAP attribute often returned as int, long, or byte array (e.g. systemFlags).</summary>
    static bool TryParseDirectoryNumeric(object? raw, out int value)
    {
        value = 0;
        if (raw is null) return false;
        switch (raw)
        {
            case int i:
                value = i;
                return true;
            case long lng:
                value = checked((int)lng);
                return true;
            case uint ui:
                value = checked((int)ui);
                return true;
            case byte[] bytes:
                if (bytes.Length >= 4)
                {
                    value = BitConverter.ToInt32(bytes, 0);
                    return true;
                }
                for (var k = 0; k < bytes.Length; k++)
                    value |= (bytes[k] & 0xFF) << (8 * k);
                return bytes.Length > 0;
            default:
                var s = raw.ToString();
                if (string.IsNullOrWhiteSpace(s) || s.StartsWith("System.", StringComparison.Ordinal))
                    return false;
                return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }
    }

    /// <summary>LDAP systemFlags: string may exceed int.MaxValue (e.g. 2147483648); high-bit masks as uint.</summary>
    static bool TryParseDirectoryFlags(object? raw, out long value)
    {
        value = 0;
        if (raw is null) return false;
        switch (raw)
        {
            case int i:
                value = i;
                return true;
            case long lng:
                value = lng;
                return true;
            case uint ui:
                value = ui;
                return true;
            case byte[] bytes:
                if (bytes.Length >= 4)
                {
                    value = BitConverter.ToUInt32(bytes, 0);
                    return true;
                }
                for (var k = 0; k < bytes.Length; k++)
                    value |= (long)(bytes[k] & 0xFF) << (8 * k);
                return bytes.Length > 0;
            default:
                var s = raw.ToString();
                if (string.IsNullOrWhiteSpace(s) || s.StartsWith("System.", StringComparison.Ordinal))
                    return false;
                return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }
    }

    static byte[]? ReadObjectSidBytes(SearchResultEntry entry)
    {
        var a = entry.Attributes["objectSid"];
        if (a is null || a.Count == 0) return null;
        return a[0] as byte[];
    }

    static bool TryGetRidFromObjectSidBytes(byte[]? sidBytes, out int rid)
    {
        rid = 0;
        if (sidBytes is null || sidBytes.Length == 0) return false;
        try
        {
            var sid = new SecurityIdentifier(sidBytes, 0);
            var parts = sid.Value.Split('-', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return false;
            return int.TryParse(parts[^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out rid);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>True if at least one user or computer in the domain has this RID as primary group.</summary>
    static bool AnyUserOrComputerUsesPrimaryGroupRid(LdapConnection conn, string searchBaseDn, int rid)
    {
        if (string.IsNullOrWhiteSpace(searchBaseDn) || rid <= 0) return false;
        var filter = $"(&(|(objectClass=user)(objectClass=computer))(primaryGroupID={rid}))";
        var req = new SearchRequest(searchBaseDn, filter, SearchScope.Subtree, "distinguishedName");
        req.SizeLimit = 1;
        try
        {
            var resp = (SearchResponse)conn.SendRequest(req);
            return resp.Entries.Count > 0;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "[PrimaryGroupRid] Search primaryGroupID={Rid} under {Base} failed.", rid, searchBaseDn);
            return false;
        }
    }

    // Primary group DN by reconstructing group SID: domainSid + primaryGroupID
    static string? GetPrimaryGroupDn(AppConfig cfg, LdapConnection conn, SearchResultEntry userEntry)
    {
        if (!TryReadPrimaryGroupRid(userEntry, out var pgid)) return null;
        var objSidBytes = ReadObjectSidBytes(userEntry);
        if (objSidBytes is null || objSidBytes.Length == 0) return null;

        // Account domain SID, then primary group SID = domainSid + "-" + primaryGroupID
        var userSid = new System.Security.Principal.SecurityIdentifier(objSidBytes, 0);
        var domainSid = userSid.AccountDomainSid;
        if (domainSid == null) return null;

        var groupSid = new System.Security.Principal.SecurityIdentifier(domainSid.Value + "-" + pgid);

        // Lookup by objectSid (binary value escaped for filter)
        var groupSidBytes = new byte[groupSid.BinaryLength];
        groupSid.GetBinaryForm(groupSidBytes, 0);
        var sidHex = BytesToLdapHex(groupSidBytes);

        var filter = $"(&(objectClass=group)(objectSid={sidHex}))";
        var req = new SearchRequest(cfg.Ldap.RootDn, filter, SearchScope.Subtree, new[] { "distinguishedName" });
        var resp = (SearchResponse)conn.SendRequest(req);
        return resp.Entries.Count > 0 ? resp.Entries[0].DistinguishedName : null;
    }

    /// <summary>
    /// Adds the user to group <paramref name="groupDn"/>; no-op if already a member (LDAP "already exists").
    /// </summary>
    static void EnsureUserIsGroupMember(LdapConnection connection, string groupDn, string userDn)
    {
        var addMod = new DirectoryAttributeModification { Operation = DirectoryAttributeOperation.Add, Name = "member" };
        addMod.Add(userDn);
        try
        {
            _ = (ModifyResponse)connection.SendRequest(new ModifyRequest(groupDn, addMod));
        }
        catch (DirectoryOperationException doe)
        {
            var rc = doe.Response?.ResultCode ?? ResultCode.Other;
            // 20 = attributeOrValueExists, 68 = entryAlreadyExists (directory-dependent)
            if (rc == (ResultCode)20 || rc == (ResultCode)68) return;
            var em = (doe.Response?.ErrorMessage ?? doe.Message ?? "").ToLowerInvariant();
            if (em.Contains("already exists") || em.Contains("attribute or value exists") || em.Contains("exists"))
                return;
            throw;
        }
    }

    /// <summary>
    /// Sets primary group: same domain SID as user, add to group if needed, then <c>primaryGroupID</c> = group RID.
    /// </summary>
    static void SetUserPrimaryGroup(AppConfig cfg, LdapConnection connection, string userDn, string groupDn)
    {
        if (!TryGetEntry(connection, userDn, out var userEntry, new[] { "objectSid" }) || userEntry is null)
            throw new InvalidOperationException("Utilisateur introuvable.");
        if (!TryGetEntry(connection, groupDn, out var groupEntry, new[] { "objectSid" }) || groupEntry is null)
            throw new InvalidOperationException("Groupe introuvable.");

        var userSidBytes = userEntry.Attributes["objectSid"]?[0] as byte[];
        var groupSidBytes = groupEntry.Attributes["objectSid"]?[0] as byte[];
        if (userSidBytes == null || groupSidBytes == null)
            throw new InvalidOperationException("SID manquant (utilisateur ou groupe).");

        var userSid = new SecurityIdentifier(userSidBytes, 0);
        var groupSid = new SecurityIdentifier(groupSidBytes, 0);
        var userDomain = userSid.AccountDomainSid;
        var groupDomain = groupSid.AccountDomainSid;
        if (userDomain == null || groupDomain == null || !userDomain.Equals(groupDomain))
            throw new InvalidOperationException("Le groupe principal doit être un groupe de sécurité du même domaine que l’utilisateur.");

        var sidParts = groupSid.Value.Split('-');
        if (sidParts.Length < 2 || !int.TryParse(sidParts[^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var ridParsed))
            throw new InvalidOperationException("Impossible de lire le RID du groupe (objectSid).");
        int rid = ridParsed;

        EnsureUserIsGroupMember(connection, groupDn, userDn);

        var pgMod = new DirectoryAttributeModification { Operation = DirectoryAttributeOperation.Replace, Name = "primaryGroupID" };
        pgMod.Add(rid.ToString(CultureInfo.InvariantCulture));
        _ = (ModifyResponse)connection.SendRequest(new ModifyRequest(userDn, pgMod));
    }

    // Robust isAdmin: effective membership by DN (nested + primary included)
    static bool IsAdminEffective(HashSet<string> effectiveGroupDns, AppConfig cfg)
    {
        var adminDn = cfg.Ldap.AdminGroupDn ?? "";
        if (string.IsNullOrWhiteSpace(adminDn)) return false;

        // 1) DN exact
        if (effectiveGroupDns.Contains(adminDn, StringComparer.OrdinalIgnoreCase)) return true;

        // 2) CN fallback for lenient matching
        var adminCn = adminDn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
            ? adminDn.Split(',')[0].Substring(3)
            : adminDn;

        if (string.IsNullOrWhiteSpace(adminCn)) return false;

        foreach (var dn in effectiveGroupDns)
        {
            var first = dn.Split(',')[0];
            var cn = first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? first.Substring(3) : first;
            if (cn.Equals(adminCn, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    // === HELPERS FILETIME / accountExpires ===
    static bool IsNeverAccountExpiresValue(string? v)
    {
        // 0 or 9223372036854775807 => "Never" in AD
        return string.IsNullOrWhiteSpace(v) || v == "0" || v == "9223372036854775807";
    }

    static (DateTimeOffset? expiresAt, bool never) DecodeAccountExpiresFromEntry(SearchResultEntry e)
    {
        var v = e.Attributes["accountExpires"]?[0]?.ToString();
        if (IsNeverAccountExpiresValue(v)) return (null, true);

        if (long.TryParse(v, out var ft))
        {
            try
            {
                var dt = DateTime.FromFileTimeUtc(ft);
                return (new DateTimeOffset(dt, TimeSpan.Zero), false);
            }
            catch { /* ignore */ }
        }
        return (null, false);
    }

    /// <summary>pwdLastSet 0 => user must change password at next logon.</summary>
    static bool PwdMustChangeAtNextLogon(SearchResultEntry entry)
    {
        var attr = entry.Attributes["pwdLastSet"];
        if (attr is null || attr.Count == 0) return false;
        var raw = attr[0];
        if (raw is byte[] b && b.Length >= 8)
            return BitConverter.ToInt64(b, 0) == 0L;
        return long.TryParse(raw?.ToString(), out var ft) && ft == 0L;
    }

    static string ToAccountExpiresFileTime(DateTimeOffset dto)
        => dto.UtcDateTime.ToFileTimeUtc().ToString();

    static DateTimeOffset? ParseAdFileTimeUtc(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        if (!long.TryParse(v, out var ft)) return null;
        if (ft <= 0 || ft == long.MaxValue) return null;
        try
        {
            return new DateTimeOffset(DateTime.FromFileTimeUtc(ft), TimeSpan.Zero);
        }
        catch
        {
            return null;
        }
    }

    static DateTimeOffset? ParseAdGeneralizedTimeUtc(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        if (DateTimeOffset.TryParse(v, out var dto))
            return dto.ToUniversalTime();
        if (DateTime.TryParseExact(v, "yyyyMMddHHmmss.0Z", null, System.Globalization.DateTimeStyles.AssumeUniversal, out var dt1))
            return new DateTimeOffset(dt1.ToUniversalTime());
        if (DateTime.TryParseExact(v, "yyyyMMddHHmmssZ", null, System.Globalization.DateTimeStyles.AssumeUniversal, out var dt2))
            return new DateTimeOffset(dt2.ToUniversalTime());
        return null;
    }

    static async Task<string[]> ResolveHostIpsAsync(string? hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName)) return Array.Empty<string>();
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(hostName.Trim());
            return addresses
                .Select(a => a.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(8)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    static DirectoryAttributeModification BuildReplaceAccountExpires(bool never, DateTimeOffset? when)
    {
        var mod = new DirectoryAttributeModification
        {
            Operation = DirectoryAttributeOperation.Replace,
            Name = "accountExpires"
        };
        if (never) mod.Add("0");
        else if (when.HasValue) mod.Add(ToAccountExpiresFileTime(when.Value));
        else mod.Add("0"); // fallback "never"
        return mod;
    }

    // === OU HELPERS ===
    const string OU_PROTECT_MARKER = "API_PROTECTED=1";

    static bool DnIsUnder(string child, string parent)
    {
        var c = child.Trim().Trim(',');
        var p = parent.Trim().Trim(',');
        if (c.Equals(p, StringComparison.OrdinalIgnoreCase)) return true; // allow creation directly under BaseDn
        return c.EndsWith("," + p, StringComparison.OrdinalIgnoreCase);
    }

    static bool TryGetEntry(LdapConnection conn, string dn, out SearchResultEntry? entry, string[]? attrs = null)
    {
        var req = new SearchRequest(
            dn,                               // base DN — no RDN escaping needed
            "(objectClass=*)",                // catch-all filter
            SearchScope.Base,
            attrs ?? new[] { "objectClass", "objectCategory" }
        );
        var resp = (SearchResponse)conn.SendRequest(req);
        entry = resp.Entries.Count == 1 ? resp.Entries[0] : null;
        return entry is not null;
    }

    static bool EntryIsOu(SearchResultEntry e)
    {
        var oc = e.Attributes["objectClass"];
        if (oc is null) return false;
        for (int i = 0; i < oc.Count; i++)
            if (string.Equals(oc[i]?.ToString(), "organizationalUnit", StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    static bool EntryIsContainer(SearchResultEntry e)
    {
        IEnumerable<string> get(string attr) =>
            e.Attributes[attr]?.GetValues(typeof(string)).Cast<string>()
              ?? Enumerable.Empty<string>();

        var oc = new HashSet<string>(get("objectClass").Select(s => s.ToLowerInvariant()));
        if (oc.Contains("organizationalunit")) return true;  // classic OU
        if (oc.Contains("container")) return true;           // CN=Users, etc.
        if (oc.Contains("domaindns")) return true;           // domain root

        var cat = get("objectCategory").FirstOrDefault() ?? "";
        if (cat.IndexOf("CN=Organizational-Unit", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (cat.IndexOf("CN=Container", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (cat.IndexOf("CN=Domain-DNS", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        Log.Information("[OU/create] ParentDN rejected. objectClass={@oc} objectCategory={cat}", oc.ToArray(), cat);

        return false;
    }

    // "Protected": RSAT/ADUC-style DACL (DENY Everyone DELETE+DELETE_TREE on the OU, DENY DELETE_CHILD on parent),
    // plus systemFlags, API marker adminDescription, isCriticalSystemObject.
    const long SystemFlagDisallowDeleteLegacy = 0x02000000L;
    const long SystemFlagDisallowDeleteAccidental = 0x80000000L;

    /// <summary>LDAP_SERVER_SD_FLAGS_OID: BER SEQUENCE { INTEGER } with DACL_SECURITY_INFORMATION (4).</summary>
    static readonly byte[] LdapSdFlagsControlDaclOnly = { 0x30, 0x03, 0x02, 0x01, 0x04 };

    /// <summary>OWNER + GROUP + DACL (1+2+4) to read/write a consistent security descriptor.</summary>
    static readonly byte[] LdapSdFlagsControlOwnerGroupDacl = { 0x30, 0x03, 0x02, 0x01, 0x07 };

    const uint AdAccessMaskDelete = 0x0001_0000;   // ActiveDirectoryRights.Delete
    const uint AdAccessMaskDeleteTree = 0x0000_0040; // DeleteTree
    const uint AdAccessMaskDeleteChild = 0x0000_0002; // DeleteChild (on parent)

    static readonly SecurityIdentifier EveryoneSid = new(WellKnownSidType.WorldSid, null);

    static bool IsAccessDeniedAce(GenericAce ace) =>
        ace.AceType == AceType.AccessDenied || ace.AceType == AceType.AccessDeniedObject;

    static bool TryGetNtSecurityDescriptorBytes(SearchResultEntry entry, out byte[]? sdBytes)
    {
        sdBytes = null;
        var a = entry.Attributes["nTSecurityDescriptor"];
        if (a is null || a.Count == 0) return false;
        if (a[0] is byte[] b && b.Length > 0)
        {
            sdBytes = b;
            return true;
        }
        return false;
    }

    /// <summary>
    /// RSAT-style "protect from accidental deletion" on the OU: DENY Everyone DELETE and DELETE_TREE.
    /// </summary>
    static bool OuDaclHasEveryoneDenyDeleteAndDeleteTree(byte[] binarySd)
    {
        try
        {
            var sd = new RawSecurityDescriptor(binarySd, 0);
            if (sd.DiscretionaryAcl is null) return false;
            var hasDelete = false;
            var hasDeleteTree = false;
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if (!IsAccessDeniedAce(ace)) continue;
                if (ace is not QualifiedAce qa) continue;
                if (!EveryoneSid.Equals(qa.SecurityIdentifier)) continue;
                var m = unchecked((uint)qa.AccessMask);
                if ((m & AdAccessMaskDelete) != 0) hasDelete = true;
                if ((m & AdAccessMaskDeleteTree) != 0) hasDeleteTree = true;
            }
            return hasDelete && hasDeleteTree;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "OuDaclHasEveryoneDenyDeleteAndDeleteTree: parse SD");
            return false;
        }
    }

    /// <summary>On parent: DENY Everyone DELETE_CHILD (blocks deleting the child OU).</summary>
    static bool ParentDaclHasEveryoneDenyDeleteChild(byte[] binarySd)
    {
        try
        {
            var sd = new RawSecurityDescriptor(binarySd, 0);
            if (sd.DiscretionaryAcl is null) return false;
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if (!IsAccessDeniedAce(ace)) continue;
                if (ace is not QualifiedAce qa) continue;
                if (!EveryoneSid.Equals(qa.SecurityIdentifier)) continue;
                if ((unchecked((uint)qa.AccessMask) & AdAccessMaskDeleteChild) != 0)
                    return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "ParentDaclHasEveryoneDenyDeleteChild: parse SD");
            return false;
        }
    }

    static bool TryFetchNtSecurityDescriptorDacl(LdapConnection conn, string dn, out byte[]? sdBytes)
    {
        sdBytes = null;
        try
        {
            var req = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, "nTSecurityDescriptor");
            req.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.801", LdapSdFlagsControlDaclOnly, true, true));
            var resp = (SearchResponse)conn.SendRequest(req);
            if (resp.Entries.Count != 1) return false;
            return TryGetNtSecurityDescriptorBytes(resp.Entries[0], out sdBytes) && sdBytes is not null;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "TryFetchNtSecurityDescriptorDacl failed for {Dn}", dn);
            return false;
        }
    }

    static bool TryReadNtSecurityDescriptorOgd(LdapConnection conn, string dn, out byte[]? sdBytes)
    {
        sdBytes = null;
        try
        {
            var req = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, "nTSecurityDescriptor");
            req.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.801", LdapSdFlagsControlOwnerGroupDacl, true, true));
            var resp = (SearchResponse)conn.SendRequest(req);
            if (resp.Entries.Count != 1) return false;
            return TryGetNtSecurityDescriptorBytes(resp.Entries[0], out sdBytes) && sdBytes is not null;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "TryReadNtSecurityDescriptorOgd failed for {Dn}", dn);
            return false;
        }
    }

    static void WriteNtSecurityDescriptorOgd(LdapConnection conn, string dn, byte[] newSd)
    {
        var mod = new DirectoryAttributeModification
        {
            Name = "nTSecurityDescriptor",
            Operation = DirectoryAttributeOperation.Replace
        };
        mod.Add(newSd);
        var mreq = new ModifyRequest(dn, mod);
        mreq.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.801", LdapSdFlagsControlOwnerGroupDacl, true, true));
        _ = (ModifyResponse)conn.SendRequest(mreq);
    }

    static void WriteNtSecurityDescriptorDaclOnly(LdapConnection conn, string dn, byte[] newSd)
    {
        var mod = new DirectoryAttributeModification
        {
            Name = "nTSecurityDescriptor",
            Operation = DirectoryAttributeOperation.Replace
        };
        mod.Add(newSd);
        var mreq = new ModifyRequest(dn, mod);
        mreq.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.801", LdapSdFlagsControlDaclOnly, true, true));
        _ = (ModifyResponse)conn.SendRequest(mreq);
    }

    static bool IsNtSecurityDescriptorConstraint(DirectoryOperationException doe)
    {
        var msg = doe.Response?.ErrorMessage ?? doe.Message ?? "";
        if (doe.Response?.ResultCode == ResultCode.ConstraintViolation) return true;
        return msg.IndexOf("CONSTRAINT_ATT_TYPE", StringComparison.OrdinalIgnoreCase) >= 0
            || msg.IndexOf("Att 20119", StringComparison.OrdinalIgnoreCase) >= 0
            || msg.IndexOf("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    static void WriteNtSecurityDescriptorWithFallback(LdapConnection conn, string dn, byte[] newSd)
    {
        try
        {
            WriteNtSecurityDescriptorOgd(conn, dn, newSd);
        }
        catch (DirectoryOperationException doe) when (IsNtSecurityDescriptorConstraint(doe))
        {
            // Some AD setups reject O/G/DACL replacement with CONSTRAINT_ATT_TYPE on nTSecurityDescriptor.
            // Retry with DACL-only control (RSAT semantics for accidental deletion protection).
            Log.Warning(doe, "WriteNtSecurityDescriptor OGD rejected for {Dn}; fallback to DACL-only", dn);
            WriteNtSecurityDescriptorDaclOnly(conn, dn, newSd);
        }
    }

    static bool MatchesEveryoneDenyDeleteDeleteTreeOnly(System.DirectoryServices.ActiveDirectoryAccessRule r)
    {
        if (r.AccessControlType != AccessControlType.Deny) return false;
        if (!EveryoneSid.Equals((SecurityIdentifier)r.IdentityReference)) return false;
        if (r.InheritanceType != System.DirectoryServices.ActiveDirectorySecurityInheritance.None) return false;
        const System.DirectoryServices.ActiveDirectoryRights rel =
            System.DirectoryServices.ActiveDirectoryRights.Delete | System.DirectoryServices.ActiveDirectoryRights.DeleteTree;
        if ((r.ActiveDirectoryRights & rel) == 0) return false;
        return (r.ActiveDirectoryRights & ~rel) == 0;
    }

    static bool MatchesEveryoneDenyDeleteChildOnly(System.DirectoryServices.ActiveDirectoryAccessRule r)
    {
        if (r.AccessControlType != AccessControlType.Deny) return false;
        if (!EveryoneSid.Equals((SecurityIdentifier)r.IdentityReference)) return false;
        if (r.InheritanceType != System.DirectoryServices.ActiveDirectorySecurityInheritance.None) return false;
        if (!r.ActiveDirectoryRights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.DeleteChild)) return false;
        return (r.ActiveDirectoryRights & ~System.DirectoryServices.ActiveDirectoryRights.DeleteChild) == 0;
    }

    static void RemoveEveryoneDenyDeleteDeleteTreeOnObject(System.DirectoryServices.ActiveDirectorySecurity ads)
    {
        var toRemove = ads.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.DirectoryServices.ActiveDirectoryAccessRule>()
            .Where(MatchesEveryoneDenyDeleteDeleteTreeOnly)
            .ToList();
        foreach (var r in toRemove)
            ads.RemoveAccessRule(r);
    }

    static void RemoveEveryoneDenyDeleteChildOnObject(System.DirectoryServices.ActiveDirectorySecurity ads)
    {
        var toRemove = ads.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.DirectoryServices.ActiveDirectoryAccessRule>()
            .Where(MatchesEveryoneDenyDeleteChildOnly)
            .ToList();
        foreach (var r in toRemove)
            ads.RemoveAccessRule(r);
    }

    /// <summary>
    /// Enables/disables RSAT-style "accidental deletion" protection: DACL on OU and parent.
    /// Does not rely on adminDescription (often absent on organizationalUnit in AD schema).
    /// </summary>
    static bool TrySetOuAccidentalDeletionProtection(LdapConnection conn, string ouDn, bool protect, out string? error)
    {
        error = null;
        try
        {
            var parentDn = ParentDnOf(ouDn);

            if (!protect)
            {
                if (!string.IsNullOrEmpty(parentDn)
                    && TryReadNtSecurityDescriptorOgd(conn, parentDn, out var pBytesUn) && pBytesUn is not null)
                {
                    var pSec = new System.DirectoryServices.ActiveDirectorySecurity();
                    pSec.SetSecurityDescriptorBinaryForm(pBytesUn, AccessControlSections.All);
                    RemoveEveryoneDenyDeleteChildOnObject(pSec);
                    WriteNtSecurityDescriptorWithFallback(conn, parentDn, pSec.GetSecurityDescriptorBinaryForm());
                }

                if (!TryReadNtSecurityDescriptorOgd(conn, ouDn, out var ouBytesUn) || ouBytesUn is null)
                {
                    error = "Impossible de lire nTSecurityDescriptor sur l’OU.";
                    return false;
                }
                var ouSecUn = new System.DirectoryServices.ActiveDirectorySecurity();
                ouSecUn.SetSecurityDescriptorBinaryForm(ouBytesUn, AccessControlSections.All);
                RemoveEveryoneDenyDeleteDeleteTreeOnObject(ouSecUn);
                WriteNtSecurityDescriptorWithFallback(conn, ouDn, ouSecUn.GetSecurityDescriptorBinaryForm());
                return true;
            }

            if (!TryReadNtSecurityDescriptorOgd(conn, ouDn, out var ouBytes) || ouBytes is null)
            {
                error = "Impossible de lire nTSecurityDescriptor sur l’OU (droits « Contrôle total » / Write DACL requis).";
                return false;
            }
            var ouSec = new System.DirectoryServices.ActiveDirectorySecurity();
            ouSec.SetSecurityDescriptorBinaryForm(ouBytes, AccessControlSections.All);
            if (!OuDaclHasEveryoneDenyDeleteAndDeleteTree(ouBytes))
            {
                ouSec.AddAccessRule(new System.DirectoryServices.ActiveDirectoryAccessRule(
                    EveryoneSid,
                    System.DirectoryServices.ActiveDirectoryRights.Delete | System.DirectoryServices.ActiveDirectoryRights.DeleteTree,
                    AccessControlType.Deny,
                    System.DirectoryServices.ActiveDirectorySecurityInheritance.None));
            }
            WriteNtSecurityDescriptorWithFallback(conn, ouDn, ouSec.GetSecurityDescriptorBinaryForm());

            if (string.IsNullOrEmpty(parentDn))
                return true;

            if (!TryReadNtSecurityDescriptorOgd(conn, parentDn, out var pBytes) || pBytes is null)
            {
                error = "OU partiellement protégée : lecture nTSecurityDescriptor du parent impossible. Réessayez avec un compte ayant les droits sur le parent.";
                return false;
            }
            var pSecProt = new System.DirectoryServices.ActiveDirectorySecurity();
            pSecProt.SetSecurityDescriptorBinaryForm(pBytes, AccessControlSections.All);
            if (!ParentDaclHasEveryoneDenyDeleteChild(pBytes))
            {
                pSecProt.AddAccessRule(new System.DirectoryServices.ActiveDirectoryAccessRule(
                    EveryoneSid,
                    System.DirectoryServices.ActiveDirectoryRights.DeleteChild,
                    AccessControlType.Deny,
                    System.DirectoryServices.ActiveDirectorySecurityInheritance.None));
            }
            WriteNtSecurityDescriptorWithFallback(conn, parentDn, pSecProt.GetSecurityDescriptorBinaryForm());
            return true;
        }
        catch (DirectoryOperationException doe)
        {
            error = doe.Response?.ErrorMessage ?? doe.Message;
            Log.Warning(doe, "TrySetOuAccidentalDeletionProtection LDAP {Protect} {OuDn}", protect, ouDn);
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            Log.Warning(ex, "TrySetOuAccidentalDeletionProtection {Protect} {OuDn}", protect, ouDn);
            return false;
        }
    }

    static bool OuIsProtectedFromAttrs(SearchResultEntry e)
    {
        var sfa = e.Attributes["systemFlags"];
        if (sfa is not null && sfa.Count > 0 && TryParseDirectoryFlags(sfa[0], out var flags)
            && ((flags & SystemFlagDisallowDeleteLegacy) != 0 || (flags & SystemFlagDisallowDeleteAccidental) != 0))
            return true;

        var ad = e.Attributes["adminDescription"];
        if (ad is not null)
            for (int i = 0; i < ad.Count; i++)
            {
                var txt = ad[i]?.ToString() ?? "";
                if (txt.IndexOf(OU_PROTECT_MARKER, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

        var crit = e.Attributes["isCriticalSystemObject"];
        if (crit is not null && crit.Count > 0 && string.Equals(crit[0]?.ToString(), "TRUE", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    static bool OuIsProtected(LdapConnection conn, string ouDn)
    {
        SearchResultEntry? entry = null;
        try
        {
            var req = new SearchRequest(ouDn, "(objectClass=organizationalUnit)", SearchScope.Base,
                new[] { "adminDescription", "isCriticalSystemObject", "systemFlags", "nTSecurityDescriptor" });
            req.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.801", LdapSdFlagsControlDaclOnly, true, true));
            var resp = (SearchResponse)conn.SendRequest(req);
            if (resp.Entries.Count == 1)
                entry = resp.Entries[0];
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "OuIsProtected: lecture OU avec contrôle SD échouée pour {Dn}, repli sans nTSecurityDescriptor", ouDn);
        }

        if (entry is null && !TryGetEntry(conn, ouDn, out entry,
                new[] { "adminDescription", "isCriticalSystemObject", "systemFlags" }))
            return false;

        if (entry is null) return false;

        if (TryGetNtSecurityDescriptorBytes(entry, out var ouSd) && ouSd is not null
            && OuDaclHasEveryoneDenyDeleteAndDeleteTree(ouSd))
        {
            var parentDn = ParentDnOf(ouDn);
            if (string.IsNullOrEmpty(parentDn))
                return true;

            if (TryFetchNtSecurityDescriptorDacl(conn, parentDn, out var parentSd) && parentSd is not null)
            {
                if (ParentDaclHasEveryoneDenyDeleteChild(parentSd))
                    return true;
            }
            else
            {
                // Cannot read parent (permissions): OU-side pattern is enough in practice for RSAT.
                return true;
            }
        }

        return OuIsProtectedFromAttrs(entry);
    }

    // Valid parent for an OU: another OU or the domain root (domainDNS)
    static bool ParentAcceptsOu(LdapConnection conn, string parentDn)
    {
        if (!TryGetEntry(conn, parentDn, out var e, new[] { "objectClass" }) || e is null) return false;
        var oc = e.Attributes["objectClass"];
        bool isOu = false, isDomain = false;
        for (int i = 0; i < oc.Count; i++)
        {
            var v = oc[i]?.ToString();
            isOu |= string.Equals(v, "organizationalUnit", StringComparison.OrdinalIgnoreCase);
            isDomain |= string.Equals(v, "domainDNS", StringComparison.OrdinalIgnoreCase);
        }
        return isOu || isDomain;
    }

    // Map LDAP result codes to HTTP status
    static int Map(ResultCode rc) => rc switch
    {
        ResultCode.NoSuchObject => 404,
        ResultCode.NotAllowedOnNonLeaf => 409, // not empty
        ResultCode.ConstraintViolation => 409,
        ResultCode.UnwillingToPerform => 403, // often policy/DACL
        ResultCode.InsufficientAccessRights => 403,
        _ => 400
    };

    // Is OU empty? — at most one child for performance
    static bool OuIsEmpty(LdapConnection conn, string ouDn)
    {
        var req = new SearchRequest(
            ouDn,
            "(objectClass=*)",
            SearchScope.OneLevel,
            "distinguishedName"
        );
        req.SizeLimit = 1;
        var resp = (SearchResponse)conn.SendRequest(req);
        return resp.Entries.Count == 0;
    }

    static string ParentDnOf(string dn)
    {
        var i = dn.IndexOf(',');
        return i < 0 ? "" : dn[(i + 1)..];
    }

    static string NewOuDn(string parentDn, string name) => $"OU={EscapeRdnValue(name)},{parentDn}";

    static Dictionary<string, object?> BuildExplorerCapabilities(string type, bool underBaseDn)
    {
        var isContainer = type is "ou" or "container" or "domain";
        var isUser = type is "user" or "inetOrgPerson";
        var isGroup = type is "group";
        var isOu = type is "ou";

        return new Dictionary<string, object?>
        {
            ["canCreateOu"] = underBaseDn && isContainer,
            ["canUpdateOu"] = underBaseDn && isOu,
            ["canDeleteOu"] = underBaseDn && isOu,
            ["canCreateUser"] = underBaseDn && isContainer,
            ["canDeleteUser"] = underBaseDn && isUser,
            ["canMoveUser"] = underBaseDn && isUser,
            ["canSetUserEnabled"] = underBaseDn && isUser,
            ["canUnlockUser"] = underBaseDn && isUser,
            ["canRenameUserCn"] = underBaseDn && isUser,
            ["canResetUserPassword"] = underBaseDn && isUser,
            ["canCreateGroup"] = underBaseDn && isContainer,
            ["canDeleteGroup"] = underBaseDn && isGroup,
            ["canManageGroupMembers"] = underBaseDn && (isUser || isGroup)
        };
    }
    
    // Encode bytes as \XX sequence for LDAP filter (RFC4515)
    static string BytesToLdapHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 3);
        foreach (var b in bytes)
        {
            sb.Append('\\');
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    // =======================
    //  MAIN
    // =======================
    public static void Main(string[] args)
    {
        // 0) Utility CLI to register / unregister the Windows service
        if (args is { Length: > 0 })
        {
            if (Array.Exists(args, a => string.Equals(a, "--add-service", StringComparison.OrdinalIgnoreCase)))
            {
                HandleWindowsServiceCommand(add: true);
                return;
            }
            if (Array.Exists(args, a => string.Equals(a, "--remove-service", StringComparison.OrdinalIgnoreCase)))
            {
                HandleWindowsServiceCommand(add: false);
                return;
            }
        }

        // 1) Bootstrap logger (before config is loaded)
        var bootstrapLogDir = Path.Combine(AppBase, "logs");
        BootstrapLogger(bootstrapLogDir);

        // 2) Load config (create default if missing)
        var (cfg, loadErr, created) = LoadConfig();
        if (loadErr != null)
        {
            Log.Fatal("[CONFIG] {Error}. Exiting.", loadErr);
            Log.CloseAndFlush();
            Environment.Exit(1);
        }

        if (created)
        {
            Log.Information("[CONFIG] Created 'config.json' at {Path}. Fill it in and restart.", DefaultConfigJsonPath);
            Log.CloseAndFlush();
            return;
        }

        // 3) Reconfigure logger from config
        try
        {
            if (!Directory.Exists(cfg!.Debug.LogDir))
                Directory.CreateDirectory(cfg.Debug.LogDir);

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.File(
                    path: Path.Combine(cfg.Debug.LogDir, "log-.log"),
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 30,
                    restrictedToMinimumLevel: LogEventLevel.Debug,
                    shared: true)
                .WriteTo.Console(restrictedToMinimumLevel: cfg.Debug.Console ? LogEventLevel.Information : LogEventLevel.Fatal)
                .CreateLogger();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "[LOG] Impossible de configurer les logs.");
            Log.CloseAndFlush();
            Environment.Exit(1);
        }

        Log.Information("ADSelfService-API v{Version} started.", AppVersion);

        // 4) Validate config
        var errors = ValidateConfig(cfg!);
        if (errors.Count > 0)
        {
            foreach (var e in errors) Log.Fatal("[CONFIG] {Err}", e);
            Log.Fatal("Invalid configuration. Exiting.");
            Log.CloseAndFlush();
            Environment.Exit(1);
        }

        // 4b) Detect placeholder / default values
        if (IsLikelyDefault(cfg))
        {
            Log.Fatal("[CONFIG] Configuration still contains example values (DN or password). Edit 'config.json' and restart.");
            Log.CloseAndFlush();
            Environment.Exit(1);
        }
        foreach (var w in SecurityWarnings(cfg))
            Log.Warning("[SECURITY] {Warning}", w);

        // 5) LDAP startup check
        if (cfg.StartupCheck.Enabled)
        {
            // 4a) Raw TCP connectivity (like ldp.exe "Connect")
            if (!TestLdapTcpConnectivity(cfg, out var connErr))
            {
                Log.Error("[STARTUP] LDAP TCP connectivity failed: {Err}", connErr);
                if (cfg.StartupCheck.FailFast)
                {
                    Log.CloseAndFlush();
                    Environment.Exit(2);
                }
            }
            else
            {
                Log.Information("[STARTUP] TCP LDAP OK to {Host}:{Port}", cfg.Ldap.Url, cfg.Ldap.Port);
            }

            // 4b) Service account bind test (next step)
            try
            {
                using var c = GetLdapConnection(cfg);
                if (!BindServiceAccount(c, cfg)) throw new Exception("Service account bind failed.");
                Log.Information("[STARTUP] Bind LDAP OK.");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[STARTUP] LDAP connectivity failed.");
                Console.Error.WriteLine(
                    "LDAP unreachable at startup. See logs in '" + cfg.Debug.LogDir + "'."
                    + (cfg.StartupCheck.ShowDetailsInConsole ? Environment.NewLine + ex : "")
                );
                if (cfg.StartupCheck.FailFast)
                {
                    Log.CloseAndFlush();
                    Environment.Exit(2);
                }
            }
        }

        // 5) Web application
        var builder = WebApplication.CreateBuilder(args);
        builder.Host.UseSerilog();
        if (cfg.Server.Urls?.Count > 0)
            builder.WebHost.UseUrls(cfg.Server.Urls.ToArray());
        var app = builder.Build();

        // Security & debug middleware
        app.Use(async (context, next) =>
        {
            bool isHealth = string.Equals(context.Request.Path, "/health", StringComparison.OrdinalIgnoreCase);

            // 1) Optional internal shared key (X-Internal-Auth),
            //    except /health (no secret, but IP-filtered).
            var shared = cfg.Security.InternalSharedSecret;
            if (!isHealth && !string.IsNullOrEmpty(shared))
            {
                if (!context.Request.Headers.TryGetValue("X-Internal-Auth", out var hdr) ||
                    hdr.Count == 0 ||
                    !string.Equals(hdr[0], shared, StringComparison.Ordinal))
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                    await context.Response.WriteAsync("Forbidden (internal key).");
                    return;
                }
            }

            // 2) Allowed IP list (including /health)
            var ip = context.Connection.RemoteIpAddress ?? IPAddress.None;
            if (!IsIpAllowed(ip, cfg.Security))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                await context.Response.WriteAsync("Forbidden.");
                return;
            }

            // 3) Application context check (defense in depth, API-side)
            if (!IsRequestContextAllowed(context, cfg.Security))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = "Forbidden (application context)." });
                return;
            }
            await next();
        });

        if (cfg.Debug.Enabled)
        {
            app.Use(async (ctx, next) =>
            {
                try
                {
                    string body = "";
                    if (ctx.Request.ContentLength > 0)
                    {
                        ctx.Request.EnableBuffering();
                        using var reader = new StreamReader(ctx.Request.Body, leaveOpen: true);
                        body = await reader.ReadToEndAsync();
                        ctx.Request.Body.Position = 0;
                    }
                    var masked = MaskPasswords(body, cfg.Debug.ShowPasswords);
                    Log.Information("[REQ] {Method} {Path} Body={Body}", ctx.Request.Method, ctx.Request.Path, masked);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[REQ] Log body failed.");
                }
                await next();
            });

            app.Use(async (context, next) =>
            {
                var originalBodyStream = context.Response.Body;
                using var responseBody = new MemoryStream();
                context.Response.Body = responseBody;

                await next();

                context.Response.Body.Seek(0, SeekOrigin.Begin);
                string text = await new StreamReader(context.Response.Body).ReadToEndAsync();
                context.Response.Body.Seek(0, SeekOrigin.Begin);
                Log.Information("[RESP] {Code} {Path} {Text}", context.Response.StatusCode, context.Request.Path, text);
                await responseBody.CopyToAsync(originalBodyStream);
            });
        }

        // ===== /health =====
        app.MapGet("/health", () =>
        {
            try
            {
                using var c = GetLdapConnection(cfg);
                if (!BindServiceAccount(c, cfg)) return Results.StatusCode(500);
                return Results.Ok(new { status = "ok" });
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[/health] LDAP KO");
                return Results.StatusCode(500);
            }
        });

        // ===== Endpoints =====

        // POST /auth
        app.MapPost("/auth", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<AuthRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "username et password requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind service account échoué." });
                    return;
                }

                var safeUser = EscapeLdapFilterValue(req.Username);
                var filter = $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safeUser}))";
                var search = new SearchRequest(
                    cfg.Ldap.BaseDn,
                    filter,
                    SearchScope.Subtree,
                    new[] {
                "distinguishedName","sAMAccountName","givenName","sn","mail","memberOf","pwdLastSet",
                "userAccountControl","telephoneNumber","wWWHomePage","streetAddress","objectGUID",
                "primaryGroupID","objectSid","description"
                    }
                );
                var sr = await Task.Run(() => (SearchResponse)connection.SendRequest(search));
                if (sr.Entries.Count == 0)
                {
                    http.Response.StatusCode = 401;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                var entry = sr.Entries[0];
                string userDn = entry.DistinguishedName;

                var uacStr = entry.Attributes["userAccountControl"]?[0]?.ToString() ?? "0";
                int.TryParse(uacStr, out var uac);
                if ((uac & 2) == 2)
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "Compte désactivé." });
                    return;
                }

                bool mustChangePassword = (entry.Attributes["pwdLastSet"]?[0]?.ToString() == "0");
                try
                {
                    // User bind: LDAPS uses simple bind (Basic + DN);
                    // LDAP+Kerberos prefers a UPN/DOMAIN\user principal when available.
                    string? upn = entry.Attributes["userPrincipalName"]?[0]?.ToString();
                    string loginName = upn ?? req.Username;

                    LdapConnection userConn;
                    if (cfg.Ldap.Ssl)
                    {
                        // LDAPS: simple bind with DN (TLS-encrypted transport)
                        var id = new LdapDirectoryIdentifier(cfg.Ldap.Url, cfg.Ldap.Port);
                        userConn = new LdapConnection(id);
                        userConn.SessionOptions.ProtocolVersion = 3;
                        userConn.SessionOptions.SecureSocketLayer = true;
                        if (cfg.Ldap.IgnoreCertificate)
                        {
                            userConn.SessionOptions.VerifyServerCertificate = (con, cer) => true;
                        }
                        userConn.AuthType = AuthType.Basic;
                        using (userConn)
                        {
                            userConn.Bind(new NetworkCredential(userDn, req.Password));
                        }
                    }
                    else
                    {
                        // LDAP + Kerberos (UseKerberosSealing): principal (UPN/DOMAIN\user)
                        using var kConn = GetLdapConnection(cfg);
                        kConn.Bind(new NetworkCredential(loginName, req.Password));
                    }
                }
                catch (LdapException lex)
                {
                    var msg = lex.ServerErrorMessage ?? "";
                    if (!(msg.Contains("773") || msg.Contains("532")))
                    {
                        http.Response.StatusCode = 401;
                        await http.Response.WriteAsJsonAsync(new { error = "Identifiants invalides." });
                        return;
                    }
                    mustChangePassword = true;
                }

                // ==== Groups (direct + nested + primary) ====
                var directMemberOfDns = GetMemberOfDns(entry.Attributes["memberOf"]);
                var transitiveDns = GetTransitiveGroupDnsForUser(cfg, connection, userDn);

                string? primaryGroupDn = null;
                try { primaryGroupDn = GetPrimaryGroupDn(cfg, connection, entry); }
                catch (Exception ex) { Log.Warning(ex, "Primary group lookup failed; ignoring."); }

                var effectiveDns = new HashSet<string>(transitiveDns, StringComparer.OrdinalIgnoreCase);
                foreach (var dn in directMemberOfDns) effectiveDns.Add(dn);
                if (!string.IsNullOrWhiteSpace(primaryGroupDn)) effectiveDns.Add(primaryGroupDn!);

                var directMemberOfCn = CnsFromDns(directMemberOfDns);
                var memberOfEffectiveCn = CnsFromDns(effectiveDns);

                bool isAdmin = IsAdminEffective(effectiveDns, cfg);

                byte[]? guidBin = entry.Attributes["objectGUID"]?[0] as byte[];
                Guid? objectGuid = guidBin != null ? new Guid(guidBin) : (Guid?)null;

                var userObj = new
                {
                    dn = userDn,
                    sAMAccountName = entry.Attributes["sAMAccountName"]?[0]?.ToString(),
                    givenName = entry.Attributes["givenName"]?[0]?.ToString(),
                    sn = entry.Attributes["sn"]?[0]?.ToString(),
                    mail = entry.Attributes["mail"]?[0]?.ToString(),
                    memberOf = directMemberOfCn,
                    memberOfEffective = memberOfEffectiveCn,
                    objectGUID = objectGuid,
                    telephoneNumber = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                    wwwhomepage = entry.Attributes["wWWHomePage"]?[0]?.ToString(),
                    streetAddress = entry.Attributes["streetAddress"]?[0]?.ToString(),
                    description = entry.Attributes["description"]?[0]?.ToString()
                };

                await http.Response.WriteAsJsonAsync(new { success = true, user = userObj, mustChangePassword, isAdmin });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /auth] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /users — fast by default; groups optional
        app.MapGet("/users", async (HttpContext http) =>
        {
            try
            {
                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                bool includeBuiltins = false;
                if (bool.TryParse(http.Request.Query["includeBuiltins"], out var ib)) includeBuiltins = ib;

                var groupsMode = http.Request.Query["groups"].FirstOrDefault()?.ToLowerInvariant() ?? "direct";
                bool wantGroups = groupsMode != "none";
                bool wantEffective = groupsMode == "effective";

                var filter = "(&(objectCategory=person)(objectClass=user))";
                if (!includeBuiltins) filter = $"(&{filter}(!(sAMAccountName=Guest)))";

                int page = 1;
                int pageSize = cfg.Pagination.PageSize;
                if (cfg.Pagination.Enabled)
                {
                    if (int.TryParse(http.Request.Query["page"], out var p) && p > 0) page = p;
                    if (int.TryParse(http.Request.Query["pageSize"], out var ps) && ps > 0) pageSize = ps;
                }
                int want = pageSize;
                int skip = (page - 1) * pageSize;
                int taken = 0;

                var baseAttrs = new List<string>
                {
                    "distinguishedName","sAMAccountName","givenName","sn","mail",
                    "telephoneNumber","wWWHomePage","streetAddress","objectGUID","userAccountControl",
                    "description", "accountExpires"
                };

                if (wantGroups) baseAttrs.Add("memberOf");
                if (wantEffective) { baseAttrs.Add("primaryGroupID"); baseAttrs.Add("objectSid"); }

                var attrs = baseAttrs.ToArray();

                var users = new List<object>();
                var pageControl = new PageResultRequestControl(cfg.Pagination.Enabled ? pageSize : 1000);
                var req = new SearchRequest(cfg.Ldap.BaseDn, filter, SearchScope.Subtree, attrs);
                req.Controls.Add(pageControl);

                bool hasMore = false;
                int seen = 0;
                var ct = http.RequestAborted;

                while (true)
                {
                    ct.ThrowIfCancellationRequested();

                    var resp = await Task.Run(() => (SearchResponse)connection.SendRequest(req));
                    foreach (SearchResultEntry entry in resp.Entries)
                    {
                        if (cfg.Pagination.Enabled)
                        {
                            if (seen++ < skip) continue;
                            if (taken >= want) break;
                        }

                        List<string> memberOfCn = new();
                        List<string> memberOfEffectiveCn = new();
                        bool isAdmin = false;

                        if (wantGroups)
                        {
                            var directMemberOfDns = GetMemberOfDns(entry.Attributes["memberOf"]);
                            memberOfCn = CnsFromDns(directMemberOfDns);

                            if (wantEffective)
                            {
                                var transitiveDns = GetTransitiveGroupDnsForUser(cfg, connection, entry.DistinguishedName);

                                string? primaryGroupDn = null;
                                try { primaryGroupDn = GetPrimaryGroupDn(cfg, connection, entry); }
                                catch (Exception ex) { Log.Warning(ex, "Primary group lookup failed; ignoring."); }

                                var effectiveDns = new HashSet<string>(transitiveDns, StringComparer.OrdinalIgnoreCase);
                                foreach (var dn in directMemberOfDns) effectiveDns.Add(dn);
                                if (!string.IsNullOrWhiteSpace(primaryGroupDn)) effectiveDns.Add(primaryGroupDn!);

                                memberOfEffectiveCn = CnsFromDns(effectiveDns);
                                isAdmin = IsAdminEffective(effectiveDns, cfg);
                            }
                        }

                        var uacStr = entry.Attributes["userAccountControl"]?[0]?.ToString() ?? "0";
                        int.TryParse(uacStr, out var uac);
                        bool disabled = (uac & 2) == 2;

                        byte[]? guidBin = entry.Attributes["objectGUID"]?[0] as byte[];
                        Guid? guid = guidBin != null ? new Guid(guidBin) : (Guid?)null;

                        var (expAt, never) = DecodeAccountExpiresFromEntry(entry);

                        users.Add(new
                        {
                            dn = entry.DistinguishedName,
                            sAMAccountName = entry.Attributes["sAMAccountName"]?[0]?.ToString(),
                            givenName = entry.Attributes["givenName"]?[0]?.ToString(),
                            sn = entry.Attributes["sn"]?[0]?.ToString(),
                            mail = entry.Attributes["mail"]?[0]?.ToString(),
                            telephoneNumber = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                            wwwhomepage = entry.Attributes["wWWHomePage"]?[0]?.ToString(),
                            streetAddress = entry.Attributes["streetAddress"]?[0]?.ToString(),
                            description = entry.Attributes["description"]?[0]?.ToString(),
                            objectGUID = guid,
                            disabled,
                            isAdmin,
                            memberOf = wantGroups ? memberOfCn : null,
                            memberOfEffective = wantEffective ? memberOfEffectiveCn : null,
                            expiresNever = never,
                            expiresAt = expAt?.ToString("o")
                        });

                        if (cfg.Pagination.Enabled) taken++;
                        ct.ThrowIfCancellationRequested();
                    }

                    var prc = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                    if (cfg.Pagination.Enabled)
                    {
                        if (taken >= want)
                        {
                            // Filled requested page; hasMore only if DC has more pages
                            hasMore = prc != null && prc.Cookie.Length != 0;
                            break;
                        }

                        if (prc == null || prc.Cookie.Length == 0)
                        {
                            hasMore = false; // no further pages
                            break;
                        }

                        pageControl.Cookie = prc.Cookie; // next DC page
                    }
                    else
                    {
                        if (prc == null || prc.Cookie.Length == 0) break;
                        pageControl.Cookie = prc.Cookie;
                    }

                }

                if (cfg.Pagination.Enabled)
                {
                    http.Response.Headers["X-Page"] = page.ToString();
                    http.Response.Headers["X-Page-Size"] = pageSize.ToString();
                    http.Response.Headers["X-Has-More"] = hasMore.ToString();
                }

                await http.Response.WriteAsJsonAsync(users);
            }
            catch (OperationCanceledException)
            {
                Log.Information("Request /users canceled by client.");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /users] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /user/{sam}?groups=none|direct|effective   (default: effective)
        app.MapGet("/user/{sam}", async (HttpContext http, string sam) =>
        {
            try
            {
                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var groupsMode = http.Request.Query["groups"].FirstOrDefault()?.ToLowerInvariant() ?? "direct";
                bool wantGroups = groupsMode != "none";
                bool wantEffective = groupsMode == "effective";

                var attrs = new List<string> {
                    "distinguishedName","sAMAccountName","userPrincipalName","givenName","sn","mail","pwdLastSet",
                    "telephoneNumber","wWWHomePage","streetAddress","objectGUID","userAccountControl",
                    "description", "accountExpires", "primaryGroupID", "objectSid"
                };
                if (wantGroups) attrs.Add("memberOf");

                var safeSam = EscapeLdapFilterValue(sam);
                var request = new SearchRequest(
                    cfg.Ldap.BaseDn,
                    $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safeSam}))",
                    SearchScope.Subtree,
                    attrs.ToArray()
                )
                {
                    SizeLimit = 1,
                    TimeLimit = TimeSpan.FromSeconds(15)
                };

                var response = await Task.Run(() => (SearchResponse)connection.SendRequest(request));
                if (response.Entries.Count == 0)
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur non trouvé." });
                    return;
                }

                var entry = response.Entries[0];

                var uacStr = entry.Attributes["userAccountControl"]?[0]?.ToString() ?? "0";
                int.TryParse(uacStr, out var uac);
                bool disabled = (uac & 2) == 2;
                bool mustChangePassword = (entry.Attributes["pwdLastSet"]?[0]?.ToString() == "0");
                byte[]? guidBin = entry.Attributes["objectGUID"]?[0] as byte[];
                Guid? guid = guidBin != null ? new Guid(guidBin) : (Guid?)null;

                List<string>? memberOfCn = null;
                List<string>? memberOfEffectiveCn = null;
                bool isAdmin = false;

                List<string> directMemberOfDns = new();
                HashSet<string> effectiveDns = new(StringComparer.OrdinalIgnoreCase);

                if (wantGroups)
                {
                    directMemberOfDns = GetMemberOfDns(entry.Attributes["memberOf"]);
                    memberOfCn = CnsFromDns(directMemberOfDns);
                }

                if (wantEffective)
                {
                    var transitiveDns = GetTransitiveGroupDnsForUser(cfg, connection, entry.DistinguishedName);
                    string? primaryGroupDn = null;
                    try { primaryGroupDn = GetPrimaryGroupDn(cfg, connection, entry); }
                    catch (Exception ex) { Log.Warning(ex, "Primary group lookup failed; ignoring."); }

                    foreach (var dn in transitiveDns) effectiveDns.Add(dn);
                    foreach (var dn in directMemberOfDns) effectiveDns.Add(dn);
                    if (!string.IsNullOrWhiteSpace(primaryGroupDn)) effectiveDns.Add(primaryGroupDn!);

                    memberOfEffectiveCn = CnsFromDns(effectiveDns);
                    isAdmin = IsAdminEffective(effectiveDns, cfg);
                }

                var (expAt, never) = DecodeAccountExpiresFromEntry(entry);

                string? primaryGroupDnVal = null;
                int? primaryGroupIdVal = null;
                try
                {
                    if (TryReadPrimaryGroupRid(entry, out var pgi))
                        primaryGroupIdVal = pgi;
                    primaryGroupDnVal = GetPrimaryGroupDn(cfg, connection, entry);
                }
                catch (Exception ex) { Log.Warning(ex, "Primary group for GET /user"); }

                var user = new
                {
                    dn = entry.DistinguishedName,
                    sAMAccountName = entry.Attributes["sAMAccountName"]?[0]?.ToString(),
                    userPrincipalName = entry.Attributes["userPrincipalName"]?[0]?.ToString(),
                    givenName = entry.Attributes["givenName"]?[0]?.ToString(),
                    sn = entry.Attributes["sn"]?[0]?.ToString(),
                    mail = entry.Attributes["mail"]?[0]?.ToString(),
                    telephoneNumber = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                    wwwhomepage = entry.Attributes["wWWHomePage"]?[0]?.ToString(),
                    streetAddress = entry.Attributes["streetAddress"]?[0]?.ToString(),
                    description = entry.Attributes["description"]?[0]?.ToString(),
                    objectGUID = guid,
                    disabled,
                    mustChangePassword,
                    isAdmin,
                    memberOf = wantGroups ? memberOfCn : null,
                    memberOfEffective = wantEffective ? memberOfEffectiveCn : null,
                    primaryGroupDn = primaryGroupDnVal,
                    primaryGroupId = primaryGroupIdVal,
                    expiresNever = never,
                    expiresAt = expAt?.ToString("o")
                };

                await http.Response.WriteAsJsonAsync(user);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /user/{sam}] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /user/updateProfile
        app.MapPost("/user/updateProfile", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<UpdateProfileRequest>();
                if (req == null || string.IsNullOrEmpty(req.Dn) || req.Modifications == null)
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "dn et modifications requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var mods = new List<DirectoryAttributeModification>();
                foreach (var kv in req.Modifications)
                {
                    var key = kv.Key;
                    var val = kv.Value;

                    if (string.IsNullOrWhiteSpace(key) || !UserProfileAllowedAttributes.Contains(key))
                    {
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new
                        {
                            error = $"Attribut non autorisé pour updateProfile: '{key}'."
                        });
                        return;
                    }

                    // Light API-side validation for description
                    if (string.Equals(key, "description", StringComparison.OrdinalIgnoreCase) && val is not null && val.Length > 1024)
                    {
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new { error = "description trop longue (max 1024 caractères)" });
                        return;
                    }

                    var mod = new DirectoryAttributeModification { Name = key };
                    if (!string.IsNullOrEmpty(val))
                    {
                        mod.Operation = DirectoryAttributeOperation.Replace;
                        mod.Add(val);
                    }
                    else
                    {
                        mod.Operation = DirectoryAttributeOperation.Delete;
                    }
                    mods.Add(mod);
                }

                if (mods.Count == 0)
                {
                    await http.Response.WriteAsJsonAsync(new { success = true, note = "Aucune modification." });
                    return;
                }

                try
                {
                    var modifyRequest = new ModifyRequest(req.Dn, mods.ToArray());
                    _ = (ModifyResponse)connection.SendRequest(modifyRequest);
                }
                catch (DirectoryOperationException doe)
                {
                    var msg = doe.Response?.ErrorMessage ?? doe.Message ?? "";
                    // Many DCs return "No such attribute" when deleting a missing value — treat as OK
                    if (msg.IndexOf("No such attribute", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        await http.Response.WriteAsJsonAsync(new { success = true, note = "Certains attributs étaient déjà absents." });
                        return;
                    }
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
                    return;
                }

                await http.Response.WriteAsJsonAsync(new { success = true });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /user/updateProfile] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /user/changePassword
        app.MapPost("/user/changePassword", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<ChangePasswordRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.CurrentPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "username, currentPassword et newPassword requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var userObj = SearchUserBySam(cfg, req.Username);
                if (userObj == null)
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }
                dynamic user = userObj;
                string userDn = user.dn;

                try
                {
                    // Verify current password same way as /auth:
                    // - LDAPS: simple bind (Basic + DN) over TLS
                    // - LDAP+Kerberos: bind with principal (UPN/DOMAIN\user when possible)
                    string loginName = req.Username;

                    if (cfg.Ldap.Ssl)
                    {
                        var id = new LdapDirectoryIdentifier(cfg.Ldap.Url, cfg.Ldap.Port);
                        using var userConn = new LdapConnection(id);
                        userConn.SessionOptions.ProtocolVersion = 3;
                        userConn.SessionOptions.SecureSocketLayer = true;
                        if (cfg.Ldap.IgnoreCertificate)
                        {
                            userConn.SessionOptions.VerifyServerCertificate = (con, cer) => true;
                        }
                        userConn.AuthType = AuthType.Basic;
                        userConn.Bind(new NetworkCredential(userDn, req.CurrentPassword));
                    }
                    else
                    {
                        using var kConn = GetLdapConnection(cfg);
                        kConn.Bind(new NetworkCredential(loginName, req.CurrentPassword));
                    }
                }
                catch (LdapException exBind)
                {
                    var msg = exBind.ServerErrorMessage ?? "";
                    if (!(msg.Contains("773") || msg.Contains("532")))
                    {
                        http.Response.StatusCode = 401;
                        await http.Response.WriteAsJsonAsync(new { error = "Mot de passe actuel incorrect." });
                        return;
                    }
                }

                ChangeUserPassword(cfg, userDn, req.NewPassword, async (err) =>
                {
                    if (err != null)
                    {
                        http.Response.StatusCode = 500;
                        await http.Response.WriteAsJsonAsync(new { error = "Échec du changement de mot de passe." });
                        return;
                    }
                    await http.Response.WriteAsJsonAsync(new { success = true });
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /user/changePassword] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/changePassword (optional MustChangeAtNextLogon)
        app.MapPost("/admin/changePassword", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<ChangeAdminPasswordRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.NewPassword))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "username et newPassword requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var userObj = SearchUserBySam(cfg, req.Username);
                if (userObj == null)
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }
                dynamic user = userObj;
                string userDn = user.dn;

                ChangeUserPassword(cfg, userDn, req.NewPassword, async (err) =>
                {
                    if (err != null)
                    {
                        http.Response.StatusCode = 500;
                        await http.Response.WriteAsJsonAsync(new { error = "Échec du changement de mot de passe (admin)." });
                        return;
                    }

                    if (req.MustChangeAtNextLogon.HasValue)
                    {
                        var ok = SetPwdLastSet(cfg, userDn, req.MustChangeAtNextLogon.Value ? 0 : -1);
                        if (!ok)
                        {
                            http.Response.StatusCode = 500;
                            await http.Response.WriteAsJsonAsync(new { error = "Mot de passe changé, mais impossible de définir pwdLastSet." });
                            return;
                        }
                    }

                    await http.Response.WriteAsJsonAsync(new { success = true });
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/changePassword] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/setUserEnabled  (+ alias enable/disable)
        app.MapPost("/admin/setUserEnabled", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetUserEnabledRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.User))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user et enabled requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve DN + UAC without 'dynamic'
                string userDn;
                int? uac = null;

                if (req.User.Contains("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    // Caller supplied full DN
                    userDn = req.User;

                    // Read userAccountControl at Base scope
                    var baseReq = new SearchRequest(
                        userDn,
                        "(objectClass=user)",
                        SearchScope.Base,
                        new[] { "userAccountControl" }
                    );
                    var baseResp = await Task.Run(() => (SearchResponse)connection.SendRequest(baseReq));
                    if (baseResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable (DN invalide)." });
                        return;
                    }
                    var uacStr = baseResp.Entries[0].Attributes["userAccountControl"]?[0]?.ToString();
                    if (int.TryParse(uacStr, out var parsed)) uac = parsed;
                }
                else
                {
                    // sAMAccountName lookup
                    var safe = EscapeLdapFilterValue(req.User);
                    var sReq = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safe}))",
                        SearchScope.Subtree,
                        new[] { "distinguishedName", "userAccountControl" }
                    );
                    var sResp = await Task.Run(() => (SearchResponse)connection.SendRequest(sReq));
                    if (sResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                        return;
                    }
                    var ent = sResp.Entries[0];
                    userDn = ent.DistinguishedName;

                    var uacStr = ent.Attributes["userAccountControl"]?[0]?.ToString();
                    if (int.TryParse(uacStr, out var parsed)) uac = parsed;
                }

                if (!SetUserEnabled(cfg, userDn, req.Enabled, uac))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Impossible de modifier l'état activé/désactivé." });
                    return;
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn, enabled = req.Enabled });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/setUserEnabled] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/createUser
        app.MapPost("/admin/createUser", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<CreateUserRequest>();
                if (req == null
                    || string.IsNullOrWhiteSpace(req.OuDn)
                    || string.IsNullOrWhiteSpace(req.Cn)
                    || string.IsNullOrWhiteSpace(req.Sam)
                    || string.IsNullOrWhiteSpace(req.GivenName)
                    || string.IsNullOrWhiteSpace(req.Sn)
                    || string.IsNullOrWhiteSpace(req.UserPrincipalName)
                    || string.IsNullOrWhiteSpace(req.Password))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "Champs requis: ouDn, cn, sam, givenName, sn, userPrincipalName, password." });
                    return;
                }

                var upnForLdap = req.UserPrincipalName.Trim();
                if (!string.IsNullOrWhiteSpace(req.CloneSourceSam) && !string.IsNullOrWhiteSpace(req.CloneSourceUserPrincipalName))
                {
                    upnForLdap = UserPrincipalNameCloneNormalization.NormalizeSubmittedUpnForClone(
                        upnForLdap,
                        req.Sam.Trim(),
                        req.CloneSourceSam.Trim(),
                        req.CloneSourceUserPrincipalName.Trim());
                }

                if (string.IsNullOrWhiteSpace(upnForLdap))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "userPrincipalName invalide après normalisation (clonage)." });
                    return;
                }

                // Normalize target OU (trim stray spaces) and ensure it exists.
                var targetOuDn = req.OuDn.Trim();
                if (string.IsNullOrWhiteSpace(targetOuDn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "OU cible invalide." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                try
                {
                    var chk = new SearchRequest(
                        targetOuDn,
                        "(|(objectClass=organizationalUnit)(objectClass=container))",
                        SearchScope.Base,
                        "distinguishedName");
                    var chkResp = await Task.Run(() => (SearchResponse)connection.SendRequest(chk));
                    if (chkResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "OU/Conteneur cible introuvable." });
                        return;
                    }
                }
                catch (DirectoryOperationException doe)
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "OU cible invalide (DN).", serverError = doe.Response?.ErrorMessage ?? doe.Message });
                    return;
                }

                // Build a valid user DN (CN escaped correctly).
                string userDn = $"CN={EscapeRdnValue(req.Cn)},{targetOuDn}";
                var addReq = new AddRequest(userDn,
                    new DirectoryAttribute("objectClass", "top", "person", "organizationalPerson", "user"),
                    new DirectoryAttribute("cn", req.Cn),
                    new DirectoryAttribute("sn", req.Sn),
                    new DirectoryAttribute("givenName", req.GivenName),
                    new DirectoryAttribute("displayName", req.Cn),
                    new DirectoryAttribute("sAMAccountName", req.Sam),
                    new DirectoryAttribute("userPrincipalName", upnForLdap),
                    new DirectoryAttribute("userAccountControl", "514") // disabled at creation
                );
                if (!string.IsNullOrWhiteSpace(req.Mail))
                    addReq.Attributes.Add(new DirectoryAttribute("mail", req.Mail));
                if (!string.IsNullOrWhiteSpace(req.Description))
                    addReq.Attributes.Add(new DirectoryAttribute("description", req.Description));
                if (req.NeverExpires)
                    addReq.Attributes.Add(new DirectoryAttribute("accountExpires", "0"));
                else if (req.ExpiresAt.HasValue)
                    addReq.Attributes.Add(new DirectoryAttribute("accountExpires", ToAccountExpiresFileTime(req.ExpiresAt.Value)));

                _ = (AddResponse)connection.SendRequest(addReq);

                var pwdMod = new DirectoryAttributeModification
                {
                    Operation = DirectoryAttributeOperation.Replace,
                    Name = "unicodePwd"
                };
                pwdMod.Add(EncodePassword(req.Password));
                var pwdReq = new ModifyRequest(userDn, pwdMod);
                _ = (ModifyResponse)connection.SendRequest(pwdReq);

                if (req.Enabled)
                {
                    var uacMod = new DirectoryAttributeModification
                    {
                        Operation = DirectoryAttributeOperation.Replace,
                        Name = "userAccountControl"
                    };
                    uacMod.Add("512"); // NORMAL_ACCOUNT
                    var uacReq = new ModifyRequest(userDn, uacMod);
                    _ = (ModifyResponse)connection.SendRequest(uacReq);
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /admin/createUser] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/createUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/deleteUser
        app.MapPost("/admin/deleteUser", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<DeleteUserRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                string userDn = LooksLikeDn(req.User)
                    ? req.User
                    : (SearchUserBySam(cfg, req.User) as dynamic)?.dn;

                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                var del = new DeleteRequest(userDn);
                _ = (DeleteResponse)connection.SendRequest(del);
                await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /admin/deleteUser] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/deleteUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/updateUser
        app.MapPost("/admin/updateUser", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<AdminUpdateUserRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.User) || req.Attributes == null)
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user et attributes requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve DN: direct DN or search by sAMAccountName
                string userDn = req.User.Contains("DC=", StringComparison.OrdinalIgnoreCase)
                    ? req.User
                    : (SearchUserBySam(cfg, req.User) as dynamic)?.dn;

                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                // Apply all modifications in a single LDAP request
                var mods = new List<DirectoryAttributeModification>();
                foreach (var kv in req.Attributes)
                {
                    var attrName = kv.Key?.Trim();
                    if (string.IsNullOrEmpty(attrName)) continue;
                    if (!AdminUpdateAllowedAttributes.Contains(attrName))
                    {
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new
                        {
                            error = $"Attribut non autorisé pour admin/updateUser: '{attrName}'."
                        });
                        return;
                    }

                    var val = kv.Value?.Trim();

                    // Light validation: description too long
                    if (attrName.Equals("description", StringComparison.OrdinalIgnoreCase) && val is not null && val.Length > 1024)
                    {
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new { error = "description trop longue (max 1024 caractères)" });
                    return;
                }

                    var m = new DirectoryAttributeModification { Name = attrName };
                    if (!string.IsNullOrEmpty(val))
                    {
                        m.Operation = DirectoryAttributeOperation.Replace; // Replace fonctionne en ajout/maj
                        m.Add(val);
                    }
                    else
                    {
                        m.Operation = DirectoryAttributeOperation.Delete; // empty field => remove attribute
                    }
                    mods.Add(m);
                }

                if (mods.Count == 0)
                {
                    await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn, note = "Aucune modification." });
                    return;
                }

                try
                {
                    var mreq = new ModifyRequest(userDn, mods.ToArray());
                _ = (ModifyResponse)connection.SendRequest(mreq);
            }
            catch (DirectoryOperationException doe)
            {
                    // Idempotent: deleting an already-absent attribute -> OK
                    var serverMsg = doe.Response?.ErrorMessage ?? doe.Message ?? "";
                    if (serverMsg.IndexOf("No such attribute", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn, note = "Certains attributs étaient déjà absents." });
                    return;
                }

                    Log.Error(doe, "[POST /admin/updateUser] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
                    return;
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/updateUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /groups — list groups (id/cn/dn/sam/description), pagination + search
        app.MapGet("/groups", async (HttpContext http) =>
        {
            try
            {
                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                string baseDn = http.Request.Query["baseDn"].FirstOrDefault()
                                ?? (string.IsNullOrWhiteSpace(cfg.Ldap.GroupBaseDn) ? cfg.Ldap.RootDn : cfg.Ldap.GroupBaseDn);

                string search = http.Request.Query["search"].FirstOrDefault() ?? "";
                string filter = string.IsNullOrWhiteSpace(search)
                    ? "(objectClass=group)"
                    : $"(&(objectClass=group)(|(cn=*{EscapeLdapFilterValue(search)}*)(sAMAccountName=*{EscapeLdapFilterValue(search)}*)))";

                var attrs = new[] { "cn", "distinguishedName", "objectGUID", "sAMAccountName", "description" };
                var groups = new List<object>();

                int page = 1;
                int pageSize = cfg.Pagination.PageSize;
                if (cfg.Pagination.Enabled)
                {
                    if (int.TryParse(http.Request.Query["page"], out var p) && p > 0) page = p;
                    if (int.TryParse(http.Request.Query["pageSize"], out var ps) && ps > 0) pageSize = ps;
                }

                int want = pageSize;
                int skip = (page - 1) * pageSize;
                int taken = 0;

                var pageControl = new PageResultRequestControl(cfg.Pagination.Enabled ? pageSize : 1000);
                var req = new SearchRequest(baseDn, filter, SearchScope.Subtree, attrs);
                req.Controls.Add(pageControl);

                bool hasMore = false;

                while (true)
                {
                    var resp = await Task.Run(() => (SearchResponse)connection.SendRequest(req));
                    foreach (SearchResultEntry e in resp.Entries)
                    {
                        if (cfg.Pagination.Enabled)
                        {
                            if (skip-- > 0) continue;
                            if (taken >= want) break;
                        }

                        byte[]? guidBin = e.Attributes["objectGUID"]?[0] as byte[];
                        Guid? guid = guidBin != null ? new Guid(guidBin) : (Guid?)null;

                        groups.Add(new
                        {
                            id = guid,
                            name = e.Attributes["cn"]?[0]?.ToString(),
                            dn = e.Attributes["distinguishedName"]?[0]?.ToString(),
                            sam = e.Attributes["sAMAccountName"]?[0]?.ToString(),
                            description = e.Attributes["description"]?[0]?.ToString() 
                        });

                        if (cfg.Pagination.Enabled) taken++;
                    }

                    var prc = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                    if (cfg.Pagination.Enabled)
                    {
                        if (taken >= want)
                        {
                            // Returned requested item count; check if DC has more pages
                            hasMore = prc != null && prc.Cookie.Length != 0;
                            break;
                        }

                        if (prc == null || prc.Cookie.Length == 0)
                        {
                            hasMore = false;
                            break;
                        }

                        pageControl.Cookie = prc.Cookie;
                    }
                    else
                    {
                        if (prc == null || prc.Cookie.Length == 0) break;
                        pageControl.Cookie = prc.Cookie;
                    }

                }

                if (cfg.Pagination.Enabled)
                {
                    http.Response.Headers["X-Page"] = page.ToString();
                    http.Response.Headers["X-Page-Size"] = pageSize.ToString();
                    http.Response.Headers["X-Has-More"] = hasMore.ToString();
                }

                await http.Response.WriteAsJsonAsync(groups);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /groups] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /meta/ad — AD metadata for the client
        app.MapGet("/meta/ad", async (HttpContext http) =>
        {
            try
            {
                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                await http.Response.WriteAsJsonAsync(new
                {
                    baseDn = explorerBaseDn,
                    groupBaseDn = EffectiveGroupBaseDn(cfg),
                    rootDn = cfg.Ldap.RootDn
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /meta/ad] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /recovery/lookup
        // Targeted search for forgot-password flow (avoids scanning /users from PHP).
        app.MapGet("/recovery/lookup", async (HttpContext http) =>
        {
            try
            {
                var identifier = (http.Request.Query["identifier"].FirstOrDefault() ?? "").Trim();
                if (string.IsNullOrWhiteSpace(identifier))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "identifier requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                bool byMail = identifier.Contains('@');
                SearchRequest req;
                if (byMail)
                {
                    var safe = EscapeLdapFilterValue(identifier);
                    req = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        $"(&(&(objectCategory=person)(objectClass=user))(mail={safe}))",
                        SearchScope.Subtree,
                        new[] { "sAMAccountName", "givenName", "mail", "telephoneNumber" });
                    req.SizeLimit = 1;
                }
                else
                {
                    var normalizedId = NormalizeFrenchPhone(identifier);
                    if (string.IsNullOrWhiteSpace(normalizedId))
                    {
                        await http.Response.WriteAsJsonAsync(new { found = false });
                        return;
                    }

                    // Prefer entries that expose a phone, then compare after normalization.
                    req = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        "(&(&(objectCategory=person)(objectClass=user))(telephoneNumber=*))",
                        SearchScope.Subtree,
                        new[] { "sAMAccountName", "givenName", "mail", "telephoneNumber" });
                }

                var resp = await Task.Run(() => (SearchResponse)connection.SendRequest(req));
                SearchResultEntry? hit = null;

                if (byMail)
                {
                    hit = resp.Entries.Count > 0 ? resp.Entries[0] : null;
                }
                else
                {
                    var normalizedId = NormalizeFrenchPhone(identifier);
                    foreach (SearchResultEntry e in resp.Entries)
                    {
                        var phone = e.Attributes["telephoneNumber"]?[0]?.ToString();
                        var n = NormalizeFrenchPhone(phone);
                        if (!string.IsNullOrWhiteSpace(n) &&
                            string.Equals(n, normalizedId, StringComparison.Ordinal))
                        {
                            hit = e;
                            break;
                        }
                    }
                }

                if (hit is null)
                {
                    await http.Response.WriteAsJsonAsync(new { found = false });
                    return;
                }

                await http.Response.WriteAsJsonAsync(new
                {
                    found = true,
                    sam = hit.Attributes["sAMAccountName"]?[0]?.ToString(),
                    givenName = hit.Attributes["givenName"]?[0]?.ToString(),
                    mail = hit.Attributes["mail"]?[0]?.ToString(),
                    telephoneNumber = hit.Attributes["telephoneNumber"]?[0]?.ToString()
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /recovery/lookup] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/search?q=<term>&type=<all|user|inetorgperson|group|computer|ou|container|domain>&max=200
        app.MapGet("/explorer/search", async (HttpContext http) =>
        {
            try
            {
                var q = (http.Request.Query["q"].FirstOrDefault() ?? "").Trim();
                var type = (http.Request.Query["type"].FirstOrDefault() ?? "all").Trim().ToLowerInvariant();
                int max = 200;
                if (int.TryParse(http.Request.Query["max"], out var m) && m > 0 && m <= 2000) max = m;

                string typeFilter = type switch
                {
                    "user" => "(&(objectCategory=person)(objectClass=user))",
                    "inetorgperson" => "(objectClass=inetOrgPerson)",
                    "group" => "(objectClass=group)",
                    "computer" => "(objectClass=computer)",
                    "ou" => "(objectClass=organizationalUnit)",
                    "container" => "(objectClass=container)",
                    "domain" => "(objectClass=domainDNS)",
                    _ => "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=group)(objectClass=computer)(objectClass=domainDNS)(&(objectCategory=person)(|(objectClass=user)(objectClass=inetOrgPerson))))"
                };

                string textFilter;
                if (string.IsNullOrWhiteSpace(q) || q == "*")
                {
                    textFilter = "(objectClass=*)";
                }
                else
                {
                    var safe = EscapeLdapFilterValue(q);
                    textFilter = $"(|(name=*{safe}*)(cn=*{safe}*)(ou=*{safe}*)(sAMAccountName=*{safe}*)(userPrincipalName=*{safe}*)(distinguishedName=*{safe}*))";
                }

                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var req = new SearchRequest(
                    explorerBaseDn,
                    $"(&{typeFilter}{textFilter})",
                    SearchScope.Subtree,
                    new[] { "distinguishedName", "name", "cn", "ou", "description", "objectClass", "sAMAccountName" });
                req.SizeLimit = max;
                var resp = (SearchResponse)connection.SendRequest(req);

                var rows = resp.Entries.Cast<SearchResultEntry>()
                    .Where(e => DnIsUnder(e.DistinguishedName, explorerBaseDn))
                    .Select(e =>
                    {
                        var dn = e.DistinguishedName;
                        var parentDn = ParentDnOf(dn);
                        return new
                        {
                            name = GetNameFromEntry(e),
                            dn,
                            parentDn,
                            type = GetNodeTypeFromEntry(e),
                            objectClasses = GetObjectClassesFromEntry(e),
                            samAccountName = e.Attributes["sAMAccountName"]?[0]?.ToString(),
                            description = e.Attributes["description"]?[0]?.ToString()
                        };
                    })
                    .OrderBy(x => x.dn, StringComparer.OrdinalIgnoreCase)
                    .Take(max)
                    .ToList();

                    await http.Response.WriteAsJsonAsync(new
                    {
                    query = q,
                    type,
                    max,
                    count = rows.Count,
                    results = rows
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/search] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/group-search?q=<term>&scope=<all|explorer|groups>&max=100
        app.MapGet("/explorer/group-search", async (HttpContext http) =>
        {
            try
            {
                var q = (http.Request.Query["q"].FirstOrDefault() ?? "").Trim();
                var scope = (http.Request.Query["scope"].FirstOrDefault() ?? "all").Trim().ToLowerInvariant();
                int max = 100;
                if (int.TryParse(http.Request.Query["max"], out var m) && m > 0 && m <= 2000) max = m;

                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                var groupBaseDn = EffectiveGroupBaseDn(cfg);
                var searchBase = scope switch
                {
                    "explorer" => explorerBaseDn,
                    "groups" => groupBaseDn,
                    _ => cfg.Ldap.RootDn
                };

                var textFilter = string.IsNullOrWhiteSpace(q) || q == "*"
                    ? "(objectClass=*)"
                    : $"(|(cn=*{EscapeLdapFilterValue(q)}*)(sAMAccountName=*{EscapeLdapFilterValue(q)}*)(name=*{EscapeLdapFilterValue(q)}*)(distinguishedName=*{EscapeLdapFilterValue(q)}*))";

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var req = new SearchRequest(
                    searchBase,
                    $"(&(objectClass=group){textFilter})",
                    SearchScope.Subtree,
                    new[] { "objectGUID", "cn", "name", "sAMAccountName", "distinguishedName", "description", "objectClass" });
                req.SizeLimit = max;
                var resp = (SearchResponse)connection.SendRequest(req);

                var rows = resp.Entries.Cast<SearchResultEntry>()
                    // scope=all => RootDn, scope=groups => GroupBaseDn, scope=explorer => BaseDn explorateur
                    .Where(e => DnIsUnder(e.DistinguishedName, searchBase))
                    .Select(e =>
                    {
                        byte[]? guidBin = e.Attributes["objectGUID"]?[0] as byte[];
                        Guid? guid = guidBin != null ? new Guid(guidBin) : (Guid?)null;
                        return new
                        {
                            id = guid,
                            name = e.Attributes["cn"]?[0]?.ToString() ?? e.Attributes["name"]?[0]?.ToString(),
                            sam = e.Attributes["sAMAccountName"]?[0]?.ToString(),
                            dn = e.Attributes["distinguishedName"]?[0]?.ToString() ?? e.DistinguishedName,
                            description = e.Attributes["description"]?[0]?.ToString(),
                            type = GetNodeTypeFromEntry(e)
                        };
                    })
                    .OrderBy(x => x.name ?? x.dn, StringComparer.OrdinalIgnoreCase)
                    .Take(max)
                    .ToList();

                await http.Response.WriteAsJsonAsync(new
                {
                    query = q,
                    scope,
                    max,
                    count = rows.Count,
                    results = rows
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/group-search] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/user-search?q=<term>&max=50
        app.MapGet("/explorer/user-search", async (HttpContext http) =>
        {
            try
            {
                var q = (http.Request.Query["q"].FirstOrDefault() ?? "").Trim();
                int max = 50;
                if (int.TryParse(http.Request.Query["max"], out var m) && m > 0 && m <= 1000) max = m;

                string textFilter = string.IsNullOrWhiteSpace(q) || q == "*"
                    ? "(objectClass=*)"
                    : $"(|(cn=*{EscapeLdapFilterValue(q)}*)(name=*{EscapeLdapFilterValue(q)}*)(sAMAccountName=*{EscapeLdapFilterValue(q)}*)(userPrincipalName=*{EscapeLdapFilterValue(q)}*)(distinguishedName=*{EscapeLdapFilterValue(q)}*))";

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var req = new SearchRequest(
                    EffectiveExplorerBaseDn(cfg),
                    $"(&(&(objectCategory=person)(|(objectClass=user)(objectClass=inetOrgPerson))){textFilter})",
                    SearchScope.Subtree,
                    new[] { "distinguishedName", "cn", "name", "sAMAccountName", "userPrincipalName", "objectClass" });
                req.SizeLimit = max;
                var resp = (SearchResponse)connection.SendRequest(req);

                var rows = resp.Entries.Cast<SearchResultEntry>()
                    .Where(e => DnIsUnder(e.DistinguishedName, EffectiveExplorerBaseDn(cfg)))
                    .Select(e => new
                    {
                        name = e.Attributes["cn"]?[0]?.ToString() ?? e.Attributes["name"]?[0]?.ToString(),
                        sam = e.Attributes["sAMAccountName"]?[0]?.ToString(),
                        upn = e.Attributes["userPrincipalName"]?[0]?.ToString(),
                        dn = e.DistinguishedName,
                        type = GetNodeTypeFromEntry(e)
                    })
                    .OrderBy(x => x.name ?? x.sam ?? x.dn, StringComparer.OrdinalIgnoreCase)
                    .Take(max)
                    .ToList();

                await http.Response.WriteAsJsonAsync(new
                {
                    query = q,
                    max,
                    count = rows.Count,
                    results = rows
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/user-search] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/user-groups?user=<sAM|DN>
        app.MapGet("/explorer/user-groups", async (HttpContext http) =>
        {
            try
            {
                var user = (http.Request.Query["user"].FirstOrDefault() ?? "").Trim();
                if (string.IsNullOrWhiteSpace(user))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var userDn = ResolveUserDn(cfg, connection, user);
                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                int? primaryGroupIdVal = null;
                string? primaryGroupDnVal = null;
                if (TryGetEntry(connection, userDn, out var userEntryUg, new[] { "primaryGroupID", "objectSid" }) && userEntryUg is not null)
                {
                    if (TryReadPrimaryGroupRid(userEntryUg, out var pgrUg))
                        primaryGroupIdVal = pgrUg;
                    try { primaryGroupDnVal = GetPrimaryGroupDn(cfg, connection, userEntryUg); }
                    catch (Exception ex) { Log.Warning(ex, "[GET /explorer/user-groups] Résolution groupe principal échouée."); }
                }

                var direct = GetDirectUserGroupDns(cfg, connection, userDn);
                var groups = direct.Select(dn => GroupDtoFromDn(connection, dn)).ToList();
                await http.Response.WriteAsJsonAsync(new
                {
                    user = userDn,
                    count = groups.Count,
                    groups,
                    primaryGroupDn = primaryGroupDnVal,
                    primaryGroupId = primaryGroupIdVal
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/user-groups] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /explorer/user-groups/set  Body: { user, groups[] }
        app.MapPost("/explorer/user-groups/set", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetUserGroupsRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User))
                    {
                        http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user requis." });
                        return;
                    }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var userDn = ResolveUserDn(cfg, connection, req.User);
                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                var current = new HashSet<string>(GetDirectUserGroupDns(cfg, connection, userDn), StringComparer.OrdinalIgnoreCase);
                var target = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var input in req.Groups ?? new List<string>())
                {
                    var raw = (input ?? "").Trim();
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    var groupDn = ResolveGroupDn(cfg, connection, raw);
                    if (!string.IsNullOrWhiteSpace(groupDn)) target.Add(groupDn);
                }

                string? primaryGroupDn = null;
                if (TryGetEntry(connection, userDn, out var userEntryPg, new[] { "primaryGroupID", "objectSid" }) && userEntryPg is not null)
                {
                    try { primaryGroupDn = GetPrimaryGroupDn(cfg, connection, userEntryPg); }
                    catch { /* ignore */ }
                }

                if (!string.IsNullOrWhiteSpace(primaryGroupDn)
                    && !target.Contains(primaryGroupDn, StringComparer.OrdinalIgnoreCase))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new
                    {
                        error = "Le groupe principal ne peut pas être retiré de la liste tant qu’il reste le groupe principal du compte. Modifiez d’abord le groupe principal (modifier l’utilisateur), ou laissez ce groupe dans la liste.",
                        code = "primary_group_required",
                        primaryGroupDn
                    });
                    return;
                }

                var toAdd = target.Except(current, StringComparer.OrdinalIgnoreCase).ToList();
                var toRemove = current.Except(target, StringComparer.OrdinalIgnoreCase).ToList();
                if (!string.IsNullOrWhiteSpace(primaryGroupDn))
                    toRemove = toRemove.Where(g => !g.Equals(primaryGroupDn, StringComparison.OrdinalIgnoreCase)).ToList();

                foreach (var gdn in toAdd)
                {
                    var mod = new DirectoryAttributeModification { Operation = DirectoryAttributeOperation.Add, Name = "member" };
                    mod.Add(userDn);
                    _ = (ModifyResponse)connection.SendRequest(new ModifyRequest(gdn, mod));
                }
                foreach (var gdn in toRemove)
                {
                    var mod = new DirectoryAttributeModification { Operation = DirectoryAttributeOperation.Delete, Name = "member" };
                    mod.Add(userDn);
                    try
                    {
                        _ = (ModifyResponse)connection.SendRequest(new ModifyRequest(gdn, mod));
                }
                catch (DirectoryOperationException doe)
                {
                        var msg = doe.Response?.ErrorMessage ?? doe.Message ?? "";
                        if (msg.IndexOf("No such attribute", StringComparison.OrdinalIgnoreCase) < 0
                            && doe.Response?.ResultCode != ResultCode.NoSuchAttribute)
                        {
                            throw;
                        }
                    }
                }

                var updated = GetDirectUserGroupDns(cfg, connection, userDn).Select(dn => GroupDtoFromDn(connection, dn)).ToList();
                await http.Response.WriteAsJsonAsync(new
                {
                    success = true,
                    user = userDn,
                    addedCount = toAdd.Count,
                    removedCount = toRemove.Count,
                    count = updated.Count,
                    groups = updated
                });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /explorer/user-groups/set] DirectoryOperationException");
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /explorer/user-groups/set] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/group-members?group=<dn|sam|cn>
        app.MapGet("/explorer/group-members", async (HttpContext http) =>
        {
            try
            {
                var group = (http.Request.Query["group"].FirstOrDefault() ?? "").Trim();
                if (string.IsNullOrWhiteSpace(group))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "group requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var groupDn = ResolveGroupDn(cfg, connection, group);
                if (string.IsNullOrWhiteSpace(groupDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Groupe introuvable." });
                    return;
                }

                var members = GetDirectGroupMemberDns(connection, groupDn).Select(dn =>
                {
                    if (!TryGetEntry(connection, dn, out var u, new[] { "distinguishedName", "cn", "name", "sAMAccountName", "userPrincipalName", "objectClass" }) || u is null)
                    {
                        return new { name = DnToCn(dn) ?? dn, sam = (string?)null, upn = (string?)null, dn, type = "other" };
                    }
                    return new
                    {
                        name = u.Attributes["cn"]?[0]?.ToString() ?? u.Attributes["name"]?[0]?.ToString() ?? DnToCn(u.DistinguishedName) ?? u.DistinguishedName,
                        sam = u.Attributes["sAMAccountName"]?[0]?.ToString(),
                        upn = u.Attributes["userPrincipalName"]?[0]?.ToString(),
                        dn = u.DistinguishedName,
                        type = GetNodeTypeFromEntry(u)
                    };
                }).ToList();

                await http.Response.WriteAsJsonAsync(new
                {
                    group = groupDn,
                    count = members.Count,
                    members
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/group-members] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /explorer/group-members/set  Body: { group, members[] }
        app.MapPost("/explorer/group-members/set", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetGroupMembersRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.Group))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "group requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var groupDn = ResolveGroupDn(cfg, connection, req.Group);
                if (string.IsNullOrWhiteSpace(groupDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Groupe introuvable." });
                    return;
                }

                var current = new HashSet<string>(GetDirectGroupMemberDns(connection, groupDn), StringComparer.OrdinalIgnoreCase);
                var target = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var input in req.Members ?? new List<string>())
                {
                    var raw = (input ?? "").Trim();
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    var userDn = ResolveUserDn(cfg, connection, raw);
                    if (!string.IsNullOrWhiteSpace(userDn)) target.Add(userDn);
                }

                var toAdd = target.Except(current, StringComparer.OrdinalIgnoreCase).ToList();
                var toRemove = current.Except(target, StringComparer.OrdinalIgnoreCase).ToList();
                foreach (var userDn in toAdd)
                {
                    var mod = new DirectoryAttributeModification { Operation = DirectoryAttributeOperation.Add, Name = "member" };
                    mod.Add(userDn);
                    _ = (ModifyResponse)connection.SendRequest(new ModifyRequest(groupDn, mod));
                }
                foreach (var userDn in toRemove)
                {
                    var mod = new DirectoryAttributeModification { Operation = DirectoryAttributeOperation.Delete, Name = "member" };
                    mod.Add(userDn);
                    try
                    {
                        _ = (ModifyResponse)connection.SendRequest(new ModifyRequest(groupDn, mod));
                    }
                    catch (DirectoryOperationException doe)
                    {
                        var msg = doe.Response?.ErrorMessage ?? doe.Message ?? "";
                        if (msg.IndexOf("No such attribute", StringComparison.OrdinalIgnoreCase) < 0
                            && doe.Response?.ResultCode != ResultCode.NoSuchAttribute)
                        {
                            throw;
                        }
                    }
                }

                var updated = GetDirectGroupMemberDns(connection, groupDn);
                await http.Response.WriteAsJsonAsync(new
                {
                    success = true,
                    group = groupDn,
                    addedCount = toAdd.Count,
                    removedCount = toRemove.Count,
                    count = updated.Count
                });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /explorer/group-members/set] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /explorer/group-members/set] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/object?dn=<DN> — AD object details
        app.MapGet("/explorer/object", async (HttpContext http) =>
        {
            try
            {
                var dn = (http.Request.Query["dn"].FirstOrDefault() ?? "").Trim();
                if (string.IsNullOrWhiteSpace(dn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "dn requis." });
                    return;
                }

                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                if (!DnIsUnder(dn, explorerBaseDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "dn hors baseDn." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var attrs = new[]
                {
                    "distinguishedName", "name", "cn", "ou", "description",
                    "objectClass", "objectCategory", "sAMAccountName", "userPrincipalName",
                    "mail", "givenName", "sn", "telephoneNumber", "memberOf", "member",
                    "whenCreated", "whenChanged", "userAccountControl", "isCriticalSystemObject",
                    "adminDescription", "lockoutTime", "pwdLastSet",
                    "dNSHostName", "operatingSystem", "operatingSystemVersion", "managedBy",
                    "streetAddress", "wWWHomePage", "lastLogonTimestamp", "lastLogon",
                    "accountExpires", "primaryGroupID", "objectSid"
                };
                if (!TryGetEntry(connection, dn, out var entry, attrs) || entry is null)
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Objet introuvable." });
                    return;
                }

                var type = GetNodeTypeFromEntry(entry);
                var objectClasses = GetObjectClassesFromEntry(entry);
                var underBaseDn = DnIsUnder(dn, explorerBaseDn);

                bool isDisabled = false;
                var uacStr = entry.Attributes["userAccountControl"]?[0]?.ToString();
                if (int.TryParse(uacStr, out var uac))
                {
                    isDisabled = (uac & 0x0002) != 0;
                }

                var members = entry.Attributes["member"]?.GetValues(typeof(string)).Cast<string>().ToArray()
                              ?? Array.Empty<string>();
                var memberOfList = entry.Attributes["memberOf"]?.GetValues(typeof(string)).Cast<string>()
                    .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                    ?? new List<string>();
                int? explorerPrimaryGroupId = null;
                string? explorerPrimaryGroupDn = null;
                if (string.Equals(type, "user", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(type, "inetOrgPerson", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(type, "computer", StringComparison.OrdinalIgnoreCase))
                {
                    if (TryReadPrimaryGroupRid(entry, out var pge))
                        explorerPrimaryGroupId = pge;
                    string? primaryDn = null;
                    try { primaryDn = explorerPrimaryGroupDn = GetPrimaryGroupDn(cfg, connection, entry); }
                    catch (Exception ex) { Log.Warning(ex, "[GET /explorer/object] Primary group resolution failed."); }
                    if (!string.IsNullOrWhiteSpace(primaryDn) && !memberOfList.Exists(d => d.Equals(primaryDn, StringComparison.OrdinalIgnoreCase)))
                        memberOfList.Insert(0, primaryDn);
                }
                var memberOf = memberOfList.ToArray();
                var dnsHostName = entry.Attributes["dNSHostName"]?[0]?.ToString();
                var hostIps = await ResolveHostIpsAsync(dnsHostName);
                var whenCreatedRaw = entry.Attributes["whenCreated"]?[0]?.ToString();
                var whenChangedRaw = entry.Attributes["whenChanged"]?[0]?.ToString();
                var createdAtUtc = ParseAdGeneralizedTimeUtc(whenCreatedRaw);
                var changedAtUtc = ParseAdGeneralizedTimeUtc(whenChangedRaw);
                var lastLogonTsRaw = entry.Attributes["lastLogonTimestamp"]?[0]?.ToString();
                var lastLogonRaw = entry.Attributes["lastLogon"]?[0]?.ToString();
                var lastBindAtUtc = ParseAdFileTimeUtc(lastLogonRaw) ?? ParseAdFileTimeUtc(lastLogonTsRaw);

                var (accountExpiresAtUtc, accountNeverExpires) = DecodeAccountExpiresFromEntry(entry);
                var mustChangePasswordAtNextLogon = PwdMustChangeAtNextLogon(entry);

                var caps = BuildExplorerCapabilities(type, underBaseDn);
                var deleteGroupBlocked = false;
                string? deleteGroupBlockedDetail = null;
                if (string.Equals(type, "group", StringComparison.OrdinalIgnoreCase))
                {
                    var gSidB = ReadObjectSidBytes(entry);
                    if (TryGetRidFromObjectSidBytes(gSidB, out var grid)
                        && AnyUserOrComputerUsesPrimaryGroupRid(connection, EffectiveExplorerBaseDn(cfg), grid))
                    {
                        deleteGroupBlocked = true;
                        deleteGroupBlockedDetail =
                            "Ce groupe est le groupe principal d’au moins un compte utilisateur ou ordinateur. Modifiez d’abord le groupe principal de ces comptes avant suppression.";
                        caps["canDeleteGroup"] = false;
                    }
                }

                await http.Response.WriteAsJsonAsync(new
                {
                    dn,
                    type,
                    objectClasses,
                    underBaseDn,
                    protectedOu = type == "ou" ? OuIsProtected(connection, dn) : false,
                    isDisabled,
                    deleteGroupBlocked,
                    deleteGroupBlockedDetail,
                    capabilities = caps,
                    attributes = new
                    {
                        name = entry.Attributes["name"]?[0]?.ToString(),
                        cn = entry.Attributes["cn"]?[0]?.ToString(),
                        ou = entry.Attributes["ou"]?[0]?.ToString(),
                        description = entry.Attributes["description"]?[0]?.ToString(),
                        samAccountName = entry.Attributes["sAMAccountName"]?[0]?.ToString(),
                        userPrincipalName = entry.Attributes["userPrincipalName"]?[0]?.ToString(),
                        mail = entry.Attributes["mail"]?[0]?.ToString(),
                        givenName = entry.Attributes["givenName"]?[0]?.ToString(),
                        sn = entry.Attributes["sn"]?[0]?.ToString(),
                        telephoneNumber = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                        streetAddress = entry.Attributes["streetAddress"]?[0]?.ToString(),
                        website = entry.Attributes["wWWHomePage"]?[0]?.ToString(),
                        accountNeverExpires,
                        accountExpiresUtc = accountExpiresAtUtc?.ToString("o"),
                        mustChangePasswordAtNextLogon,
                        whenCreated = whenCreatedRaw,
                        whenChanged = whenChangedRaw,
                        createdAtUtc = createdAtUtc?.ToString("o"),
                        changedAtUtc = changedAtUtc?.ToString("o"),
                        isCriticalSystemObject = entry.Attributes["isCriticalSystemObject"]?[0]?.ToString(),
                        adminDescription = entry.Attributes["adminDescription"]?[0]?.ToString(),
                        lockoutTime = entry.Attributes["lockoutTime"]?[0]?.ToString(),
                        pwdLastSet = entry.Attributes["pwdLastSet"]?[0]?.ToString(),
                        dnsHostName = dnsHostName,
                        ipAddresses = hostIps,
                        operatingSystem = entry.Attributes["operatingSystem"]?[0]?.ToString(),
                        operatingSystemVersion = entry.Attributes["operatingSystemVersion"]?[0]?.ToString(),
                        managedBy = entry.Attributes["managedBy"]?[0]?.ToString(),
                        lastLogonTimestamp = lastLogonTsRaw,
                        lastLogon = lastLogonRaw,
                        lastBindAtUtc = lastBindAtUtc?.ToString("o"),
                        lastUserConnected = entry.Attributes["managedBy"]?[0]?.ToString(),
                        memberCount = members.Length,
                        memberOfCount = memberOf.Length,
                        memberOf,
                        primaryGroupId = explorerPrimaryGroupId,
                        primaryGroupDn = explorerPrimaryGroupDn
                    }
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/object] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /explorer/children?dn=<DN>&max=200 — direct children of an object
        app.MapGet("/explorer/children", async (HttpContext http) =>
        {
            try
            {
                var dn = (http.Request.Query["dn"].FirstOrDefault() ?? "").Trim();
                if (string.IsNullOrWhiteSpace(dn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "dn requis." });
                    return;
                }

                int max = 200;
                if (int.TryParse(http.Request.Query["max"], out var m) && m > 0 && m <= 1000) max = m;

                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                if (!DnIsUnder(dn, explorerBaseDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "dn hors baseDn." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var searchAttrs = new[] { "distinguishedName", "name", "cn", "ou", "description", "objectClass" };
                var collected = new List<SearchResultEntry>();
                byte[]? pageCookie = null;
                var pageSize = Math.Min(1000, Math.Max(64, max));

                while (collected.Count < max)
                {
                    var req = new SearchRequest(dn, "(objectClass=*)", SearchScope.OneLevel, searchAttrs);
                    req.SizeLimit = 0;
                    var prq = new PageResultRequestControl(pageSize);
                    if (pageCookie is { Length: > 0 }) prq.Cookie = pageCookie;
                    req.Controls.Add(prq);

                    var resp = (SearchResponse)connection.SendRequest(req);
                    foreach (SearchResultEntry e in resp.Entries)
                    {
                        collected.Add(e);
                        if (collected.Count >= max) break;
                    }

                    var prc = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                    if (collected.Count >= max) break;
                    if (prc is null || prc.Cookie is null || prc.Cookie.Length == 0) break;
                    pageCookie = prc.Cookie;
                }

                var children = collected
                    .Select(e =>
                    {
                        var childType = GetNodeTypeFromEntry(e);
                        var childDn = e.DistinguishedName;
                        return new
                        {
                            name = GetNameFromEntry(e),
                            dn = childDn,
                            type = childType,
                            objectClasses = GetObjectClassesFromEntry(e),
                            description = e.Attributes["description"]?[0]?.ToString(),
                            hasChildren = NodeHasAnyChildren(connection, childDn),
                            underBaseDn = DnIsUnder(childDn, explorerBaseDn)
                        };
                    })
                    .OrderBy(x => x.name, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                await http.Response.WriteAsJsonAsync(new
                {
                    dn,
                    count = children.Count,
                    max,
                    children
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /explorer/children] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // GET /tree — subtree from a DN
        app.MapGet("/tree", async (HttpContext http) =>
        {
            try
            {
                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Query parameters
                string explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                string baseDn = http.Request.Query["baseDn"].FirstOrDefault() ?? explorerBaseDn;
                if (!DnIsUnder(baseDn, explorerBaseDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "baseDn hors périmètre autorisé." });
                    return;
                }

                int depth = 3;
                if (int.TryParse(http.Request.Query["depth"], out var d) && d >= 1 && d <= 10) depth = d;

                bool includeLeaves = false;
                if (bool.TryParse(http.Request.Query["includeLeaves"], out var il)) includeLeaves = il;

                int maxChildren = 200;
                if (int.TryParse(http.Request.Query["maxChildren"], out var mc) && mc > 0 && mc <= 2000) maxChildren = mc;

                var tree = BuildTree(connection, baseDn, depth, includeLeaves, maxChildren);

                await http.Response.WriteAsJsonAsync(new
                {
                    baseDn,
                    explorerBaseDn,
                    depth,
                    includeLeaves,
                    maxChildren,
                    nodes = tree
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GET /tree] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/enableUser (alias for setUserEnabled: true)
        // Body JSON: { "user": "<sAMAccountName|DN>" }
        app.MapPost("/admin/enableUser", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetUserEnabledRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.User))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                string userDn;
                int? uac = null;

                if (req.User.Contains("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    // DN fourni
                    userDn = req.User;
                    var baseReq = new SearchRequest(userDn, "(objectClass=user)", SearchScope.Base, new[] { "userAccountControl" });
                    var baseResp = await Task.Run(() => (SearchResponse)connection.SendRequest(baseReq));
                    if (baseResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable (DN invalide)." });
                        return;
                    }
                    var uacStr = baseResp.Entries[0].Attributes["userAccountControl"]?[0]?.ToString();
                    if (int.TryParse(uacStr, out var parsed)) uac = parsed;
                }
                else
                {
                    // sAMAccountName
                    var safe = EscapeLdapFilterValue(req.User);
                    var sReq = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safe}))",
                        SearchScope.Subtree,
                        new[] { "distinguishedName", "userAccountControl" }
                    );
                    var sResp = await Task.Run(() => (SearchResponse)connection.SendRequest(sReq));
                    if (sResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                        return;
                    }
                    var ent = sResp.Entries[0];
                    userDn = ent.DistinguishedName;
                    var uacStr = ent.Attributes["userAccountControl"]?[0]?.ToString();
                    if (int.TryParse(uacStr, out var parsed)) uac = parsed;
                }

                if (!SetUserEnabled(cfg, userDn, true, uac))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Impossible d'activer l'utilisateur." });
                    return;
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn, enabled = true });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/enableUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/disableUser (alias for setUserEnabled: false)
        // Body JSON: { "user": "<sAMAccountName|DN>" }
        app.MapPost("/admin/disableUser", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetUserEnabledRequest>();
                if (req == null || string.IsNullOrWhiteSpace(req.User))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                string userDn;
                int? uac = null;

                if (req.User.Contains("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    userDn = req.User;
                    var baseReq = new SearchRequest(userDn, "(objectClass=user)", SearchScope.Base, new[] { "userAccountControl" });
                    var baseResp = await Task.Run(() => (SearchResponse)connection.SendRequest(baseReq));
                    if (baseResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable (DN invalide)." });
                        return;
                    }
                    var uacStr = baseResp.Entries[0].Attributes["userAccountControl"]?[0]?.ToString();
                    if (int.TryParse(uacStr, out var parsed)) uac = parsed;
                }
                else
                {
                    var safe = EscapeLdapFilterValue(req.User);
                    var sReq = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safe}))",
                        SearchScope.Subtree,
                        new[] { "distinguishedName", "userAccountControl" }
                    );
                    var sResp = await Task.Run(() => (SearchResponse)connection.SendRequest(sReq));
                    if (sResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                        return;
                    }
                    var ent = sResp.Entries[0];
                    userDn = ent.DistinguishedName;
                    var uacStr = ent.Attributes["userAccountControl"]?[0]?.ToString();
                    if (int.TryParse(uacStr, out var parsed)) uac = parsed;
                }

                if (!SetUserEnabled(cfg, userDn, false, uac))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Impossible de désactiver l'utilisateur." });
                    return;
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = userDn, enabled = false });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/disableUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        app.MapPost("/admin/moveUser", async(HttpContext http) =>
        {
            try {
                var req = await http.Request.ReadFromJsonAsync<MoveUserRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User) || string.IsNullOrWhiteSpace(req.NewOuDn)) {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "User et NewOuDn requis." });
                    return;
                }

                // Normalize target OU (avoid stray spaces/tags in DN)
                var targetOuDn = req.NewOuDn.Trim();
                if (string.IsNullOrWhiteSpace(targetOuDn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "OU cible invalide." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve user DN
                string userDn;
                if (req.User.Contains("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    userDn = req.User;
                }
                else
                {
                    var safe = EscapeLdapFilterValue(req.User);
                    var sReq = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safe}))",
                        SearchScope.Subtree,
                        new[] { "distinguishedName" });
                    var sResp = await Task.Run(() => (SearchResponse)connection.SendRequest(sReq));
                    if (sResp.Entries.Count == 0) { http.Response.StatusCode = 404; await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." }); return; }
                    userDn = sResp.Entries[0].DistinguishedName;
                }

                // Ensure target exists (OU/container)
                try
                {
                    var chk = new SearchRequest(targetOuDn, "(|(objectClass=organizationalUnit)(objectClass=container))", SearchScope.Base, "distinguishedName");
                    var chkResp = await Task.Run(() => (SearchResponse)connection.SendRequest(chk));
                    if (chkResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "OU cible introuvable." });
                        return;
                    }
                }
                catch (DirectoryOperationException doe)
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "OU cible invalide (DN).", serverError = doe.Response?.ErrorMessage ?? doe.Message });
                    return;
                }

                // Keep same RDN (CN=...)
                var rdn = userDn.Split(',')[0]; // ex. "CN=John Doe"
                var move = new ModifyDNRequest(userDn, targetOuDn, rdn) { DeleteOldRdn = true };
                _ = (ModifyDNResponse)connection.SendRequest(move);

                await http.Response.WriteAsJsonAsync(new { success = true, dn = $"{rdn},{targetOuDn}" });
            }
            catch (DirectoryOperationException doe) {
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex) {
                Log.Error(ex, "[POST /admin/moveUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/unlockUser
        app.MapPost("/admin/unlockUser", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<UnlockUserRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve user to DN (accepts DN or sAM)
                string userDn = LooksLikeDn(req.User)
                    ? req.User
                    : (SearchUserBySam(cfg, req.User) as dynamic)?.dn;

                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                // Unlock = set lockoutTime to 0
                var mod = new DirectoryAttributeModification
                {
                    Operation = DirectoryAttributeOperation.Replace,
                    Name = "lockoutTime"
                };
                mod.Add("0");

                var mreq = new ModifyRequest(userDn, mod);
                _ = (ModifyResponse)connection.SendRequest(mreq);

                await http.Response.WriteAsJsonAsync(new { success = true });
            }
            catch (DirectoryOperationException doe)
            {
                // If already unlocked, some DCs return "No such attribute"
                var msg = doe.Response?.ErrorMessage ?? doe.Message ?? "";
                if (msg.IndexOf("No such attribute", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    await http.Response.WriteAsJsonAsync(new { success = true, note = "Compte déjà déverrouillé." });
                    return;
                }

                Log.Error(doe, "[POST /admin/unlockUser] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/unlockUser] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/renameUserCn
        app.MapPost("/admin/renameUserCn", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<RenameCnRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User) || string.IsNullOrWhiteSpace(req.NewCn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user et newCn requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve DN
                string userDn = LooksLikeDn(req.User)
                    ? req.User
                    : (SearchUserBySam(cfg, req.User) as dynamic)?.dn;

                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                // Parent DN = user DN without first RDN component
                var parts = userDn.Split(',', 2);
                if (parts.Length < 2)
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "DN utilisateur invalide." });
                    return;
                }
                var parentDn = parts[1];
                var newRdn = "CN=" + EscapeRdnValue(req.NewCn);

                var rename = new ModifyDNRequest(userDn, parentDn, newRdn) { DeleteOldRdn = true };
                _ = (ModifyDNResponse)connection.SendRequest(rename);

                await http.Response.WriteAsJsonAsync(new { success = true, newDn = $"{newRdn},{parentDn}" });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /admin/renameUserCn] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/renameUserCn] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/createGroup
        app.MapPost("/admin/createGroup", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<CreateGroupRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.OuDn) || string.IsNullOrWhiteSpace(req.Cn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "Champs requis: ouDn, cn." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Ensure target OU exists
                var chk = new SearchRequest(req.OuDn, "(|(objectClass=organizationalUnit)(objectClass=container))", SearchScope.Base, "distinguishedName");
                var chkResp = await Task.Run(() => (SearchResponse)connection.SendRequest(chk));
                if (chkResp.Entries.Count == 0)
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "OU/Container cible introuvable." });
                    return;
                }

                string groupDn = $"CN={EscapeRdnValue(req.Cn)},{req.OuDn}";
                var groupType = ComputeGroupType(req.Scope, req.SecurityEnabled);

                // Optional sAM — if omitted, derive from CN (no spaces)
                var sam = string.IsNullOrWhiteSpace(req.Sam)
                    ? req.Cn.Replace(' ', '_')
                    : req.Sam;

                var add = new AddRequest(
                    groupDn,
                    new DirectoryAttribute("objectClass", "top", "group"),
                    new DirectoryAttribute("cn", req.Cn),
                    new DirectoryAttribute("sAMAccountName", sam),
                    new DirectoryAttribute("groupType", groupType.ToString()) // AD expects signed int string
                );
                if (!string.IsNullOrWhiteSpace(req.Description))
                    add.Attributes.Add(new DirectoryAttribute("description", req.Description));

                _ = (AddResponse)connection.SendRequest(add);
                await http.Response.WriteAsJsonAsync(new { success = true, dn = groupDn });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /admin/createGroup] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/createGroup] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // DELETE|POST /admin/deleteGroup
        app.MapMethods("/admin/deleteGroup", new[] { "DELETE", "POST" }, async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<DeleteGroupRequest>() ?? new DeleteGroupRequest(null, null);
                string? input = req.Dn ?? req.Group;

                if (string.IsNullOrWhiteSpace(input))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "dn ou group requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve DN when needed
                string? groupDn = LooksLikeDn(input) ? input : ResolveGroupDn(cfg, connection, input);
                if (string.IsNullOrWhiteSpace(groupDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Groupe introuvable." });
                    return;
                }

                if (!TryGetEntry(connection, groupDn, out var gDelEntry, new[] { "objectSid" }) || gDelEntry is null)
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Groupe introuvable (lecture LDAP)." });
                    return;
                }

                var gSidDel = ReadObjectSidBytes(gDelEntry);
                if (TryGetRidFromObjectSidBytes(gSidDel, out var ridDel)
                    && AnyUserOrComputerUsesPrimaryGroupRid(connection, EffectiveExplorerBaseDn(cfg), ridDel))
                {
                    http.Response.StatusCode = 409;
                    await http.Response.WriteAsJsonAsync(new
                    {
                        error = "Impossible de supprimer ce groupe : il est le groupe principal d’au moins un compte utilisateur ou ordinateur. Changez d’abord le groupe principal de ces comptes.",
                        code = "primary_group_in_use"
                    });
                    return;
                }

                var del = new DeleteRequest(groupDn);
                _ = (DeleteResponse)connection.SendRequest(del);
                await http.Response.WriteAsJsonAsync(new { success = true, dn = groupDn });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[/admin/deleteGroup] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[/admin/deleteGroup] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/setAccountExpiration
        // Body: { "user": "<sAM|DN>", "expiresAt": "2026-01-31T23:59:59Z", "never": true|false }
        app.MapPost("/admin/setAccountExpiration", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetAccountExpirationRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User) || (req.Never != true && !req.ExpiresAt.HasValue))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user et (never=true OU expiresAt) requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Resolve DN
                string userDn;
                if (LooksLikeDn(req.User)) userDn = req.User;
                else
                {
                    var safe = EscapeLdapFilterValue(req.User);
                    var sReq = new SearchRequest(
                        cfg.Ldap.BaseDn,
                        $"(&(&(objectCategory=person)(objectClass=user))(sAMAccountName={safe}))",
                        SearchScope.Subtree,
                        new[] { "distinguishedName" });
                    var sResp = await Task.Run(() => (SearchResponse)connection.SendRequest(sReq));
                    if (sResp.Entries.Count == 0)
                    {
                        http.Response.StatusCode = 404;
                        await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                        return;
                    }
                    userDn = sResp.Entries[0].DistinguishedName;
                }

                var mod = BuildReplaceAccountExpires(req.Never == true, req.ExpiresAt);
                var mreq = new ModifyRequest(userDn, mod);
                _ = (ModifyResponse)connection.SendRequest(mreq);

                await http.Response.WriteAsJsonAsync(new
                {
                    success = true,
                    dn = userDn,
                    expiresNever = (req.Never == true),
                    expiresAt = req.ExpiresAt?.ToString("o")
                });
            }
            catch (DirectoryOperationException doe)
            {
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/setAccountExpiration] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/setUserPrimaryGroup  Body: { "user": "<sAM|DN>", "group": "<sAM|CN|DN>" }
        app.MapPost("/admin/setUserPrimaryGroup", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<SetUserPrimaryGroupRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.User) || string.IsNullOrWhiteSpace(req.Group))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "user et group requis." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                var userDn = ResolveUserDn(cfg, connection, req.User.Trim());
                if (string.IsNullOrWhiteSpace(userDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Utilisateur introuvable." });
                    return;
                }

                var groupDn = ResolveGroupDn(cfg, connection, req.Group.Trim());
                if (string.IsNullOrWhiteSpace(groupDn))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "Groupe introuvable." });
                    return;
                }

                SetUserPrimaryGroup(cfg, connection, userDn, groupDn);
                await http.Response.WriteAsJsonAsync(new { success = true, userDn, groupDn });
            }
            catch (InvalidOperationException iox)
            {
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = iox.Message });
            }
            catch (DirectoryOperationException doe)
            {
                Log.Error(doe, "[POST /admin/setUserPrimaryGroup] DirectoryOperationException");
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/setUserPrimaryGroup] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/ou/create
        app.MapPost("/admin/ou/create", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<CreateOuRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.ParentDn) || string.IsNullOrWhiteSpace(req.Name))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "ParentDn et Name requis." });
                    return;
                }

                var parentDn = req.ParentDn.Trim();
                var ouName = req.Name.Trim();
                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                if (!DnIsUnder(parentDn, explorerBaseDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "ParentDn non autorisé (hors baseDn explorateur)." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Ensure parent is a valid container (OU/container/domain)
                if (!TryGetEntry(connection, parentDn, out var parent, new[] { "objectClass", "objectCategory" }) || parent is null || !EntryIsContainer(parent))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "DN parent introuvable ou non conteneur." });
                    return;
                }

                var ouDn = NewOuDn(parentDn, ouName);

                var add = new AddRequest(
                    ouDn,
                    new DirectoryAttribute("objectClass", "top", "organizationalUnit"),
                    new DirectoryAttribute("ou", ouName)
                );

                if (!string.IsNullOrWhiteSpace(req.Description))
                    add.Attributes.Add(new DirectoryAttribute("description", req.Description));

                _ = (AddResponse)connection.SendRequest(add);

                // Protection = DACL (RSAT), not adminDescription (often unset on organizationalUnit).
                if (req.Protected == true)
                {
                    if (!TrySetOuAccidentalDeletionProtection(connection, ouDn, true, out var protErr))
                    {
                        try
                        {
                            _ = (DeleteResponse)connection.SendRequest(new DeleteRequest(ouDn));
                        }
                        catch (Exception delEx)
                        {
                            Log.Warning(delEx, "Rollback OU après échec protection : {OuDn}", ouDn);
                        }
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new
                        {
                            error = "OU créée puis annulée : impossible d’appliquer la protection (DACL).",
                            serverError = protErr,
                            hint = "Le compte de service LDAP doit pouvoir lire/écrire nTSecurityDescriptor sur l’OU et son parent (Write DACL, souvent « Contrôle total » sur l’OU et le parent)."
                        });
                        return;
                    }
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = ouDn });
            }
            catch (DirectoryOperationException doe)
            {
                http.Response.StatusCode = 400;
                await http.Response.WriteAsJsonAsync(new { error = doe.Message, serverError = doe.Response?.ErrorMessage });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/ou/create] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/ou/update (rename / move / desc / protected)
        app.MapPost("/admin/ou/update", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<UpdateOuRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.OuDn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "OuDn requis." });
                    return;
                }

                req.OuDn = req.OuDn.Trim();
                if (!string.IsNullOrWhiteSpace(req.NewParentDn))
                    req.NewParentDn = req.NewParentDn.Trim();
                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);

                if (!DnIsUnder(req.OuDn, explorerBaseDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "OuDn hors baseDn explorateur." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                if (!TryGetEntry(connection, req.OuDn, out var entry) || entry is null || !EntryIsOu(entry))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "OU introuvable." });
                    return;
                }

                string currentDn = req.OuDn;

                // 1) Move/rename in a single operation when possible
                bool wantRename = !string.IsNullOrWhiteSpace(req.NewName);
                bool wantMove = !string.IsNullOrWhiteSpace(req.NewParentDn);

                if (wantMove)
                {
                    if (!DnIsUnder(req.NewParentDn!, explorerBaseDn))
                    {
                        http.Response.StatusCode = 403;
                        await http.Response.WriteAsJsonAsync(new { error = "NewParentDn hors baseDn explorateur." });
                        return;
                    }
                    if (!ParentAcceptsOu(connection, req.NewParentDn!))
                    {
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new { error = "Le parent cible n'accepte pas une OU." });
                        return;
                    }
                }

                if (wantRename || wantMove)
                {
                    var targetParent = wantMove ? req.NewParentDn! : ParentDnOf(currentDn);
                    var newRdn = "OU=" + EscapeRdnValue(
                        wantRename ? req.NewName! : currentDn[3..currentDn.IndexOf(',')]
                    );

                    var moddn = new ModifyDNRequest(currentDn, targetParent, newRdn)
                    {
                        DeleteOldRdn = true
                    };
                    _ = (ModifyDNResponse)connection.SendRequest(moddn);

                    currentDn = $"{newRdn},{targetParent}";
                }

                // 2) Protection = DACL on OU + parent (RSAT-style), not adminDescription on the OU.
                if (req.Protected.HasValue)
                {
                    // Avoid rewriting nTSecurityDescriptor when state is already the requested one.
                    // This prevents unnecessary ACL writes for "no-op" updates (rename/description only).
                    var currentProtected = OuIsProtected(connection, currentDn);
                    if (currentProtected != req.Protected.Value
                        && !TrySetOuAccidentalDeletionProtection(connection, currentDn, req.Protected.Value, out var protErr))
                    {
                        http.Response.StatusCode = 400;
                        await http.Response.WriteAsJsonAsync(new
                        {
                            error = "Échec de la mise à jour de la protection (DACL / nTSecurityDescriptor).",
                            serverError = protErr,
                            hint = "Compte de service : droits de lecture/écriture du descripteur de sécurité sur l’OU et son conteneur parent."
                        });
                        return;
                    }
                }

                // 3) Description only (null => leave unchanged; "" => remove)
                if (req.Description != null)
                {
                    var m = new DirectoryAttributeModification { Name = "description" };
                    if (req.Description == "")
                        m.Operation = DirectoryAttributeOperation.Delete;
                    else
                    {
                        m.Operation = DirectoryAttributeOperation.Replace;
                        m.Add(req.Description);
                    }
                    var mreq = new ModifyRequest(currentDn, m);
                    _ = (ModifyResponse)connection.SendRequest(mreq);
                }

                await http.Response.WriteAsJsonAsync(new { success = true, dn = currentDn });
            }
            catch (DirectoryOperationException doe)
            {
                var code = Map(doe.Response?.ResultCode ?? ResultCode.Other);
                http.Response.StatusCode = code;
                await http.Response.WriteAsJsonAsync(new
                {
                    error = "LDAP error",
                    ldapCode = doe.Response?.ResultCode.ToString(),
                    serverError = doe.Response?.ErrorMessage
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/ou/update] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        // POST /admin/ou/delete
        app.MapPost("/admin/ou/delete", async (HttpContext http) =>
        {
            try
            {
                var req = await http.Request.ReadFromJsonAsync<DeleteOuRequest>();
                if (req is null || string.IsNullOrWhiteSpace(req.OuDn))
                {
                    http.Response.StatusCode = 400;
                    await http.Response.WriteAsJsonAsync(new { error = "OuDn requis." });
                    return;
                }

                var ouDn = req.OuDn.Trim();
                var explorerBaseDn = EffectiveExplorerBaseDn(cfg);
                if (!DnIsUnder(ouDn, explorerBaseDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "OuDn hors baseDn explorateur." });
                    return;
                }

                using var connection = GetLdapConnection(cfg);
                if (!BindServiceAccount(connection, cfg))
                {
                    http.Response.StatusCode = 500;
                    await http.Response.WriteAsJsonAsync(new { error = "Bind LDAP échoué." });
                    return;
                }

                // Verify OU via BASE search
                if (!TryGetEntry(connection, ouDn, out var ou) || ou is null || !EntryIsOu(ou))
                {
                    http.Response.StatusCode = 404;
                    await http.Response.WriteAsJsonAsync(new { error = "OU introuvable." });
                    return;
                }

                if (OuIsProtected(connection, ouDn))
                {
                    http.Response.StatusCode = 403;
                    await http.Response.WriteAsJsonAsync(new { error = "OU protégée contre la suppression." });
                    return;
                }

                if (!OuIsEmpty(connection, ouDn))
                {
                    http.Response.StatusCode = 409;
                    await http.Response.WriteAsJsonAsync(new { error = "OU non vide : suppression refusée." });
                    return;
                }

                var del = new DeleteRequest(ouDn);
                _ = (DeleteResponse)connection.SendRequest(del);

                await http.Response.WriteAsJsonAsync(new { success = true, dn = ouDn });
            }
            catch (DirectoryOperationException doe)
            {
                var code = Map(doe.Response?.ResultCode ?? ResultCode.Other);
                http.Response.StatusCode = code;
                await http.Response.WriteAsJsonAsync(new
                {
                    error = "LDAP error",
                    ldapCode = doe.Response?.ResultCode.ToString(),
                    serverError = doe.Response?.ErrorMessage
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[POST /admin/ou/delete] Exception");
                http.Response.StatusCode = 500;
                await http.Response.WriteAsJsonAsync(new { error = ex.Message });
            }
        });

        app.Run();
    }

    private static void HandleWindowsServiceCommand(bool add)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("L'installation du service Windows n'est possible que sous Windows.");
            return;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        var isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
        if (!isAdmin)
        {
            Console.Error.WriteLine("Cette commande nécessite les droits administrateur. Lancez l'invite de commandes en tant qu'administrateur puis réessayez.");
            return;
        }

        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(exePath))
        {
            Console.Error.WriteLine("Impossible de déterminer le chemin de l'exécutable.");
            return;
        }

        const string serviceName = "ADSelfServiceAPI";
        const string description = "API REST d'auto-service et d'administration Active Directory.";

        try
        {
            if (add)
            {
                RunScCommand($"create {serviceName} binPath= \"{exePath}\" start= auto");
                RunScCommand($"description {serviceName} \"{description}\"");
                Console.WriteLine($"Service Windows '{serviceName}' créé avec succès.");
                Console.WriteLine("Démarrez-le ensuite via services.msc ou avec : sc start " + serviceName);
            }
            else
            {
                RunScCommand($"delete {serviceName}");
                Console.WriteLine($"Service Windows '{serviceName}' supprimé (il sera définitivement retiré après arrêt).");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Erreur lors de la configuration du service Windows : " + ex.Message);
        }
    }

    private static void RunScCommand(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc == null)
        {
            Console.Error.WriteLine("Impossible de lancer la commande 'sc'.");
            return;
        }

        var output = proc.StandardOutput.ReadToEnd();
        var error = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        if (!string.IsNullOrWhiteSpace(output))
            Console.WriteLine(output.Trim());
        if (!string.IsNullOrWhiteSpace(error))
            Console.Error.WriteLine(error.Trim());
    }
}
