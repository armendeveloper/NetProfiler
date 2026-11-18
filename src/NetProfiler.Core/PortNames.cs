namespace NetProfiler.Core;

/// <summary>Short service names for well-known ports, shown next to the port number.</summary>
public static class PortNames
{
    private static readonly Dictionary<int, string> Known = new()
    {
        [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "dns",
        [67] = "dhcp", [68] = "dhcp", [80] = "http", [110] = "pop3", [123] = "ntp", [137] = "netbios",
        [138] = "netbios", [139] = "netbios", [143] = "imap", [161] = "snmp", [389] = "ldap", [443] = "https",
        [445] = "smb", [465] = "smtps", [587] = "smtp", [853] = "dns-tls", [993] = "imaps", [995] = "pop3s",
        [1900] = "ssdp", [3389] = "rdp", [3478] = "stun", [5222] = "xmpp", [5228] = "google-push",
        [5353] = "mdns", [5355] = "llmnr", [8080] = "http-alt", [8443] = "https-alt",
    };

    public static string Describe(int port) =>
        port == 0 ? "—" : Known.TryGetValue(port, out var name) ? $"{port} · {name}" : port.ToString();
}
