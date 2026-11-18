using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetProfiler.Core;

namespace NetProfiler.Tests;

// These talk to the real OS but only read state; none of them need administrator rights.
public class ConnectionTableTests
{
    [Fact]
    public async Task Lists_an_open_loopback_connection_owned_by_this_process()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, serverPort);
        using var accepted = await listener.AcceptTcpClientAsync();
        var clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        var entries = ConnectionTable.GetTcpConnections();

        var mine = Assert.Single(entries, e => e.Key.LocalPort == clientPort && e.Key.RemotePort == serverPort);
        Assert.Equal(Environment.ProcessId, mine.Pid);
        Assert.Equal("Established", mine.State);
        Assert.Equal(IPAddress.Loopback, mine.Key.RemoteAddress);
        Assert.Equal(NetProtocol.Tcp, mine.Key.Protocol);
    }

    [Fact]
    public void Lists_listening_sockets_with_unspecified_remote_address()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var entries = ConnectionTable.GetTcpConnections();

        var entry = Assert.Single(entries, e => e.Key.LocalPort == port && e.State == "Listening");
        Assert.Equal(0, entry.Key.RemotePort);
    }
}

public class ProcessResolverTests
{
    [Fact]
    public void Resolves_name_of_current_process()
    {
        var resolver = new ProcessResolver();

        var info = resolver.Get(Environment.ProcessId);

        Assert.Equal(Process.GetCurrentProcess().ProcessName, info.Name);
        Assert.False(string.IsNullOrEmpty(info.Path));
    }

    [Theory]
    [InlineData(0, "System Idle Process")]
    [InlineData(4, "System")]
    public void Well_known_kernel_pids_have_fixed_names(int pid, string expected)
    {
        Assert.Equal(expected, new ProcessResolver().Get(pid).Name);
    }

    [Fact]
    public void Missing_process_gets_a_placeholder_name()
    {
        var info = new ProcessResolver().Get(2_147_483_644);

        Assert.Contains("2147483644", info.Name);
        Assert.Null(info.Path);
    }
}

public class AdapterCountersTests
{
    [Fact]
    public void Byte_counters_never_go_backwards()
    {
        var first = AdapterCounters.Sample();
        var second = AdapterCounters.Sample();

        Assert.True(first.Received >= 0 && first.Sent >= 0);
        Assert.True(second.Received >= first.Received);
        Assert.True(second.Sent >= first.Sent);
    }
}

public class WindowsFirewallReadTests
{
    [Fact]
    public void Reading_blocked_list_works_without_admin_rights()
    {
        var firewall = new WindowsFirewall();

        var blocked = firewall.GetBlocked();

        Assert.NotNull(blocked);
    }

    [Fact]
    public void Dynamic_com_enumeration_used_by_the_firewall_class_sees_existing_rules()
    {
        // Guards the platform assumption GetBlocked relies on: foreach over a dynamic COM collection
        // must yield items on this runtime, otherwise the blocked list would silently be empty.
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;
        var names = new List<string>();

        foreach (dynamic rule in policy.Rules)
            names.Add((string)rule.Name);

        Assert.Equal((int)policy.Rules.Count, names.Count);
        Assert.NotEmpty(names);
    }

    [Fact]
    public void Reading_firewall_state_works_without_admin_rights()
    {
        var firewall = new WindowsFirewall();

        var state = firewall.GetState();

        Assert.NotEmpty(state.ActiveProfiles);
    }
}
