using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetProfiler.Core;

public static class AddressNormalizer
{
    /// <summary>
    /// Brings addresses from different sources (ETW, TCP table, user input) to one canonical form:
    /// IPv4-mapped IPv6 becomes IPv4 and IPv6 scope ids are dropped.
    /// </summary>
    public static IPAddress Normalize(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            return address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            return new IPAddress(address.GetAddressBytes());
        return address;
    }

    public static bool IsMulticastOrBroadcast(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6Multicast;
        var first = address.GetAddressBytes()[0];
        return first is >= 224 and <= 239 || address.Equals(IPAddress.Broadcast);
    }

    public static bool IsUnspecified(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
}

public static class FlowOrientation
{
    /// <summary>
    /// Kernel network events report a source and destination; this works out which side is this PC.
    /// </summary>
    public static (IPEndPoint Local, IPEndPoint Remote) Orient(
        IPAddress saddr, int sport, IPAddress daddr, int dport, Func<IPAddress, bool> isLocal)
    {
        var source = new IPEndPoint(AddressNormalizer.Normalize(saddr), sport);
        var destination = new IPEndPoint(AddressNormalizer.Normalize(daddr), dport);

        if (isLocal(source.Address))
            return (source, destination);
        if (isLocal(destination.Address))
            return (destination, source);
        // A multicast/broadcast group is never a sender, so the other side is the remote peer.
        if (AddressNormalizer.IsMulticastOrBroadcast(destination.Address))
            return (destination, source);
        return (source, destination);
    }
}

/// <summary>Addresses assigned to this PC's network adapters, refreshed when they change.</summary>
public sealed class LocalAddressSet : IDisposable
{
    private volatile HashSet<IPAddress> _addresses = [];

    public LocalAddressSet()
    {
        Refresh();
        NetworkChange.NetworkAddressChanged += OnAddressChanged;
    }

    public bool Contains(IPAddress address)
    {
        var normalized = AddressNormalizer.Normalize(address);
        return IPAddress.IsLoopback(normalized) || _addresses.Contains(normalized);
    }

    public void Refresh()
    {
        var set = new HashSet<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback, IPAddress.Any, IPAddress.IPv6Any };
        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            foreach (var unicast in adapter.GetIPProperties().UnicastAddresses)
                set.Add(AddressNormalizer.Normalize(unicast.Address));
        }
        catch (NetworkInformationException)
        {
            // Keep loopback-only set; next address change will retry.
        }
        _addresses = set;
    }

    public void Dispose() => NetworkChange.NetworkAddressChanged -= OnAddressChanged;

    private void OnAddressChanged(object? sender, EventArgs e) => Refresh();
}
