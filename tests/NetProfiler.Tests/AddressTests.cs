using System.Net;
using NetProfiler.Core;

namespace NetProfiler.Tests;

public class AddressNormalizerTests
{
    [Fact]
    public void Ipv4_mapped_ipv6_becomes_plain_ipv4()
    {
        var result = AddressNormalizer.Normalize(IPAddress.Parse("::ffff:10.1.2.3"));

        Assert.Equal(IPAddress.Parse("10.1.2.3"), result);
    }

    [Fact]
    public void Ipv6_scope_id_is_dropped_so_keys_from_different_sources_match()
    {
        var withScope = IPAddress.Parse("fe80::1%12");

        var result = AddressNormalizer.Normalize(withScope);

        Assert.Equal(0, result.ScopeId);
        Assert.Equal(IPAddress.Parse("fe80::1"), result);
    }

    [Fact]
    public void Plain_ipv4_is_unchanged()
    {
        var address = IPAddress.Parse("8.8.4.4");

        Assert.Equal(address, AddressNormalizer.Normalize(address));
    }
}

public class FlowOrientationTests
{
    private static readonly IPAddress Me = IPAddress.Parse("192.168.1.10");
    private static readonly IPAddress Them = IPAddress.Parse("142.250.74.46");
    private static bool IsLocal(IPAddress a) => a.Equals(Me) || IPAddress.IsLoopback(a);

    [Fact]
    public void Source_is_local_when_source_is_our_address()
    {
        var (local, remote) = FlowOrientation.Orient(Me, 50000, Them, 443, IsLocal);

        Assert.Equal(new IPEndPoint(Me, 50000), local);
        Assert.Equal(new IPEndPoint(Them, 443), remote);
    }

    [Fact]
    public void Endpoints_are_swapped_when_destination_is_our_address()
    {
        var (local, remote) = FlowOrientation.Orient(Them, 443, Me, 50000, IsLocal);

        Assert.Equal(new IPEndPoint(Me, 50000), local);
        Assert.Equal(new IPEndPoint(Them, 443), remote);
    }

    [Fact]
    public void Loopback_traffic_keeps_source_as_local()
    {
        var (local, remote) = FlowOrientation.Orient(IPAddress.Loopback, 6000, IPAddress.Loopback, 7000, IsLocal);

        Assert.Equal(6000, local.Port);
        Assert.Equal(7000, remote.Port);
    }

    [Fact]
    public void Received_multicast_treats_the_sender_as_remote()
    {
        var sender = IPAddress.Parse("192.168.1.55");
        var group = IPAddress.Parse("239.255.255.250");

        var (local, remote) = FlowOrientation.Orient(sender, 1900, group, 1900, IsLocal);

        Assert.Equal(group, local.Address);
        Assert.Equal(sender, remote.Address);
    }

    [Fact]
    public void Mapped_addresses_are_normalized_while_orienting()
    {
        var mappedMe = IPAddress.Parse("::ffff:192.168.1.10");

        var (local, _) = FlowOrientation.Orient(Them, 443, mappedMe, 50000, IsLocal);

        Assert.Equal(Me, local.Address);
    }
}

public class LocalAddressSetTests
{
    [Fact]
    public void Contains_loopback_addresses()
    {
        var set = new LocalAddressSet();

        Assert.True(set.Contains(IPAddress.Loopback));
        Assert.True(set.Contains(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void Does_not_contain_public_internet_address()
    {
        var set = new LocalAddressSet();

        Assert.False(set.Contains(IPAddress.Parse("8.8.8.8")));
    }
}
