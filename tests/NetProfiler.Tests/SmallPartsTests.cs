using System.Net;
using NetProfiler.Core;

namespace NetProfiler.Tests;

public class ByteFormatTests
{
    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(1023, "1023 B")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(1048576, "1.0 MB")]
    [InlineData(5368709120, "5.0 GB")]
    public void Size_uses_binary_units_with_one_decimal(long bytes, string expected)
    {
        Assert.Equal(expected, ByteFormat.Size(bytes));
    }

    [Theory]
    [InlineData(0, "0 B/s")]
    [InlineData(0.4, "0 B/s")]
    [InlineData(2048, "2.0 KB/s")]
    [InlineData(3_670_016, "3.5 MB/s")]
    public void Rate_appends_per_second(double bytesPerSecond, string expected)
    {
        Assert.Equal(expected, ByteFormat.Rate(bytesPerSecond));
    }
}

public class RateHistoryTests
{
    [Fact]
    public void Keeps_only_the_newest_points_oldest_first()
    {
        var history = new RateHistory(3);

        for (var i = 1; i <= 4; i++)
            history.Add(i, i * 10);

        Assert.Equal(new[] { 2.0, 3.0, 4.0 }, history.Points.Select(p => p.In));
        Assert.Equal(new[] { 20.0, 30.0, 40.0 }, history.Points.Select(p => p.Out));
    }

    [Fact]
    public void Peak_is_the_largest_value_in_either_direction()
    {
        var history = new RateHistory(5);
        history.Add(100, 5);
        history.Add(10, 700);

        Assert.Equal(700, history.Peak);
    }
}

public class FirewallRuleNamesTests
{
    [Theory]
    [InlineData("8.8.8.8", FirewallDirection.Inbound, "NetProfiler Block 8.8.8.8 (In)")]
    [InlineData("10.0.0.0/24", FirewallDirection.Outbound, "NetProfiler Block 10.0.0.0/24 (Out)")]
    public void Rule_name_contains_target_and_direction(string target, FirewallDirection direction, string expected)
    {
        BlockTarget.TryParse(target, out var t, out _);

        Assert.Equal(expected, FirewallRuleNames.For(t!, direction));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2001:db8::/32")]
    public void Target_can_be_read_back_from_rule_name(string target)
    {
        BlockTarget.TryParse(target, out var t, out _);
        var name = FirewallRuleNames.For(t!, FirewallDirection.Outbound);

        Assert.True(FirewallRuleNames.TryParse(name, out var parsed, out var direction));
        Assert.Equal(t, parsed);
        Assert.Equal(FirewallDirection.Outbound, direction);
    }

    [Theory]
    [InlineData("Google Chrome (mDNS-In)")]
    [InlineData("NetProfiler Block not-an-ip (In)")]
    [InlineData("NetProfiler Block 8.8.8.8")]
    public void Foreign_or_damaged_rule_names_are_not_ours(string name)
    {
        Assert.False(FirewallRuleNames.TryParse(name, out _, out _));
    }
}

public class HostNameResolverTests
{
    [Fact]
    public async Task Same_address_is_looked_up_only_once()
    {
        var calls = 0;
        var resolver = new HostNameResolver(async (_, _) =>
        {
            Interlocked.Increment(ref calls);
            await Task.Delay(20);
            return "one.one.one.one";
        });
        var ip = IPAddress.Parse("1.1.1.1");

        var results = await Task.WhenAll(resolver.ResolveAsync(ip), resolver.ResolveAsync(ip), resolver.ResolveAsync(ip));

        Assert.All(results, r => Assert.Equal("one.one.one.one", r));
        Assert.Equal(1, calls);
        Assert.True(resolver.TryGetCached(ip, out var cached));
        Assert.Equal("one.one.one.one", cached);
    }

    // Needs a working DNS server. Regression: Windows' general resolver falls back to NetBIOS/LLMNR when an
    // address has no PTR record and takes ~4.5 s to give up, which starved the lookup queue.
    [Fact, Trait("Category", "Network")]
    public async Task Address_without_reverse_name_fails_fast()
    {
        var resolver = new HostNameResolver();
        var watch = System.Diagnostics.Stopwatch.StartNew();

        var name = await resolver.ResolveAsync(IPAddress.Parse("203.0.113.77")); // TEST-NET-3, no PTR

        Assert.Null(name);
        Assert.True(watch.ElapsedMilliseconds < 2000, $"took {watch.ElapsedMilliseconds} ms");
    }

    [Fact, Trait("Category", "Network")]
    public async Task Public_address_resolves_to_its_reverse_name()
    {
        var resolver = new HostNameResolver();

        Assert.Equal("dns.google", await resolver.ResolveAsync(IPAddress.Parse("8.8.8.8")));
        Assert.Equal("dns.google", await resolver.ResolveAsync(IPAddress.Parse("2001:4860:4860::8888")));
    }

    [Fact]
    public async Task Failed_lookup_is_cached_as_no_name()
    {
        var calls = 0;
        var resolver = new HostNameResolver((_, _) =>
        {
            Interlocked.Increment(ref calls);
            throw new System.Net.Sockets.SocketException();
        });
        var ip = IPAddress.Parse("203.0.113.5");

        Assert.Null(await resolver.ResolveAsync(ip));
        Assert.Null(await resolver.ResolveAsync(ip));
        Assert.Equal(1, calls);
    }
}
