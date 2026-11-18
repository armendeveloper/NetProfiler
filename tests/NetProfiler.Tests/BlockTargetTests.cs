using System.Net;
using NetProfiler.Core;

namespace NetProfiler.Tests;

public class BlockTargetTests
{
    [Theory]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData("  1.2.3.4  ", "1.2.3.4")]
    [InlineData("2001:4860:4860::8888", "2001:4860:4860::8888")]
    [InlineData("10.0.0.0/24", "10.0.0.0/24")]
    [InlineData("10.0.0.77/24", "10.0.0.0/24")]
    [InlineData("::ffff:93.184.216.34", "93.184.216.34")]
    [InlineData("203.0.113.9/32", "203.0.113.9")]
    [InlineData("2001:db8:abcd::/48", "2001:db8:abcd::/48")]
    public void Parses_valid_targets_to_normalized_form(string input, string expected)
    {
        Assert.True(BlockTarget.TryParse(input, out var target, out var error), error);
        Assert.Equal(expected, target!.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/abc")]
    [InlineData("2001:db8::/129")]
    [InlineData("1.2.3.4/")]
    // .NET reads zero-padded parts as octal (192.168.001.010 -> 192.168.1.8), which would block the wrong host.
    [InlineData("192.168.001.010")]
    [InlineData("010.0.0.1")]
    [InlineData("1.2.3.04/32")]
    public void Rejects_malformed_input(string? input)
    {
        Assert.False(BlockTarget.TryParse(input, out var target, out var error));
        Assert.Null(target);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.5.5.5")]
    [InlineData("127.0.0.0/8")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("0.0.0.0/0")]
    [InlineData("10.0.0.0/7")]
    [InlineData("255.255.255.255")]
    public void Rejects_targets_that_would_cut_off_the_machine_itself(string input)
    {
        Assert.False(BlockTarget.TryParse(input, out var target, out var error));
        Assert.Null(target);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void Cidr_target_contains_only_addresses_inside_its_range()
    {
        BlockTarget.TryParse("192.168.4.0/22", out var target, out _);

        Assert.True(target!.Contains(IPAddress.Parse("192.168.4.1")));
        Assert.True(target.Contains(IPAddress.Parse("192.168.7.254")));
        Assert.False(target.Contains(IPAddress.Parse("192.168.8.1")));
        Assert.False(target.Contains(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Single_address_target_matches_itself_including_ipv4_mapped_form()
    {
        BlockTarget.TryParse("93.184.216.34", out var target, out _);

        Assert.True(target!.Contains(IPAddress.Parse("93.184.216.34")));
        Assert.True(target.Contains(IPAddress.Parse("::ffff:93.184.216.34")));
        Assert.False(target.Contains(IPAddress.Parse("93.184.216.35")));
    }

    [Fact]
    public void Targets_with_same_normalized_form_are_equal()
    {
        BlockTarget.TryParse("10.0.0.77/24", out var a, out _);
        BlockTarget.TryParse("10.0.0.0/24", out var b, out _);

        Assert.Equal(a, b);
        Assert.Equal(a!.GetHashCode(), b!.GetHashCode());
    }
}
