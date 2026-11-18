using NetProfiler.Core;

namespace NetProfiler.Tests;

public class PortNamesTests
{
    [Theory]
    [InlineData(443, "443 · https")]
    [InlineData(53, "53 · dns")]
    [InlineData(3389, "3389 · rdp")]
    public void Well_known_ports_get_their_service_name(int port, string expected)
    {
        Assert.Equal(expected, PortNames.Describe(port));
    }

    [Fact]
    public void Unknown_port_is_just_the_number()
    {
        Assert.Equal("50123", PortNames.Describe(50123));
    }

    [Fact]
    public void Port_zero_means_no_port()
    {
        Assert.Equal("—", PortNames.Describe(0));
    }
}
