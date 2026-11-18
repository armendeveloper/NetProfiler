using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace NetProfiler.Core;

/// <summary>
/// A single IP address or CIDR range that can be blocked. Parsing refuses targets that would
/// cut this PC off from itself or from most of the internet.
/// </summary>
public sealed class BlockTarget : IEquatable<BlockTarget>
{
    private const int MinimumPrefix = 8;

    private BlockTarget(IPAddress network, int prefixLength)
    {
        Network = network;
        PrefixLength = prefixLength;
    }

    public IPAddress Network { get; }

    public int PrefixLength { get; }

    public bool IsSingleAddress => PrefixLength == MaxPrefix(Network);

    public static bool TryParse(string? input, [NotNullWhen(true)] out BlockTarget? target, out string error)
    {
        target = null;
        var text = input?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            error = "Enter an IP address or range, for example 203.0.113.7 or 203.0.113.0/24.";
            return false;
        }

        var addressText = text;
        int? prefix = null;
        var slash = text.IndexOf('/');
        if (slash >= 0)
        {
            addressText = text[..slash];
            var prefixText = text[(slash + 1)..];
            if (!int.TryParse(prefixText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPrefix))
            {
                error = $"'{prefixText}' is not a valid prefix length.";
                return false;
            }
            prefix = parsedPrefix;
        }

        if (!IPAddress.TryParse(addressText, out var address) || !LooksComplete(addressText, address))
        {
            error = $"'{addressText}' is not a valid IP address.";
            return false;
        }

        if (address.IsIPv4MappedToIPv6 && prefix is not null)
        {
            if (prefix < 96)
            {
                error = "Prefix is too short for an IPv4-mapped address.";
                return false;
            }
            prefix -= 96;
        }
        address = AddressNormalizer.Normalize(address);

        var max = MaxPrefix(address);
        var length = prefix ?? max;
        if (length < 0 || length > max)
        {
            error = $"Prefix length must be between {MinimumPrefix} and {max}.";
            return false;
        }

        var network = Mask(address, length);
        if (length < MinimumPrefix)
        {
            error = $"Ranges wider than /{MinimumPrefix} are refused because they would block a large part of the internet.";
            return false;
        }
        if (IPAddress.IsLoopback(network))
        {
            error = "Loopback addresses are how programs on this PC talk to each other, so they can't be blocked.";
            return false;
        }
        if (network.Equals(IPAddress.Any) || network.Equals(IPAddress.IPv6Any))
        {
            error = "This address means 'any address', so blocking it would cut off all traffic.";
            return false;
        }
        if (network.Equals(IPAddress.Broadcast))
        {
            error = "The broadcast address can't be blocked.";
            return false;
        }

        target = new BlockTarget(network, length);
        error = string.Empty;
        return true;
    }

    public bool Contains(IPAddress address)
    {
        var candidate = AddressNormalizer.Normalize(address);
        if (candidate.AddressFamily != Network.AddressFamily)
            return false;
        return Mask(candidate, PrefixLength).Equals(Network);
    }

    public override string ToString() => IsSingleAddress ? Network.ToString() : $"{Network}/{PrefixLength}";

    public bool Equals(BlockTarget? other) =>
        other is not null && PrefixLength == other.PrefixLength && Network.Equals(other.Network);

    public override bool Equals(object? obj) => obj is BlockTarget other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Network, PrefixLength);

    private static int MaxPrefix(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

    // IPAddress.TryParse accepts shorthand ("10.1") and reads zero-padded parts as octal ("010" = 8), so
    // IPv4 must be exactly four plain decimal parts or the user could block a different host than they typed.
    private static bool LooksComplete(string text, IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return true;
        var parts = text.Split('.');
        return parts.Length == 4 && parts.All(part =>
            part.Length is >= 1 and <= 3 && part.All(char.IsAsciiDigit) && (part.Length == 1 || part[0] != '0'));
    }

    private static IPAddress Mask(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitsInByte = Math.Clamp(prefixLength - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - bitsInByte));
        }
        return new IPAddress(bytes);
    }
}
