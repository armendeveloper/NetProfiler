using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace NetProfiler.Core;

public static class ByteFormat
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB", "PB"];

    public static string Size(long bytes) => Format(bytes, string.Empty);

    public static string Rate(double bytesPerSecond) => Format(bytesPerSecond, "/s");

    private static string Format(double value, string suffix)
    {
        value = Math.Max(0, value);
        if (value < 1024)
            return Math.Round(value).ToString("0", CultureInfo.InvariantCulture) + " B" + suffix;

        var unit = 0;
        while (value >= 1024 && unit < Units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return value.ToString("0.0", CultureInfo.InvariantCulture) + " " + Units[unit] + suffix;
    }
}

/// <summary>Fixed-size history of throughput samples for the live chart.</summary>
public sealed class RateHistory
{
    private readonly RatePoint[] _buffer;
    private int _start;
    private int _count;

    public RateHistory(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _buffer = new RatePoint[capacity];
    }

    public int Capacity => _buffer.Length;

    public IReadOnlyList<RatePoint> Points
    {
        get
        {
            var points = new RatePoint[_count];
            for (var i = 0; i < _count; i++)
                points[i] = _buffer[(_start + i) % _buffer.Length];
            return points;
        }
    }

    public double Peak
    {
        get
        {
            double peak = 0;
            foreach (var point in Points)
                peak = Math.Max(peak, Math.Max(point.In, point.Out));
            return peak;
        }
    }

    public void Add(double inRate, double outRate)
    {
        var point = new RatePoint(inRate, outRate);
        if (_count < _buffer.Length)
        {
            _buffer[(_start + _count) % _buffer.Length] = point;
            _count++;
        }
        else
        {
            _buffer[_start] = point;
            _start = (_start + 1) % _buffer.Length;
        }
    }
}

/// <summary>Firewall rules created by this app are recognised by name, so the blocked list survives restarts.</summary>
public static class FirewallRuleNames
{
    public const string Group = "NetProfiler";
    private const string Prefix = "NetProfiler Block ";
    private const string InSuffix = " (In)";
    private const string OutSuffix = " (Out)";

    public static string For(BlockTarget target, FirewallDirection direction) =>
        Prefix + target + (direction == FirewallDirection.Inbound ? InSuffix : OutSuffix);

    public static bool TryParse(string name, [NotNullWhen(true)] out BlockTarget? target, out FirewallDirection direction)
    {
        target = null;
        direction = FirewallDirection.Inbound;
        if (!name.StartsWith(Prefix, StringComparison.Ordinal))
            return false;

        var rest = name[Prefix.Length..];
        string core;
        if (rest.EndsWith(InSuffix, StringComparison.Ordinal))
        {
            core = rest[..^InSuffix.Length];
        }
        else if (rest.EndsWith(OutSuffix, StringComparison.Ordinal))
        {
            core = rest[..^OutSuffix.Length];
            direction = FirewallDirection.Outbound;
        }
        else
        {
            return false;
        }
        return BlockTarget.TryParse(core, out target, out _);
    }
}

/// <summary>Reverse-DNS lookups with a cache, one lookup per address and at most four at a time.</summary>
public sealed class HostNameResolver
{
    private readonly Func<IPAddress, CancellationToken, Task<string?>> _lookup;
    private readonly ConcurrentDictionary<IPAddress, Lazy<Task<string?>>> _cache = new();
    private readonly SemaphoreSlim _throttle = new(4);

    public HostNameResolver() : this(ReverseDnsAsync)
    {
    }

    public HostNameResolver(Func<IPAddress, CancellationToken, Task<string?>> lookup) => _lookup = lookup;

    public Task<string?> ResolveAsync(IPAddress address) =>
        _cache.GetOrAdd(address, ip => new Lazy<Task<string?>>(() => LookupAsync(ip))).Value;

    public bool TryGetCached(IPAddress address, out string? name)
    {
        if (_cache.TryGetValue(address, out var entry) && entry.IsValueCreated && entry.Value.IsCompletedSuccessfully)
        {
            name = entry.Value.Result;
            return true;
        }
        name = null;
        return false;
    }

    private async Task<string?> LookupAsync(IPAddress address)
    {
        await _throttle.WaitAsync().ConfigureAwait(false);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var name = await _lookup(address, timeout.Token).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(name) || name == address.ToString() ? null : name;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            _throttle.Release();
        }
    }

    // Dns.GetHostEntry falls back to NetBIOS/LLMNR when there is no PTR record and needs ~4.5 s to give up.
    // Most internet addresses have no PTR, so ask DNS only: a missing name then fails in milliseconds.
    private static Task<string?> ReverseDnsAsync(IPAddress address, CancellationToken cancellationToken) =>
        Task.Run(() => QueryPtrRecord(address), cancellationToken);

    private static string? QueryPtrRecord(IPAddress address)
    {
        const ushort TypePtr = 12;
        const uint NoMulticast = 0x00000800;
        const uint NoNetBios = 0x00080000;
        const int FreeRecordList = 1;

        if (DnsQuery(ReverseLookupName(address), TypePtr, NoMulticast | NoNetBios, IntPtr.Zero, out var records, IntPtr.Zero) != 0
            || records == IntPtr.Zero)
            return null;
        try
        {
            // DNS_RECORD: pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved, then Data (PTR: pNameHost).
            var typeOffset = 2 * IntPtr.Size;
            var dataOffset = 2 * IntPtr.Size + 16;
            for (var record = records; record != IntPtr.Zero; record = Marshal.ReadIntPtr(record))
            {
                if ((ushort)Marshal.ReadInt16(record, typeOffset) == TypePtr)
                    return Marshal.PtrToStringUni(Marshal.ReadIntPtr(record, dataOffset));
            }
            return null;
        }
        finally
        {
            DnsRecordListFree(records, FreeRecordList);
        }
    }

    private static string ReverseLookupName(IPAddress address)
    {
        var bytes = AddressNormalizer.Normalize(address).GetAddressBytes();
        if (bytes.Length == 4)
            return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";

        var nibbles = new StringBuilder(72);
        for (var i = bytes.Length - 1; i >= 0; i--)
            nibbles.Append(HexDigit(bytes[i] & 0xF)).Append('.').Append(HexDigit(bytes[i] >> 4)).Append('.');
        return nibbles.Append("ip6.arpa").ToString();
    }

    private static char HexDigit(int value) => (char)(value < 10 ? '0' + value : 'a' + value - 10);

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode)]
    private static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll")]
    private static extern void DnsRecordListFree(IntPtr records, int freeType);
}

/// <summary>Total bytes across all real network adapters; used for the chart when live capture is unavailable.</summary>
public static class AdapterCounters
{
    public static (long Received, long Sent) Sample()
    {
        long received = 0, sent = 0;
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;
            try
            {
                var stats = adapter.GetIPStatistics();
                received += stats.BytesReceived;
                sent += stats.BytesSent;
            }
            catch (NetworkInformationException)
            {
                // Adapter vanished between enumeration and query.
            }
        }
        return (received, sent);
    }
}
