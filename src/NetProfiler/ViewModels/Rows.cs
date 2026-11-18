using System.Net;
using System.Net.Sockets;
using NetProfiler.Core;

namespace NetProfiler.ViewModels;

/// <summary>A row that refers to a remote address, so it can be blocked from a button or menu.</summary>
public interface IRemoteRow
{
    IPAddress RemoteAddress { get; }
    string? HostName { get; }
    string AppNames { get; }
}

public interface ISearchable
{
    string SearchText { get; }
}

/// <summary>Shared rate/total columns; text is pre-formatted so the grid never formats on scroll.</summary>
public abstract class TrafficRow : ObservableObject, ISearchable
{
    private double _inRate, _outRate, _activity;
    private long _totalIn, _totalOut, _totalBytes;
    private string _inRateText = "", _outRateText = "", _totalInText = "", _totalOutText = "";
    private bool _inActive, _outActive;
    private string _searchText = "";

    public double InRate { get => _inRate; private set => Set(ref _inRate, value); }
    public double OutRate { get => _outRate; private set => Set(ref _outRate, value); }
    public double Activity { get => _activity; private set => Set(ref _activity, value); }
    public long TotalIn { get => _totalIn; private set => Set(ref _totalIn, value); }
    public long TotalOut { get => _totalOut; private set => Set(ref _totalOut, value); }
    public long TotalBytes { get => _totalBytes; private set => Set(ref _totalBytes, value); }
    public string InRateText { get => _inRateText; private set => Set(ref _inRateText, value); }
    public string OutRateText { get => _outRateText; private set => Set(ref _outRateText, value); }
    public string TotalInText { get => _totalInText; private set => Set(ref _totalInText, value); }
    public string TotalOutText { get => _totalOutText; private set => Set(ref _totalOutText, value); }
    public bool InActive { get => _inActive; private set => Set(ref _inActive, value); }
    public bool OutActive { get => _outActive; private set => Set(ref _outActive, value); }
    public string SearchText { get => _searchText; protected set => Set(ref _searchText, value); }

    protected void UpdateTraffic(double inRate, double outRate, long totalIn, long totalOut, bool capturing)
    {
        InRate = inRate;
        OutRate = outRate;
        Activity = inRate + outRate;
        TotalIn = totalIn;
        TotalOut = totalOut;
        TotalBytes = totalIn + totalOut;
        InRateText = capturing ? ByteFormat.Rate(inRate) : "—";
        OutRateText = capturing ? ByteFormat.Rate(outRate) : "—";
        TotalInText = capturing ? ByteFormat.Size(totalIn) : "";
        TotalOutText = capturing ? ByteFormat.Size(totalOut) : "";
        InActive = capturing && inRate >= 1;
        OutActive = capturing && outRate >= 1;
    }
}

public sealed class ConnectionRow : TrafficRow, IRemoteRow
{
    private string _processName = "";
    private int _pid;
    private string? _processPath;
    private string? _hostName;
    private string _state = "";
    private bool _isBlocked;

    public ConnectionRow(FlowKey key)
    {
        Key = key;
        Protocol = key.Protocol == NetProtocol.Tcp ? "TCP" : "UDP";
        Local = Endpoint(key.LocalAddress, key.LocalPort);
        Remote = key.RemoteAddress.ToString();
        RemotePortText = PortNames.Describe(key.RemotePort);
    }

    public FlowKey Key { get; }
    public IPAddress RemoteAddress => Key.RemoteAddress;
    public string Protocol { get; }
    public string Local { get; }
    public string Remote { get; }
    public int RemotePort => Key.RemotePort;
    public string RemotePortText { get; }

    public string ProcessName { get => _processName; private set => Set(ref _processName, value); }
    public int Pid { get => _pid; private set => Set(ref _pid, value); }
    public string? ProcessPath { get => _processPath; private set => Set(ref _processPath, value); }
    public string? HostName { get => _hostName; private set => Set(ref _hostName, value); }
    public string State { get => _state; private set => Set(ref _state, value); }
    public bool IsBlocked { get => _isBlocked; private set => Set(ref _isBlocked, value); }
    public string AppNames => ProcessName;

    public void Update(FlowSnapshot flow, ProcessInfo process, string? hostName, bool isBlocked, bool capturing)
    {
        ProcessName = process.Name;
        Pid = flow.Pid;
        ProcessPath = process.Path;
        HostName = hostName;
        State = string.IsNullOrEmpty(flow.State) ? "—" : flow.State;
        IsBlocked = isBlocked;
        UpdateTraffic(flow.InRate, flow.OutRate, flow.TotalIn, flow.TotalOut, capturing);
        SearchText = $"{ProcessName} {Pid} {Protocol} {Remote} {RemotePortText} {HostName} {Local} {State}";
    }

    internal static string Endpoint(IPAddress address, int port) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";
}

public sealed class AppRow : TrafficRow
{
    private string _name = "";
    private string? _path;
    private int _connections;

    public AppRow(int pid) => Pid = pid;

    public int Pid { get; }
    public string Name { get => _name; private set => Set(ref _name, value); }
    public string? Path { get => _path; private set => Set(ref _path, value); }
    public int Connections { get => _connections; private set => Set(ref _connections, value); }

    public void Update(ProcessSnapshot snapshot, ProcessInfo process, bool capturing)
    {
        Name = process.Name;
        Path = process.Path;
        Connections = snapshot.FlowCount;
        UpdateTraffic(snapshot.InRate, snapshot.OutRate, snapshot.TotalIn, snapshot.TotalOut, capturing);
        SearchText = $"{Name} {Pid} {Path}";
    }
}

public sealed class HostRow : TrafficRow, IRemoteRow
{
    private string? _hostName;
    private string _appNames = "";
    private int _connections;
    private bool _isBlocked;

    public HostRow(IPAddress address)
    {
        RemoteAddress = address;
        Address = address.ToString();
    }

    public IPAddress RemoteAddress { get; }
    public string Address { get; }
    public string? HostName { get => _hostName; private set => Set(ref _hostName, value); }
    public string AppNames { get => _appNames; private set => Set(ref _appNames, value); }
    public int Connections { get => _connections; private set => Set(ref _connections, value); }
    public bool IsBlocked { get => _isBlocked; private set => Set(ref _isBlocked, value); }

    public void Update(RemoteSnapshot snapshot, string? hostName, string appNames, bool isBlocked, bool capturing)
    {
        HostName = hostName;
        AppNames = appNames;
        Connections = snapshot.FlowCount;
        IsBlocked = isBlocked;
        UpdateTraffic(snapshot.InRate, snapshot.OutRate, snapshot.TotalIn, snapshot.TotalOut, capturing);
        SearchText = $"{Address} {HostName} {AppNames}";
    }
}

public sealed class BlockedRow : ObservableObject
{
    private string? _hostName;

    public BlockedRow(BlockedRule rule)
    {
        Target = rule.Target;
        TargetText = rule.Target.ToString();
        Directions = (rule.Inbound, rule.Outbound) switch
        {
            (true, true) => "Inbound + outbound",
            (true, false) => "Inbound only",
            (false, true) => "Outbound only",
            _ => "—",
        };
        Added = rule.Description?.Replace("Blocked by NetProfiler on ", "", StringComparison.Ordinal) ?? "";
    }

    public BlockTarget Target { get; }
    public string TargetText { get; }
    public string Directions { get; }
    public string Added { get; }
    public string? HostName { get => _hostName; set => Set(ref _hostName, value); }
}

public enum LogLevel { Info, Success, Warning, Error }

public sealed record LogEntry(string Time, string Message, LogLevel Level);
