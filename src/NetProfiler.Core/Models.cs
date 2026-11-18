using System.Net;

namespace NetProfiler.Core;

public enum NetProtocol { Tcp, Udp }

public enum TrafficDirection { In, Out }

public enum FirewallDirection { Inbound, Outbound }

/// <summary>Identifies one conversation between a local socket and a remote endpoint.</summary>
public readonly record struct FlowKey(
    NetProtocol Protocol,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort);

/// <summary>One row of the OS TCP table.</summary>
public sealed record ConnectionEntry(FlowKey Key, int Pid, string State);

public sealed record FlowSnapshot(
    FlowKey Key,
    int Pid,
    string State,
    double InRate,
    double OutRate,
    long TotalIn,
    long TotalOut,
    DateTime LastActivity);

public sealed record ProcessSnapshot(
    int Pid,
    double InRate,
    double OutRate,
    long TotalIn,
    long TotalOut,
    int FlowCount);

public sealed record RemoteSnapshot(
    IPAddress Address,
    double InRate,
    double OutRate,
    long TotalIn,
    long TotalOut,
    int FlowCount,
    IReadOnlyList<int> Pids);

public sealed record TrafficSnapshot(
    DateTime Time,
    double InRate,
    double OutRate,
    long TotalIn,
    long TotalOut,
    IReadOnlyList<FlowSnapshot> Flows,
    IReadOnlyList<ProcessSnapshot> Processes,
    IReadOnlyList<RemoteSnapshot> Remotes);

public sealed record ProcessInfo(int Pid, string Name, string? Path);

public sealed record BlockedRule(BlockTarget Target, bool Inbound, bool Outbound, string? Description);

public sealed record FirewallState(IReadOnlyList<string> ActiveProfiles, bool EnabledOnAllActiveProfiles);

public readonly record struct RatePoint(double In, double Out);
