using System.Net;
using NetProfiler.Core;

namespace NetProfiler.Tests;

public class TrafficAggregatorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Idle = TimeSpan.FromSeconds(30);

    private static FlowKey Tcp(string remote, int remotePort = 443, int localPort = 50000) =>
        new(NetProtocol.Tcp, IPAddress.Parse("192.168.1.10"), localPort, IPAddress.Parse(remote), remotePort);

    [Fact]
    public void Rate_is_bytes_since_last_tick_divided_by_elapsed_seconds()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var key = Tcp("1.1.1.1");

        agg.Record(key, 100, TrafficDirection.In, 3000);
        agg.Record(key, 100, TrafficDirection.Out, 1000);
        var snap = agg.Tick(T0.AddSeconds(2));

        var flow = Assert.Single(snap.Flows);
        Assert.Equal(1500, flow.InRate);
        Assert.Equal(500, flow.OutRate);
        Assert.Equal(3000, flow.TotalIn);
        Assert.Equal(1000, flow.TotalOut);
        Assert.Equal(100, flow.Pid);
        Assert.Equal(1500, snap.InRate);
        Assert.Equal(500, snap.OutRate);
    }

    [Fact]
    public void Rate_drops_to_zero_without_new_traffic_while_totals_remain()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var key = Tcp("1.1.1.1");
        agg.Record(key, 100, TrafficDirection.In, 3000);
        agg.Tick(T0.AddSeconds(1));

        var snap = agg.Tick(T0.AddSeconds(2));

        var flow = Assert.Single(snap.Flows);
        Assert.Equal(0, flow.InRate);
        Assert.Equal(3000, flow.TotalIn);
        Assert.Equal(3000, snap.TotalIn);
    }

    [Fact]
    public void Application_view_sums_every_flow_of_the_same_process()
    {
        var agg = new TrafficAggregator(T0, Idle);
        agg.Record(Tcp("1.1.1.1"), 100, TrafficDirection.In, 1000);
        agg.Record(Tcp("8.8.8.8", localPort: 50001), 100, TrafficDirection.In, 3000);
        agg.Record(Tcp("9.9.9.9", localPort: 50002), 200, TrafficDirection.Out, 500);

        var snap = agg.Tick(T0.AddSeconds(1));

        var p100 = Assert.Single(snap.Processes, p => p.Pid == 100);
        Assert.Equal(4000, p100.InRate);
        Assert.Equal(4000, p100.TotalIn);
        Assert.Equal(2, p100.FlowCount);
        var p200 = Assert.Single(snap.Processes, p => p.Pid == 200);
        Assert.Equal(500, p200.TotalOut);
    }

    [Fact]
    public void Remote_view_sums_traffic_per_remote_address_across_processes()
    {
        var agg = new TrafficAggregator(T0, Idle);
        agg.Record(Tcp("1.1.1.1", localPort: 50000), 100, TrafficDirection.In, 1000);
        agg.Record(Tcp("1.1.1.1", localPort: 50001), 200, TrafficDirection.In, 2000);

        var snap = agg.Tick(T0.AddSeconds(1));

        var remote = Assert.Single(snap.Remotes);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), remote.Address);
        Assert.Equal(3000, remote.TotalIn);
        Assert.Equal(2, remote.FlowCount);
        Assert.Equal(new[] { 100, 200 }, remote.Pids.OrderBy(p => p));
    }

    [Fact]
    public void Idle_flows_are_dropped_after_timeout_but_their_bytes_stay_in_totals()
    {
        var agg = new TrafficAggregator(T0, Idle);
        agg.Record(Tcp("1.1.1.1"), 100, TrafficDirection.In, 3000);
        Assert.Single(agg.Tick(T0.AddSeconds(1)).Flows);

        var snap = agg.Tick(T0.AddSeconds(40));

        Assert.Empty(snap.Flows);
        Assert.Equal(3000, Assert.Single(snap.Processes).TotalIn);
        Assert.Equal(3000, Assert.Single(snap.Remotes).TotalIn);
        Assert.Equal(3000, snap.TotalIn);
    }

    [Fact]
    public void Idle_applications_and_hosts_are_forgotten_after_the_retention_period()
    {
        var agg = new TrafficAggregator(T0, Idle, retention: TimeSpan.FromMinutes(10));
        agg.Record(Tcp("1.1.1.1"), 100, TrafficDirection.In, 3000);
        agg.Tick(T0.AddSeconds(1));

        var stillRemembered = agg.Tick(T0.AddMinutes(5));
        var forgotten = agg.Tick(T0.AddMinutes(11));

        Assert.Single(stillRemembered.Processes);
        Assert.Single(stillRemembered.Remotes);
        Assert.Empty(forgotten.Processes);
        Assert.Empty(forgotten.Remotes);
        Assert.Equal(3000, forgotten.TotalIn);
    }

    [Fact]
    public void Remote_host_stops_listing_a_process_that_no_longer_uses_it()
    {
        var agg = new TrafficAggregator(T0, Idle, retention: TimeSpan.FromMinutes(10));
        agg.Record(Tcp("1.1.1.1", localPort: 50000), 100, TrafficDirection.In, 10);
        agg.Tick(T0.AddSeconds(1));
        agg.Tick(T0.AddMinutes(6));

        agg.Record(Tcp("1.1.1.1", localPort: 50001), 200, TrafficDirection.In, 10);
        var snap = agg.Tick(T0.AddMinutes(11));

        Assert.Equal(new[] { 200 }, Assert.Single(snap.Remotes).Pids);
    }

    [Fact]
    public void Open_connections_from_the_table_are_kept_with_their_state_even_when_idle()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var key = Tcp("1.1.1.1");
        agg.ApplyConnectionTable([new ConnectionEntry(key, 200, "Established")]);

        var snap = agg.Tick(T0.AddSeconds(100));

        var flow = Assert.Single(snap.Flows);
        Assert.Equal("Established", flow.State);
        Assert.Equal(200, flow.Pid);
        Assert.Equal(0, flow.InRate);
    }

    [Fact]
    public void Tcp_flow_that_leaves_the_table_is_marked_closed_then_dropped_once_idle()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var key = Tcp("1.1.1.1");
        agg.ApplyConnectionTable([new ConnectionEntry(key, 200, "Established")]);
        agg.Tick(T0.AddSeconds(100));

        agg.ApplyConnectionTable([]);
        var justClosed = agg.Tick(T0.AddSeconds(101));
        var later = agg.Tick(T0.AddSeconds(200));

        Assert.Equal("Closed", Assert.Single(justClosed.Flows).State);
        Assert.Empty(later.Flows);
    }

    [Fact]
    public void Connection_table_supplies_the_process_when_traffic_event_has_none()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var key = Tcp("1.1.1.1");
        agg.ApplyConnectionTable([new ConnectionEntry(key, 300, "Established")]);
        agg.Record(key, 0, TrafficDirection.In, 100);

        var snap = agg.Tick(T0.AddSeconds(1));

        Assert.Equal(300, Assert.Single(snap.Flows).Pid);
        Assert.Equal(100, Assert.Single(snap.Processes, p => p.Pid == 300).TotalIn);
    }

    [Fact]
    public void Listening_sockets_in_the_table_are_not_shown_as_flows()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var listener = new FlowKey(NetProtocol.Tcp, IPAddress.Any, 445, IPAddress.Any, 0);
        agg.ApplyConnectionTable([new ConnectionEntry(listener, 4, "Listening")]);

        var snap = agg.Tick(T0.AddSeconds(1));

        Assert.Empty(snap.Flows);
        Assert.Empty(snap.Remotes);
    }

    [Fact]
    public void Loopback_traffic_is_ignored_unless_enabled()
    {
        var loop = new FlowKey(NetProtocol.Tcp, IPAddress.Loopback, 5000, IPAddress.Loopback, 6000);
        var agg = new TrafficAggregator(T0, Idle);
        agg.Record(loop, 100, TrafficDirection.In, 999);
        Assert.Empty(agg.Tick(T0.AddSeconds(1)).Flows);

        agg.IncludeLoopback = true;
        agg.Record(loop, 100, TrafficDirection.In, 999);
        Assert.Single(agg.Tick(T0.AddSeconds(2)).Flows);
    }

    [Fact]
    public void Zero_elapsed_time_reports_zero_rate_instead_of_infinity()
    {
        var agg = new TrafficAggregator(T0, Idle);
        agg.Record(Tcp("1.1.1.1"), 100, TrafficDirection.In, 3000);

        var snap = agg.Tick(T0);

        Assert.Equal(0, snap.InRate);
        Assert.Equal(3000, snap.TotalIn);
    }

    [Fact]
    public void Recording_from_many_threads_loses_no_bytes()
    {
        var agg = new TrafficAggregator(T0, Idle);
        var key = Tcp("1.1.1.1");

        Parallel.For(0, 10_000, _ => agg.Record(key, 100, TrafficDirection.In, 10));
        var snap = agg.Tick(T0.AddSeconds(1));

        Assert.Equal(100_000, snap.TotalIn);
    }
}
