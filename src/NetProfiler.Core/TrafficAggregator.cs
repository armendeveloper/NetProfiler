using System.Net;

namespace NetProfiler.Core;

/// <summary>
/// Collects byte counts from the capture thread and turns them into per-connection,
/// per-application and per-remote-host rates on each <see cref="Tick"/>.
/// Connections are dropped once idle for <c>idleTimeout</c>; applications and hosts are kept
/// (with their totals) for the longer <c>retention</c> so the lists don't grow forever.
/// </summary>
public sealed class TrafficAggregator
{
    private readonly object _gate = new();
    private readonly TimeSpan _idleTimeout;
    private readonly TimeSpan _retention;
    private readonly Dictionary<FlowKey, FlowState> _flows = new();
    private readonly Dictionary<int, AggregateState> _processes = new();
    private readonly Dictionary<IPAddress, RemoteState> _remotes = new();
    private readonly Counter _total = new();
    private DateTime _lastTick;

    public TrafficAggregator(DateTime start, TimeSpan idleTimeout, TimeSpan? retention = null)
    {
        _lastTick = start;
        _idleTimeout = idleTimeout;
        _retention = retention ?? TimeSpan.FromMinutes(10);
    }

    /// <summary>Loopback traffic is local inter-process chatter, not network use, so it is hidden by default.</summary>
    public bool IncludeLoopback { get; set; }

    public void Record(FlowKey key, int pid, TrafficDirection direction, long bytes)
    {
        if (bytes <= 0 || IsHidden(key.RemoteAddress))
            return;

        lock (_gate)
        {
            var flow = GetFlow(key);
            if (pid > 0)
                flow.Pid = pid;
            flow.Counter.Add(direction, bytes);
            GetProcess(flow.Pid).Counter.Add(direction, bytes);
            var remote = GetRemote(key.RemoteAddress);
            remote.Counter.Add(direction, bytes);
            remote.MarkPid(flow.Pid);
            _total.Add(direction, bytes);
        }
    }

    public void ApplyConnectionTable(IReadOnlyList<ConnectionEntry> entries)
    {
        lock (_gate)
        {
            foreach (var flow in _flows.Values)
                flow.InTable = false;

            foreach (var entry in entries)
            {
                var remote = entry.Key.RemoteAddress;
                if (AddressNormalizer.IsUnspecified(remote) || IsHidden(remote))
                    continue;

                var flow = GetFlow(entry.Key);
                if (entry.Pid > 0)
                    flow.Pid = entry.Pid;
                flow.State = entry.State;
                flow.InTable = true;
                flow.SeenInTable = true;
                GetRemote(remote).MarkPid(flow.Pid);
            }

            foreach (var (key, flow) in _flows)
            {
                if (key.Protocol == NetProtocol.Tcp && flow.SeenInTable && !flow.InTable)
                    flow.State = "Closed";
            }
        }
    }

    public TrafficSnapshot Tick(DateTime now)
    {
        lock (_gate)
        {
            var elapsed = (now - _lastTick).TotalSeconds;
            _lastTick = now;

            var flows = new List<FlowSnapshot>(_flows.Count);
            var flowsPerPid = new Dictionary<int, int>();
            var flowsPerRemote = new Dictionary<IPAddress, int>();
            var expiredFlows = new List<FlowKey>();

            foreach (var (key, flow) in _flows)
            {
                var (inRate, outRate, moved) = flow.Counter.TakeRates(elapsed);
                if (moved || flow.InTable)
                    flow.LastActivity = now;
                if (!flow.InTable && now - flow.LastActivity > _idleTimeout)
                {
                    expiredFlows.Add(key);
                    continue;
                }

                flows.Add(new FlowSnapshot(key, flow.Pid, flow.State, inRate, outRate,
                    flow.Counter.In, flow.Counter.Out, flow.LastActivity));
                flowsPerPid[flow.Pid] = flowsPerPid.GetValueOrDefault(flow.Pid) + 1;
                flowsPerRemote[key.RemoteAddress] = flowsPerRemote.GetValueOrDefault(key.RemoteAddress) + 1;
                GetRemote(key.RemoteAddress).MarkPid(flow.Pid);
            }
            foreach (var key in expiredFlows)
                _flows.Remove(key);

            foreach (var pid in flowsPerPid.Keys)
                GetProcess(pid);
            var processes = new List<ProcessSnapshot>(_processes.Count);
            var expiredProcesses = new List<int>();
            foreach (var (pid, process) in _processes)
            {
                var count = flowsPerPid.GetValueOrDefault(pid);
                var (inRate, outRate, keep) = process.Advance(now, elapsed, count, _retention);
                if (!keep)
                {
                    expiredProcesses.Add(pid);
                    continue;
                }
                if (process.Counter.In + process.Counter.Out > 0 || count > 0)
                    processes.Add(new ProcessSnapshot(pid, inRate, outRate, process.Counter.In, process.Counter.Out, count));
            }
            foreach (var pid in expiredProcesses)
                _processes.Remove(pid);

            var remotes = new List<RemoteSnapshot>(_remotes.Count);
            var expiredRemotes = new List<IPAddress>();
            foreach (var (address, remote) in _remotes)
            {
                var count = flowsPerRemote.GetValueOrDefault(address);
                var (inRate, outRate, keep) = remote.Advance(now, elapsed, count, _retention);
                var pids = remote.SettlePids(now, _retention);
                if (!keep)
                {
                    expiredRemotes.Add(address);
                    continue;
                }
                if (remote.Counter.In + remote.Counter.Out > 0 || count > 0)
                    remotes.Add(new RemoteSnapshot(address, inRate, outRate, remote.Counter.In, remote.Counter.Out, count, pids));
            }
            foreach (var address in expiredRemotes)
                _remotes.Remove(address);

            var (totalIn, totalOut, _) = _total.TakeRates(elapsed);
            return new TrafficSnapshot(now, totalIn, totalOut, _total.In, _total.Out, flows, processes, remotes);
        }
    }

    private bool IsHidden(IPAddress remote) => !IncludeLoopback && IPAddress.IsLoopback(remote);

    private FlowState GetFlow(FlowKey key)
    {
        if (!_flows.TryGetValue(key, out var flow))
        {
            flow = new FlowState { LastActivity = _lastTick, State = string.Empty };
            _flows[key] = flow;
        }
        return flow;
    }

    private AggregateState GetProcess(int pid)
    {
        if (!_processes.TryGetValue(pid, out var process))
        {
            process = new AggregateState { LastActivity = _lastTick };
            _processes[pid] = process;
        }
        return process;
    }

    private RemoteState GetRemote(IPAddress address)
    {
        if (!_remotes.TryGetValue(address, out var remote))
        {
            remote = new RemoteState { LastActivity = _lastTick };
            _remotes[address] = remote;
        }
        return remote;
    }

    private sealed class Counter
    {
        private long _previousIn;
        private long _previousOut;

        public long In { get; private set; }
        public long Out { get; private set; }

        public void Add(TrafficDirection direction, long bytes)
        {
            if (direction == TrafficDirection.In)
                In += bytes;
            else
                Out += bytes;
        }

        public (double In, double Out, bool Moved) TakeRates(double elapsedSeconds)
        {
            var deltaIn = In - _previousIn;
            var deltaOut = Out - _previousOut;
            _previousIn = In;
            _previousOut = Out;
            if (elapsedSeconds <= 0)
                return (0, 0, deltaIn + deltaOut > 0);
            return (deltaIn / elapsedSeconds, deltaOut / elapsedSeconds, deltaIn + deltaOut > 0);
        }
    }

    private sealed class FlowState
    {
        public Counter Counter { get; } = new();
        public int Pid { get; set; }
        public required string State { get; set; }
        public bool InTable { get; set; }
        public bool SeenInTable { get; set; }
        public DateTime LastActivity { get; set; }
    }

    /// <summary>Totals for an application or remote host, kept while active or recently active.</summary>
    private class AggregateState
    {
        public Counter Counter { get; } = new();
        public DateTime LastActivity { get; set; }

        public (double In, double Out, bool Keep) Advance(DateTime now, double elapsed, int liveFlows, TimeSpan retention)
        {
            var (inRate, outRate, moved) = Counter.TakeRates(elapsed);
            if (moved || liveFlows > 0)
                LastActivity = now;
            return (inRate, outRate, liveFlows > 0 || now - LastActivity <= retention);
        }
    }

    private sealed class RemoteState : AggregateState
    {
        private readonly HashSet<int> _seenSinceTick = [];
        private readonly Dictionary<int, DateTime> _pidLastSeen = new();

        public void MarkPid(int pid)
        {
            if (pid > 0)
                _seenSinceTick.Add(pid);
        }

        /// <summary>Processes that used this host within the retention window (a reused PID ages out).</summary>
        public IReadOnlyList<int> SettlePids(DateTime now, TimeSpan retention)
        {
            foreach (var pid in _seenSinceTick)
                _pidLastSeen[pid] = now;
            _seenSinceTick.Clear();
            foreach (var stale in _pidLastSeen.Where(p => now - p.Value > retention).Select(p => p.Key).ToList())
                _pidLastSeen.Remove(stale);
            return _pidLastSeen.Keys.ToArray();
        }
    }
}
