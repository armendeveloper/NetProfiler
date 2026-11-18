using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using NetProfiler.Core;

namespace NetProfiler.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    public const int HistorySeconds = 120;
    private static readonly TimeSpan FirewallRefreshInterval = TimeSpan.FromSeconds(30);
    private const int MaxLogEntries = 500;

    private readonly TrafficAggregator _aggregator;
    private readonly LocalAddressSet _localAddresses = new();
    private readonly EtwTrafficSource _capture;
    private readonly WindowsFirewall _firewall = new();
    private readonly ProcessResolver _processes = new();
    private readonly HostNameResolver _hostNames = new();
    private readonly DispatcherTimer _timer;
    private readonly RateHistory _history = new(HistorySeconds);
    private readonly Dictionary<FlowKey, ConnectionRow> _connectionRows = new();
    private readonly Dictionary<int, AppRow> _appRows = new();
    private readonly Dictionary<IPAddress, HostRow> _hostRows = new();

    private IReadOnlyList<BlockTarget> _blockedTargets = [];
    private (long Received, long Sent) _adapterBaseline;
    private (long Received, long Sent) _lastAdapterSample;
    private DateTime _lastSampleTime;
    private DateTime _lastFirewallRefresh = DateTime.MinValue;
    private bool _firewallRefreshRunning;
    private bool _disposed;
    private double _peakDown, _peakUp;

    private bool _isCapturing, _isElevated, _isPaused, _includeLoopback, _resolveHostNames = true;
    private string _captureStatus = "Starting…", _captureError = "", _captureDetail = "";
    private string _downRateText = "0 B/s", _upRateText = "0 B/s", _peakDownText = "0 B/s", _peakUpText = "0 B/s";
    private string _totalDownText = "0 B", _totalUpText = "0 B", _totalsCaption = "";
    private int _connectionCount, _appCount, _hostCount, _blockedCount;
    private IReadOnlyList<RatePoint> _chartPoints = [];
    private string _filterText = "", _blockInput = "", _blockError = "";
    private string _firewallStatus = "Checking Windows Firewall…", _firewallWarning = "";

    public MainViewModel()
    {
        _aggregator = new TrafficAggregator(DateTime.UtcNow, TimeSpan.FromSeconds(30));
        _capture = new EtwTrafficSource(_aggregator, _localAddresses);
        _capture.Stopped += message => Application.Current?.Dispatcher.BeginInvoke(() => OnCaptureStopped(message));

        ConnectionsView = CreateView(Connections, (nameof(TrafficRow.Activity), ListSortDirection.Descending),
            (nameof(TrafficRow.TotalBytes), ListSortDirection.Descending));
        AppsView = CreateView(Apps, (nameof(TrafficRow.Activity), ListSortDirection.Descending),
            (nameof(TrafficRow.TotalBytes), ListSortDirection.Descending));
        HostsView = CreateView(Hosts, (nameof(TrafficRow.Activity), ListSortDirection.Descending),
            (nameof(TrafficRow.TotalBytes), ListSortDirection.Descending));

        TogglePauseCommand = new RelayCommand(_ => IsPaused = !IsPaused);
        ToggleBlockCommand = new RelayCommand(p => Run(() => ToggleBlockAsync(p as IRemoteRow)), p => p is IRemoteRow);
        BlockManualCommand = new RelayCommand(_ => Run(BlockManualAsync));
        UnblockCommand = new RelayCommand(p => Run(() => UnblockAsync(p as BlockedRow)), p => p is BlockedRow);
        UnblockAllCommand = new RelayCommand(_ => Run(UnblockAllAsync), _ => Blocked.Count > 0);
        ExportCommand = new RelayCommand(_ => Export());
        RestartAsAdminCommand = new RelayCommand(_ => RestartAsAdmin());
        CopyCommand = new RelayCommand(p => Copy(p as string), p => !string.IsNullOrEmpty(p as string));
        FilterToAppCommand = new RelayCommand(p => FilterText = p switch
        {
            ConnectionRow c => c.ProcessName,
            AppRow a => a.Name,
            _ => FilterText,
        });
        ClearFilterCommand = new RelayCommand(_ => FilterText = "");
        OpenLocationCommand = new RelayCommand(p => OpenLocation(p as string), p => File.Exists(p as string));

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
    }

    public ObservableCollection<ConnectionRow> Connections { get; } = [];
    public ObservableCollection<AppRow> Apps { get; } = [];
    public ObservableCollection<HostRow> Hosts { get; } = [];
    public ObservableCollection<BlockedRow> Blocked { get; } = [];
    public ObservableCollection<LogEntry> Log { get; } = [];
    public ListCollectionView ConnectionsView { get; }
    public ListCollectionView AppsView { get; }
    public ListCollectionView HostsView { get; }

    public ICommand TogglePauseCommand { get; }
    public ICommand ToggleBlockCommand { get; }
    public ICommand BlockManualCommand { get; }
    public ICommand UnblockCommand { get; }
    public ICommand UnblockAllCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand RestartAsAdminCommand { get; }
    public ICommand CopyCommand { get; }
    public ICommand FilterToAppCommand { get; }
    public ICommand ClearFilterCommand { get; }
    public ICommand OpenLocationCommand { get; }

    public bool IsCapturing
    {
        get => _isCapturing;
        private set
        {
            if (Set(ref _isCapturing, value))
                OnPropertyChanged(nameof(ShowCaptureBanner));
        }
    }

    public bool IsElevated
    {
        get => _isElevated;
        private set
        {
            if (Set(ref _isElevated, value))
                OnPropertyChanged(nameof(ShowRestartButton));
        }
    }

    public bool ShowCaptureBanner => !IsCapturing;
    public bool ShowRestartButton => !IsElevated;
    public string CaptureStatus { get => _captureStatus; private set => Set(ref _captureStatus, value); }
    public string CaptureError { get => _captureError; private set => Set(ref _captureError, value); }
    public string CaptureDetail { get => _captureDetail; private set => Set(ref _captureDetail, value); }
    public string DownRateText { get => _downRateText; private set => Set(ref _downRateText, value); }
    public string UpRateText { get => _upRateText; private set => Set(ref _upRateText, value); }
    public string PeakDownText { get => _peakDownText; private set => Set(ref _peakDownText, value); }
    public string PeakUpText { get => _peakUpText; private set => Set(ref _peakUpText, value); }
    public string TotalDownText { get => _totalDownText; private set => Set(ref _totalDownText, value); }
    public string TotalUpText { get => _totalUpText; private set => Set(ref _totalUpText, value); }
    public string TotalsCaption { get => _totalsCaption; private set => Set(ref _totalsCaption, value); }
    public int ConnectionCount { get => _connectionCount; private set => Set(ref _connectionCount, value); }
    public int AppCount { get => _appCount; private set => Set(ref _appCount, value); }
    public int HostCount { get => _hostCount; private set => Set(ref _hostCount, value); }
    public int BlockedCount { get => _blockedCount; private set => Set(ref _blockedCount, value); }
    public IReadOnlyList<RatePoint> ChartPoints { get => _chartPoints; private set => Set(ref _chartPoints, value); }
    public string FirewallStatus { get => _firewallStatus; private set => Set(ref _firewallStatus, value); }

    public string FirewallWarning
    {
        get => _firewallWarning;
        private set
        {
            if (Set(ref _firewallWarning, value))
                OnPropertyChanged(nameof(HasFirewallWarning));
        }
    }

    public bool HasFirewallWarning => FirewallWarning.Length > 0;

    public bool IsPaused
    {
        get => _isPaused;
        set
        {
            if (!Set(ref _isPaused, value))
                return;
            OnPropertyChanged(nameof(PauseButtonText));
            CaptureStatus = StatusText();
            AddLog(value ? "View paused. Capture continues in the background." : "View resumed.");
        }
    }

    public string PauseButtonText => IsPaused ? "Resume" : "Pause";

    public string FilterText
    {
        get => _filterText;
        set
        {
            if (!Set(ref _filterText, value ?? ""))
                return;
            ConnectionsView.Refresh();
            AppsView.Refresh();
            HostsView.Refresh();
        }
    }

    public bool IncludeLoopback
    {
        get => _includeLoopback;
        set
        {
            if (Set(ref _includeLoopback, value))
                _aggregator.IncludeLoopback = value;
        }
    }

    public bool ResolveHostNames { get => _resolveHostNames; set => Set(ref _resolveHostNames, value); }

    public string BlockInput { get => _blockInput; set => Set(ref _blockInput, value ?? ""); }

    public string BlockError
    {
        get => _blockError;
        private set
        {
            if (Set(ref _blockError, value))
                OnPropertyChanged(nameof(HasBlockError));
        }
    }

    public bool HasBlockError => BlockError.Length > 0;

    public void Start()
    {
        IsElevated = Elevation.IsElevated();
        if (_capture.TryStart(out var error))
        {
            IsCapturing = true;
            CaptureDetail = "Per-app bandwidth from Windows kernel network events (ETW)";
            AddLog("Live capture started.", LogLevel.Success);
        }
        else
        {
            CaptureError = error;
            CaptureDetail = "Throughput from network adapter counters · connections from the TCP table";
            AddLog(error, LogLevel.Warning);
        }
        CaptureStatus = StatusText();
        TotalsCaption = IsCapturing ? "since NetProfiler started" : "all adapters, since start";

        _lastAdapterSample = _adapterBaseline = AdapterCounters.Sample();
        _lastSampleTime = DateTime.UtcNow;
        Run(() => RefreshFirewallAsync());
        Tick();
        _timer.Start();
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _timer.Stop();
        _capture.Dispose();
        _localAddresses.Dispose();
    }

    private void Tick()
    {
        if (_disposed)
            return;

        if (IsCapturing)
            _capture.Flush();

        var now = DateTime.UtcNow;
        try
        {
            _aggregator.ApplyConnectionTable(ConnectionTable.GetTcpConnections());
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"TCP table read failed: {ex.Message}");
        }
        var snapshot = _aggregator.Tick(now);

        var adapters = AdapterCounters.Sample();
        double down, up;
        long totalDown, totalUp;
        if (IsCapturing)
        {
            (down, up, totalDown, totalUp) = (snapshot.InRate, snapshot.OutRate, snapshot.TotalIn, snapshot.TotalOut);
        }
        else
        {
            var seconds = (now - _lastSampleTime).TotalSeconds;
            down = seconds > 0 ? Math.Max(0, adapters.Received - _lastAdapterSample.Received) / seconds : 0;
            up = seconds > 0 ? Math.Max(0, adapters.Sent - _lastAdapterSample.Sent) / seconds : 0;
            totalDown = Math.Max(0, adapters.Received - _adapterBaseline.Received);
            totalUp = Math.Max(0, adapters.Sent - _adapterBaseline.Sent);
        }
        _lastAdapterSample = adapters;
        _lastSampleTime = now;

        _history.Add(down, up);
        ChartPoints = _history.Points;
        _peakDown = Math.Max(_peakDown, down);
        _peakUp = Math.Max(_peakUp, up);
        DownRateText = ByteFormat.Rate(down);
        UpRateText = ByteFormat.Rate(up);
        PeakDownText = ByteFormat.Rate(_peakDown);
        PeakUpText = ByteFormat.Rate(_peakUp);
        TotalDownText = ByteFormat.Size(totalDown);
        TotalUpText = ByteFormat.Size(totalUp);

        if (now - _lastFirewallRefresh > FirewallRefreshInterval)
            Run(() => RefreshFirewallAsync());

        if (IsPaused)
            return;

        SyncConnections(snapshot.Flows);
        SyncApps(snapshot.Processes);
        SyncHosts(snapshot.Remotes);
        ConnectionCount = snapshot.Flows.Count(f => f.State != "Closed");
        AppCount = Apps.Count;
        HostCount = Hosts.Count;
    }

    private void SyncConnections(IReadOnlyList<FlowSnapshot> flows) =>
        Sync(flows, f => f.Key, _connectionRows, Connections, f => new ConnectionRow(f.Key), (row, f) =>
            row.Update(f, ProcessFor(f.Pid), HostNameFor(f.Key.RemoteAddress), IsBlocked(f.Key.RemoteAddress), IsCapturing));

    private void SyncApps(IReadOnlyList<ProcessSnapshot> processes) =>
        Sync(processes, p => p.Pid, _appRows, Apps, p => new AppRow(p.Pid), (row, p) =>
            row.Update(p, ProcessFor(p.Pid), IsCapturing));

    // PID 0 in the TCP table means the socket has no owner any more (e.g. TIME_WAIT after the app closed it).
    private ProcessInfo ProcessFor(int pid) =>
        pid == 0 ? new ProcessInfo(0, "(no owner — closing)", null) : _processes.Get(pid);

    private void SyncHosts(IReadOnlyList<RemoteSnapshot> remotes) =>
        Sync(remotes, r => r.Address, _hostRows, Hosts, r => new HostRow(r.Address), (row, r) =>
            row.Update(r, HostNameFor(r.Address), AppNamesFor(r.Pids), IsBlocked(r.Address), IsCapturing));

    /// <summary>Updates rows in place (keeps selection and scroll position), adds new ones, removes gone ones.</summary>
    private static void Sync<TKey, TRow, TItem>(IEnumerable<TItem> items, Func<TItem, TKey> keyOf,
        Dictionary<TKey, TRow> rows, ObservableCollection<TRow> collection, Func<TItem, TRow> create, Action<TRow, TItem> update)
        where TKey : notnull
    {
        var seen = new HashSet<TKey>();
        foreach (var item in items)
        {
            var key = keyOf(item);
            seen.Add(key);
            if (rows.TryGetValue(key, out var row))
            {
                update(row, item);
                continue;
            }
            row = create(item);
            update(row, item);
            rows[key] = row;
            collection.Add(row);
        }

        foreach (var key in rows.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            collection.Remove(rows[key]);
            rows.Remove(key);
        }
    }

    private string? HostNameFor(IPAddress address)
    {
        if (!ResolveHostNames || IPAddress.IsLoopback(address))
            return null;
        if (_hostNames.TryGetCached(address, out var name))
            return name;
        _ = _hostNames.ResolveAsync(address); // picked up on a later tick
        return null;
    }

    private string AppNamesFor(IReadOnlyList<int> pids) => string.Join(", ",
        pids.Where(pid => pid > 0).Select(pid => _processes.Get(pid).Name).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase));

    private bool IsBlocked(IPAddress address) => _blockedTargets.Any(t => t.Contains(address));

    private async Task ToggleBlockAsync(IRemoteRow? row)
    {
        if (row is null)
            return;
        var address = row.RemoteAddress;

        var exact = _blockedTargets.FirstOrDefault(t => t.IsSingleAddress && t.Contains(address));
        if (exact is not null)
        {
            await UnblockTargetAsync(exact);
            return;
        }
        var range = _blockedTargets.FirstOrDefault(t => t.Contains(address));
        if (range is not null)
        {
            Inform($"{address} is inside the blocked range {range}. Unblock that range on the Blocked IPs tab.", "Already blocked");
            return;
        }
        if (!BlockTarget.TryParse(address.ToString(), out var target, out var error))
        {
            Inform(error, "Can't block this address");
            return;
        }
        await BlockTargetAsync(target, row.HostName, row.AppNames);
    }

    private async Task BlockManualAsync()
    {
        if (!BlockTarget.TryParse(BlockInput, out var target, out var error))
        {
            BlockError = error;
            return;
        }
        BlockError = "";
        if (_blockedTargets.Contains(target))
        {
            BlockError = $"{target} is already blocked.";
            return;
        }
        var hostName = target.IsSingleAddress ? HostNameFor(target.Network) : null;
        if (await BlockTargetAsync(target, hostName, null))
            BlockInput = "";
    }

    private async Task<bool> BlockTargetAsync(BlockTarget target, string? hostName, string? appNames)
    {
        if (!IsElevated)
        {
            if (Ask("Blocking an IP address adds Windows Firewall rules, which needs administrator rights.\n\nRestart NetProfiler as administrator now?",
                    "Administrator rights needed", MessageBoxImage.Information))
                RestartAsAdmin();
            return false;
        }

        var message = new StringBuilder($"Block all traffic to and from {target}");
        if (!string.IsNullOrEmpty(hostName))
            message.Append($" ({hostName})");
        message.Append("?\n\n");
        if (!string.IsNullOrEmpty(appNames))
            message.Append($"Currently used by: {appNames}\n\n");
        message.Append("NetProfiler will add an inbound and an outbound Windows Firewall rule. Open connections to this " +
                       "address will stop working. The block stays in place after NetProfiler closes, until you unblock it.");
        var risk = NetworkInfo.DescribeRisk(target);
        if (risk is not null)
            message.Append("\n\nWarning: ").Append(risk);

        if (!Ask(message.ToString(), "Block IP address", risk is null ? MessageBoxImage.Question : MessageBoxImage.Warning))
            return false;

        try
        {
            await Task.Run(() => _firewall.Block(target));
            AddLog($"Blocked {target}{(string.IsNullOrEmpty(hostName) ? "" : $" ({hostName})")}.", LogLevel.Warning);
        }
        catch (UnauthorizedAccessException)
        {
            AddLog($"Windows refused to add the firewall rule for {target}.", LogLevel.Error);
            Inform("Windows refused the firewall change. Make sure NetProfiler is running as administrator.", "Block failed");
            return false;
        }
        await RefreshFirewallAsync(force: true);
        return true;
    }

    private Task UnblockAsync(BlockedRow? row) => row is null ? Task.CompletedTask : UnblockTargetAsync(row.Target);

    private async Task UnblockTargetAsync(BlockTarget target)
    {
        if (!IsElevated)
        {
            if (Ask("Removing a firewall block needs administrator rights.\n\nRestart NetProfiler as administrator now?",
                    "Administrator rights needed", MessageBoxImage.Information))
                RestartAsAdmin();
            return;
        }
        try
        {
            await Task.Run(() => _firewall.Unblock(target));
            AddLog($"Unblocked {target}.", LogLevel.Success);
        }
        catch (UnauthorizedAccessException)
        {
            AddLog($"Windows refused to remove the firewall rule for {target}.", LogLevel.Error);
            Inform("Windows refused the firewall change. Make sure NetProfiler is running as administrator.", "Unblock failed");
        }
        await RefreshFirewallAsync(force: true);
    }

    private async Task UnblockAllAsync()
    {
        var targets = Blocked.Select(b => b.Target).ToList();
        if (targets.Count == 0 ||
            !Ask($"Remove all {targets.Count} NetProfiler block rule(s) from Windows Firewall?", "Unblock all", MessageBoxImage.Question))
            return;
        foreach (var target in targets)
            await UnblockTargetAsync(target);
    }

    private async Task RefreshFirewallAsync(bool force = false)
    {
        if (_firewallRefreshRunning && !force)
            return;
        _firewallRefreshRunning = true;
        _lastFirewallRefresh = DateTime.UtcNow;
        try
        {
            var (rules, state) = await Task.Run(() => (_firewall.GetBlocked(), _firewall.GetState()));
            _blockedTargets = rules.Select(r => r.Target).ToList();

            Blocked.Clear();
            foreach (var rule in rules)
            {
                Blocked.Add(new BlockedRow(rule)
                {
                    HostName = rule.Target.IsSingleAddress ? HostNameFor(rule.Target.Network) : null,
                });
            }
            BlockedCount = rules.Count;

            var profiles = string.Join(", ", state.ActiveProfiles);
            FirewallStatus = state.EnabledOnAllActiveProfiles
                ? $"Windows Firewall on ({profiles})"
                : $"Windows Firewall OFF ({profiles})";
            FirewallWarning = state.EnabledOnAllActiveProfiles
                ? ""
                : $"Windows Firewall is turned off for the active network profile ({profiles}). Blocks won't take effect until it is turned back on.";
        }
        catch (Exception ex)
        {
            FirewallStatus = "Windows Firewall unavailable";
            AddLog($"Could not read Windows Firewall: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            _firewallRefreshRunning = false;
        }
    }

    private void Export()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export connections",
            Filter = "CSV file (*.csv)|*.csv",
            FileName = $"netprofiler-connections-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };
        if (dialog.ShowDialog() != true)
            return;

        var csv = new StringBuilder();
        csv.Append("Application,PID,Path,Protocol,Local,Remote address,Remote port,Host name,State,")
           .Append("Download B/s,Upload B/s,Downloaded bytes,Uploaded bytes\r\n");
        var count = 0;
        foreach (ConnectionRow row in ConnectionsView)
        {
            csv.AppendJoin(',', new[]
            {
                row.ProcessName, row.Pid.ToString(), row.ProcessPath, row.Protocol, row.Local, row.Remote,
                row.RemotePort.ToString(), row.HostName, row.State, Math.Round(row.InRate).ToString(),
                Math.Round(row.OutRate).ToString(), row.TotalIn.ToString(), row.TotalOut.ToString(),
            }.Select(CsvField)).Append("\r\n");
            count++;
        }
        File.WriteAllText(dialog.FileName, csv.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        AddLog($"Exported {count} connection(s) to {dialog.FileName}.", LogLevel.Success);
    }

    // Host names come from reverse DNS, which anyone can set; neutralise spreadsheet formulas.
    private static string CsvField(string? value)
    {
        value ??= "";
        if (value.Length > 0 && "=+-@\t\r".Contains(value[0]))
            value = "'" + value;
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }

    private void RestartAsAdmin()
    {
        if (Elevation.TryRestartElevated())
            Application.Current.Shutdown();
        else
            AddLog("Restart as administrator was cancelled.", LogLevel.Warning);
    }

    private void Copy(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return;
        try
        {
            Clipboard.SetText(text);
        }
        catch (Exception ex)
        {
            AddLog($"Couldn't copy to the clipboard: {ex.Message}", LogLevel.Error);
        }
    }

    private static void OpenLocation(string? path)
    {
        if (File.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }

    private void OnCaptureStopped(string message)
    {
        if (_disposed)
            return;
        IsCapturing = false;
        CaptureError = $"Live capture stopped: {message}";
        CaptureStatus = StatusText();
        AddLog(CaptureError, LogLevel.Error);
    }

    private string StatusText() => IsPaused ? "Paused" : IsCapturing ? "Live capture" : "Limited mode";

    private ListCollectionView CreateView<T>(ObservableCollection<T> source, params (string Property, ListSortDirection Direction)[] sort)
    {
        var view = new ListCollectionView(source)
        {
            Filter = MatchesFilter,
            IsLiveSorting = true,
            IsLiveFiltering = true,
        };
        view.LiveFilteringProperties.Add(nameof(ISearchable.SearchText));
        foreach (var (property, direction) in sort)
            view.SortDescriptions.Add(new SortDescription(property, direction));
        return view;
    }

    private bool MatchesFilter(object item) =>
        _filterText.Length == 0 ||
        (item is ISearchable searchable && searchable.SearchText.Contains(_filterText.Trim(), StringComparison.OrdinalIgnoreCase));

    private void AddLog(string message, LogLevel level = LogLevel.Info)
    {
        Log.Insert(0, new LogEntry(DateTime.Now.ToString("HH:mm:ss"), message, level));
        while (Log.Count > MaxLogEntries)
            Log.RemoveAt(Log.Count - 1);
    }

    private async void Run(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            AddLog($"Error: {ex.Message}", LogLevel.Error);
            Inform(ex.Message, "Something went wrong");
        }
    }

    private static bool Ask(string message, string title, MessageBoxImage image) =>
        MessageBox.Show(Application.Current.MainWindow!, message, title, MessageBoxButton.YesNo, image, MessageBoxResult.No)
        == MessageBoxResult.Yes;

    private static void Inform(string message, string title) =>
        MessageBox.Show(Application.Current.MainWindow!, message, title, MessageBoxButton.OK, MessageBoxImage.Information);
}
