using System.Globalization;
using System.Windows;
using System.Windows.Threading;

namespace NetProfiler;

public partial class App : Application
{
    private const string MutexName = @"Local\NetProfiler.SingleInstance";
    private Mutex? _singleInstance;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;

        var args = e.Args;
        var screenshotPath = ValueAfter(args, "--screenshot");

        // Two instances would fight over the same kernel trace session, so only one runs at a time
        // (screenshot runs included). A restart-as-admin waits briefly for the old instance to close.
        if (!AcquireSingleInstance(args.Contains("--restarted") ? TimeSpan.FromSeconds(10) : TimeSpan.Zero))
        {
            if (screenshotPath is null)
                MessageBox.Show("NetProfiler is already running.", "NetProfiler", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(screenshotPath is null ? 0 : 2);
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        if (screenshotPath is not null)
        {
            var seconds = double.TryParse(ValueAfter(args, "--after"), NumberStyles.Float, CultureInfo.InvariantCulture, out var s) ? s : 6;
            var tab = int.TryParse(ValueAfter(args, "--tab"), out var t) ? t : 0;
            window.CaptureScreenshotAndExit(screenshotPath, TimeSpan.FromSeconds(seconds), tab);
        }
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _singleInstance?.ReleaseMutex();
        }
        catch (ApplicationException)
        {
            // Not owned by this thread; nothing to release.
        }
        _singleInstance?.Dispose();
        base.OnExit(e);
    }

    private bool AcquireSingleInstance(TimeSpan wait)
    {
        _singleInstance = new Mutex(false, MutexName);
        try
        {
            return _singleInstance.WaitOne(wait);
        }
        catch (AbandonedMutexException)
        {
            return true; // previous instance crashed; we own it now
        }
    }

    private static string? ValueAfter(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // A monitoring tool should keep running; report the problem instead of crashing.
        e.Handled = true;
        MessageBox.Show(MainWindow!, e.Exception.Message, "NetProfiler error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
