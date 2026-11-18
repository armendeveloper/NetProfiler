using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace NetProfiler.Core;

/// <summary>Maps process ids to names and executable paths, with a short cache because pids get reused.</summary>
public sealed class ProcessResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private readonly ConcurrentDictionary<int, (ProcessInfo Info, DateTime Expires)> _cache = new();

    public ProcessInfo Get(int pid)
    {
        switch (pid)
        {
            case 0: return new ProcessInfo(0, "System Idle Process", null);
            case 4: return new ProcessInfo(4, "System", null);
        }

        var now = DateTime.UtcNow;
        if (_cache.TryGetValue(pid, out var cached) && cached.Expires > now)
            return cached.Info;

        var info = Lookup(pid);
        _cache[pid] = (info, now.AddSeconds(info.Path is null ? 5 : 60));
        return info;
    }

    private static ProcessInfo Lookup(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return new ProcessInfo(pid, process.ProcessName, QueryImagePath(pid));
        }
        catch (ArgumentException)
        {
            return new ProcessInfo(pid, $"Exited process ({pid})", null);
        }
        catch (Exception)
        {
            return new ProcessInfo(pid, $"PID {pid}", null);
        }
    }

    private static string? QueryImagePath(int pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
            return null;
        try
        {
            var builder = new StringBuilder(1024);
            var size = builder.Capacity;
            return QueryFullProcessImageName(handle, 0, builder, ref size) ? builder.ToString() : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
