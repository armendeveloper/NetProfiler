using System.Net;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetProfiler.Core;

/// <summary>
/// Live per-process TCP/UDP byte counts from the Windows kernel's network trace events (ETW).
/// Needs administrator rights. Every send/receive is oriented to local/remote and fed to the aggregator.
/// </summary>
public sealed class EtwTrafficSource : IDisposable
{
    private const string SessionName = "NetProfiler-Network";

    private readonly TrafficAggregator _aggregator;
    private readonly LocalAddressSet _localAddresses;
    private TraceEventSession? _session;
    private Thread? _thread;

    public EtwTrafficSource(TrafficAggregator aggregator, LocalAddressSet localAddresses)
    {
        _aggregator = aggregator;
        _localAddresses = localAddresses;
    }

    public bool IsRunning => _session is not null;

    /// <summary>Raised on the capture thread if the trace session ends unexpectedly.</summary>
    public event Action<string>? Stopped;

    public bool TryStart(out string error)
    {
        if (IsRunning)
        {
            error = string.Empty;
            return true;
        }
        if (TraceEventSession.IsElevated() != true)
        {
            error = "Live per-app bandwidth needs administrator rights.";
            return false;
        }

        try
        {
            _session = OpenSession();
        }
        catch (Exception ex)
        {
            error = $"Could not start the kernel network trace: {ex.Message}";
            return false;
        }

        var kernel = _session.Source.Kernel;
        kernel.TcpIpRecv += d => Add(NetProtocol.Tcp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.In);
        kernel.TcpIpSend += d => Add(NetProtocol.Tcp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.Out);
        kernel.TcpIpRecvIPV6 += d => Add(NetProtocol.Tcp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.In);
        kernel.TcpIpSendIPV6 += d => Add(NetProtocol.Tcp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.Out);
        kernel.UdpIpRecv += d => Add(NetProtocol.Udp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.In);
        kernel.UdpIpSend += d => Add(NetProtocol.Udp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.Out);
        kernel.UdpIpRecvIPV6 += d => Add(NetProtocol.Udp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.In);
        kernel.UdpIpSendIPV6 += d => Add(NetProtocol.Udp, d.ProcessID, d.saddr, d.sport, d.daddr, d.dport, d.size, TrafficDirection.Out);

        var session = _session;
        _thread = new Thread(() =>
        {
            try
            {
                session.Source.Process();
            }
            catch (Exception ex)
            {
                Stopped?.Invoke(ex.Message);
                return;
            }
            if (ReferenceEquals(_session, session))
                Stopped?.Invoke("The kernel network trace stopped.");
        })
        {
            IsBackground = true,
            Name = "NetProfiler ETW capture",
        };
        _thread.Start();

        error = string.Empty;
        return true;
    }

    /// <summary>Pushes buffered kernel events to the capture thread so quiet traffic isn't held back.</summary>
    public void Flush()
    {
        try
        {
            _session?.Flush();
        }
        catch (Exception)
        {
            // Session is stopping; the Stopped event reports it.
        }
    }

    public void Dispose()
    {
        var session = _session;
        _session = null;
        session?.Dispose();
    }

    private static TraceEventSession OpenSession()
    {
        // Windows 8+ allows private-named kernel sessions, which avoids fighting other tools for
        // the single "NT Kernel Logger". Restarting our own name is fine (leftover from a crash).
        try
        {
            return Enable(new TraceEventSession(SessionName, TraceEventSessionOptions.Create));
        }
        catch (Exception privateError)
        {
            // Only borrow "NT Kernel Logger" if nobody else is using it: NoRestartOnCreate makes this
            // fail instead of silently stopping another tool's trace (WPR, xperf, security software).
            try
            {
                return Enable(new TraceEventSession(KernelTraceEventParser.KernelSessionName,
                    TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate));
            }
            catch (Exception)
            {
                throw new InvalidOperationException(privateError.Message, privateError);
            }
        }
    }

    private static TraceEventSession Enable(TraceEventSession session)
    {
        try
        {
            session.StopOnDispose = true;
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    private void Add(NetProtocol protocol, int pid, IPAddress saddr, int sport, IPAddress daddr, int dport, int size, TrafficDirection direction)
    {
        var (local, remote) = FlowOrientation.Orient(saddr, sport, daddr, dport, _localAddresses.Contains);
        var key = new FlowKey(protocol, local.Address, local.Port, remote.Address, remote.Port);
        _aggregator.Record(key, pid, direction, size);
    }
}
