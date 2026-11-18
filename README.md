# NetProfiler

A real-time network profiler for Windows 10/11. It shows which applications are talking to which
IP addresses, how fast, and how much. It can also block or unblock any remote IP with a click.

## Features

- **Live throughput chart** of download and upload over the last 2 minutes. Hover it for exact values.
- **Connections**: every TCP connection and UDP flow, with the owning application, remote IP, port
  (with the service name), reverse-DNS host name, TCP state, live rate and running total.
- **Applications**: bandwidth per process.
- **Remote hosts**: bandwidth per remote IP, plus the applications using it.
- **Block / Unblock** from any row or the right-click menu, or type an IP or CIDR range
  (`203.0.113.0/24`) on the **Blocked IPs** tab.
- **Filter** every table by app, IP, host or port. **Pause** freezes the view while capture continues.
  **Export CSV** saves the connections table.
- **Activity** log of what was blocked or unblocked, and when.

## How it works

| Piece | Source |
|---|---|
| Per-app bytes in/out | Windows kernel network events (ETW, `NetworkTCPIP`) via Microsoft's TraceEvent library |
| Open TCP connections and owners | `GetExtendedTcpTable` (IP Helper API) |
| Blocking | Windows Firewall rules created through the built-in `HNetCfg.FwPolicy2` COM API |
| Host names | DNS-only PTR lookups (`DnsQuery`, without the slow NetBIOS fallback) |

No drivers or packet-capture software are installed.

### About blocking

- Each block adds two Windows Firewall rules: `NetProfiler Block <ip> (In)` and `(Out)`, in the group
  **NetProfiler**. You can also see them in *Windows Defender Firewall with Advanced Security*.
- **Blocks stay in place after NetProfiler closes**, until you unblock them. They're shown again the
  next time you start the app.
- Blocking only affects traffic to and from this PC. To block an IP for every device on your network,
  block it on your router.
- For safety, the app refuses loopback, "any" (`0.0.0.0`, `::`), broadcast, and ranges wider than `/8`. It also
  warns before blocking your router, a DNS server, or this PC's own address.
- Blocks only take effect while Windows Firewall is on. The app warns you if it's off.

## Requirements

- Windows 10 or 11, x64
- [.NET 10 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/10.0) (to build: .NET 10 SDK)
- **Administrator rights** for live per-app bandwidth and for blocking. The app asks via UAC when it starts.
  Without admin it runs in *limited mode*: connections are still listed and total throughput still comes from
  the adapter counters.

## Build and run

```powershell
dotnet test                                    # 92 tests (2 need internet DNS: --filter "Category!=Network" skips them)
dotnet publish src/NetProfiler -c Release -o publish
.\publish\NetProfiler.exe                      # or double-click it; Windows shows a UAC prompt
```

`dotnet run` can't start the app, because the executable requires elevation. Run the built `.exe` instead.

For development without UAC prompts, build with `-p:RunAsInvoker=true` (limited mode).
`NetProfiler.exe --screenshot out.png --after 8 --tab 0` renders the window off-screen to a PNG and exits.

## Project layout

```
src/NetProfiler.Core/   capture, aggregation, firewall, DNS, TCP table  (no UI; unit-tested)
src/NetProfiler/        WPF app: MainWindow, view models, live chart, dark theme
tests/NetProfiler.Tests xUnit tests for the core
```
