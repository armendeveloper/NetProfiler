using System.Net;
using System.Runtime.InteropServices;

namespace NetProfiler.Core;

/// <summary>Reads the OS TCP connection table (IPv4 + IPv6) with owning process ids. Works without admin rights.</summary>
public static class ConnectionTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;
    private const int Ipv4RowSize = 24;
    private const int Ipv6RowSize = 56;

    public static IReadOnlyList<ConnectionEntry> GetTcpConnections()
    {
        var entries = new List<ConnectionEntry>(256);
        ReadTable(AfInet, Ipv4RowSize, ReadIpv4Row, entries);
        ReadTable(AfInet6, Ipv6RowSize, ReadIpv6Row, entries);
        return entries;
    }

    private static void ReadTable(int family, int rowSize, Func<IntPtr, ConnectionEntry> readRow, List<ConnectionEntry> into)
    {
        var size = 0;
        var buffer = IntPtr.Zero;
        try
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                var result = GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0);
                if (result == 0)
                    break;
                if (result != ErrorInsufficientBuffer)
                    return;
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
                size += 4096; // the table may grow between calls
                buffer = Marshal.AllocHGlobal(size);
            }
            if (buffer == IntPtr.Zero)
                return;

            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
                into.Add(readRow(buffer + 4 + i * rowSize));
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }
    }

    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
    private static ConnectionEntry ReadIpv4Row(IntPtr row)
    {
        var state = Marshal.ReadInt32(row, 0);
        var local = new IPAddress((uint)Marshal.ReadInt32(row, 4));
        var localPort = Port(Marshal.ReadInt32(row, 8));
        var remote = new IPAddress((uint)Marshal.ReadInt32(row, 12));
        var remotePort = Port(Marshal.ReadInt32(row, 16));
        var pid = Marshal.ReadInt32(row, 20);
        return Entry(local, localPort, remote, remotePort, pid, state);
    }

    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
    private static ConnectionEntry ReadIpv6Row(IntPtr row)
    {
        var local = new IPAddress(ReadBytes(row, 0, 16));
        var localPort = Port(Marshal.ReadInt32(row, 20));
        var remote = new IPAddress(ReadBytes(row, 24, 16));
        var remotePort = Port(Marshal.ReadInt32(row, 44));
        var state = Marshal.ReadInt32(row, 48);
        var pid = Marshal.ReadInt32(row, 52);
        return Entry(local, localPort, remote, remotePort, pid, state);
    }

    private static ConnectionEntry Entry(IPAddress local, int localPort, IPAddress remote, int remotePort, int pid, int state) =>
        new(new FlowKey(NetProtocol.Tcp, AddressNormalizer.Normalize(local), localPort,
                AddressNormalizer.Normalize(remote), remotePort),
            pid, StateName(state));

    private static byte[] ReadBytes(IntPtr row, int offset, int length)
    {
        var bytes = new byte[length];
        Marshal.Copy(row + offset, bytes, 0, length);
        return bytes;
    }

    // Ports are stored in network byte order in the low 16 bits.
    private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    private static string StateName(int state) => state switch
    {
        1 => "Closed",
        2 => "Listening",
        3 => "SYN sent",
        4 => "SYN received",
        5 => "Established",
        6 => "FIN wait 1",
        7 => "FIN wait 2",
        8 => "Close wait",
        9 => "Closing",
        10 => "Last ACK",
        11 => "Time wait",
        12 => "Delete TCB",
        _ => "Unknown",
    };

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
}
