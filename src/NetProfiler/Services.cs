using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Interop;
using NetProfiler.Core;

namespace NetProfiler;

internal static class Elevation
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool TryRestartElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--restarted")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            return true;
        }
        catch (Win32Exception)
        {
            return false; // user declined the UAC prompt
        }
    }
}

internal static class NetworkInfo
{
    /// <summary>Explains why blocking this target could break the user's own connectivity, or null if it looks safe.</summary>
    public static string? DescribeRisk(BlockTarget target)
    {
        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up)
                    continue;
                var properties = adapter.GetIPProperties();
                foreach (var gateway in properties.GatewayAddresses)
                {
                    if (!AddressNormalizer.IsUnspecified(gateway.Address) && target.Contains(gateway.Address))
                        return $"{gateway.Address} is your router (default gateway). Blocking it can break DNS and access to your router's settings page.";
                }
                foreach (var dns in properties.DnsAddresses)
                {
                    if (target.Contains(dns))
                        return $"{dns} is one of your DNS servers. Blocking it stops websites from loading by name unless another DNS server is configured.";
                }
                foreach (var own in properties.UnicastAddresses)
                {
                    if (target.Contains(own.Address))
                        return $"This range includes this PC's own address ({own.Address}).";
                }
            }
        }
        catch (NetworkInformationException)
        {
            // Can't check; the confirmation dialog still applies.
        }
        return null;
    }
}

internal static class DarkTitleBar
{
    private const int UseImmersiveDarkMode = 20;
    private const int CaptionColor = 35;

    public static void Apply(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        var enabled = 1;
        DwmSetWindowAttribute(handle, UseImmersiveDarkMode, ref enabled, sizeof(int));
        var color = 0x00140F0B; // COLORREF (0x00BBGGRR) of the window background #0B0F14
        DwmSetWindowAttribute(handle, CaptionColor, ref color, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
