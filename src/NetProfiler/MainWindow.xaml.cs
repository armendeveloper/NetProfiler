using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using NetProfiler.ViewModels;

namespace NetProfiler;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;
        Icon = RenderIcon();
        SourceInitialized += (_, _) => DarkTitleBar.Apply(this);
        Loaded += (_, _) => _viewModel.Start();
        Closed += (_, _) => _viewModel.Dispose();
    }

    /// <summary>
    /// Development aid: render the window to a PNG after a delay, then exit. The window is placed
    /// off-screen so it does not interrupt whoever is using the PC.
    /// </summary>
    public void CaptureScreenshotAndExit(string path, TimeSpan delay, int tabIndex)
    {
        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = SystemParameters.VirtualScreenLeft - Width - 200;
        Top = 0;
        ShowActivated = false;
        ShowInTaskbar = false;

        Loaded += (_, _) =>
        {
            var timer = new DispatcherTimer { Interval = delay };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                Tabs.SelectedIndex = tabIndex;
                Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, () =>
                {
                    SavePng(Root, path);
                    Application.Current.Shutdown();
                });
            };
            timer.Start();
        };
    }

    private static void SavePng(FrameworkElement element, string path)
    {
        const double scale = 1.5;
        var bitmap = new RenderTargetBitmap(
            (int)(element.ActualWidth * scale), (int)(element.ActualHeight * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        bitmap.Render(element);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    /// <summary>Draws the app icon (the same two traffic lines as the header logo) at runtime.</summary>
    private static ImageSource RenderIcon()
    {
        const int size = 64;
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromRgb(0x12, 0x18, 0x20)), null, new Rect(0, 0, size, size), 14, 14);
            var down = new Pen(new SolidColorBrush(Color.FromRgb(0x3D, 0xA9, 0xFC)), 6) { LineJoin = PenLineJoin.Round, StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            var up = new Pen(new SolidColorBrush(Color.FromRgb(0xFF, 0x9F, 0x43)), 4.5) { LineJoin = PenLineJoin.Round, StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            dc.DrawGeometry(null, down, Geometry.Parse("M 10,38 L 22,24 L 31,31 L 43,15 L 54,22"));
            dc.DrawGeometry(null, up, Geometry.Parse("M 10,50 L 22,43 L 31,46 L 43,37 L 54,41"));
        }
        var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        bitmap.Freeze();
        return bitmap;
    }
}
