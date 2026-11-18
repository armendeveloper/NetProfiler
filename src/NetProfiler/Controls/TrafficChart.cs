using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using NetProfiler.Core;

namespace NetProfiler.Controls;

/// <summary>
/// Scrolling throughput chart: one point per second, newest on the right. Download is a filled area,
/// upload a lighter one on top. Hovering shows the exact values at that second.
/// </summary>
public sealed class TrafficChart : FrameworkElement
{
    private const double LeftGutter = 78;
    private const double RightGutter = 8;
    private const double TopGutter = 8;
    private const double BottomGutter = 22;

    public static readonly DependencyProperty PointsProperty = DependencyProperty.Register(
        nameof(Points), typeof(IReadOnlyList<RatePoint>), typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty CapacityProperty = DependencyProperty.Register(
        nameof(Capacity), typeof(int), typeof(TrafficChart),
        new FrameworkPropertyMetadata(120, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty DownBrushProperty = RegisterBrush(nameof(DownBrush), Brushes.DodgerBlue);
    public static readonly DependencyProperty UpBrushProperty = RegisterBrush(nameof(UpBrush), Brushes.Orange);
    public static readonly DependencyProperty GridBrushProperty = RegisterBrush(nameof(GridBrush), Brushes.DimGray);
    public static readonly DependencyProperty LabelBrushProperty = RegisterBrush(nameof(LabelBrush), Brushes.Gray);
    public static readonly DependencyProperty PanelBrushProperty = RegisterBrush(nameof(PanelBrush), Brushes.Black);
    public static readonly DependencyProperty TextBrushProperty = RegisterBrush(nameof(TextBrush), Brushes.White);

    private Point? _hover;

    public IReadOnlyList<RatePoint>? Points
    {
        get => (IReadOnlyList<RatePoint>?)GetValue(PointsProperty);
        set => SetValue(PointsProperty, value);
    }

    public int Capacity
    {
        get => (int)GetValue(CapacityProperty);
        set => SetValue(CapacityProperty, value);
    }

    public Brush DownBrush { get => (Brush)GetValue(DownBrushProperty); set => SetValue(DownBrushProperty, value); }
    public Brush UpBrush { get => (Brush)GetValue(UpBrushProperty); set => SetValue(UpBrushProperty, value); }
    public Brush GridBrush { get => (Brush)GetValue(GridBrushProperty); set => SetValue(GridBrushProperty, value); }
    public Brush LabelBrush { get => (Brush)GetValue(LabelBrushProperty); set => SetValue(LabelBrushProperty, value); }
    public Brush PanelBrush { get => (Brush)GetValue(PanelBrushProperty); set => SetValue(PanelBrushProperty, value); }
    public Brush TextBrush { get => (Brush)GetValue(TextBrushProperty); set => SetValue(TextBrushProperty, value); }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        _hover = e.GetPosition(this);
        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        _hover = null;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        // Transparent fill so the whole surface receives mouse events.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(RenderSize));

        var plot = new Rect(LeftGutter, TopGutter,
            Math.Max(0, ActualWidth - LeftGutter - RightGutter),
            Math.Max(0, ActualHeight - TopGutter - BottomGutter));
        if (plot.Width < 20 || plot.Height < 20)
            return;

        var points = Points ?? [];
        var capacity = Math.Max(2, Capacity);
        var step = plot.Width / (capacity - 1);
        var peak = points.Count == 0 ? 0 : points.Max(p => Math.Max(p.In, p.Out));
        var max = NiceMaximum(peak);
        var dip = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        DrawGrid(dc, plot, max, step, capacity, dip);

        dc.PushClip(new RectangleGeometry(plot));
        DrawSeries(dc, points, p => p.In, DownBrush, plot, max, step, 0.32);
        DrawSeries(dc, points, p => p.Out, UpBrush, plot, max, step, 0.18);
        dc.Pop();

        DrawHover(dc, points, plot, max, step, dip);
    }

    private void DrawGrid(DrawingContext dc, Rect plot, double max, double step, int capacity, double dip)
    {
        var gridPen = new Pen(GridBrush, 1);
        gridPen.Freeze();

        for (var i = 0; i <= 4; i++)
        {
            var y = Math.Round(plot.Bottom - plot.Height * i / 4) + 0.5;
            dc.DrawLine(gridPen, new Point(plot.Left, y), new Point(plot.Right, y));
            var label = Text(ByteFormat.Rate(max * i / 4), LabelBrush, 11, dip);
            dc.DrawText(label, new Point(plot.Left - 12 - label.Width, y - label.Height / 2));
        }

        var seconds = capacity - 1;
        for (var ago = 0; ago <= seconds; ago += 30)
        {
            var x = plot.Right - ago * step;
            var label = Text(ago == 0 ? "now" : FormatAgo(ago), LabelBrush, 11, dip);
            var left = Math.Clamp(x - label.Width / 2, plot.Left, plot.Right - label.Width);
            dc.DrawText(label, new Point(left, plot.Bottom + 5));
        }
    }

    private static void DrawSeries(DrawingContext dc, IReadOnlyList<RatePoint> points, Func<RatePoint, double> value,
        Brush brush, Rect plot, double max, double step, double fillOpacity)
    {
        if (points.Count < 2)
            return;

        Point At(int i) => new(
            plot.Right - (points.Count - 1 - i) * step,
            plot.Bottom - Math.Min(1, value(points[i]) / max) * plot.Height);

        var area = new StreamGeometry();
        using (var ctx = area.Open())
        {
            ctx.BeginFigure(new Point(At(0).X, plot.Bottom), true, true);
            for (var i = 0; i < points.Count; i++)
                ctx.LineTo(At(i), true, true);
            ctx.LineTo(new Point(At(points.Count - 1).X, plot.Bottom), true, true);
        }
        area.Freeze();

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(At(0), false, false);
            for (var i = 1; i < points.Count; i++)
                ctx.LineTo(At(i), true, true);
        }
        line.Freeze();

        var color = brush is SolidColorBrush solid ? solid.Color : Colors.White;
        var fill = new LinearGradientBrush(
            Color.FromArgb((byte)(255 * fillOpacity), color.R, color.G, color.B),
            Color.FromArgb(0, color.R, color.G, color.B), 90);
        fill.Freeze();
        var pen = new Pen(brush, 1.8) { LineJoin = PenLineJoin.Round };
        pen.Freeze();

        dc.DrawGeometry(fill, null, area);
        dc.DrawGeometry(null, pen, line);
    }

    private void DrawHover(DrawingContext dc, IReadOnlyList<RatePoint> points, Rect plot, double max, double step, double dip)
    {
        if (_hover is not { } mouse || points.Count == 0 || !plot.Contains(mouse))
            return;

        var firstX = plot.Right - (points.Count - 1) * step;
        var index = (int)Math.Round((mouse.X - firstX) / step);
        if (index < 0 || index >= points.Count)
            return;

        var point = points[index];
        var x = plot.Right - (points.Count - 1 - index) * step;
        var guide = new Pen(LabelBrush, 1) { DashStyle = DashStyles.Dash };
        guide.Freeze();
        dc.DrawLine(guide, new Point(x, plot.Top), new Point(x, plot.Bottom));
        dc.DrawEllipse(DownBrush, null, new Point(x, plot.Bottom - Math.Min(1, point.In / max) * plot.Height), 3.5, 3.5);
        dc.DrawEllipse(UpBrush, null, new Point(x, plot.Bottom - Math.Min(1, point.Out / max) * plot.Height), 3.5, 3.5);

        var ago = points.Count - 1 - index;
        var down = Text("↓ " + ByteFormat.Rate(point.In), DownBrush, 12, dip);
        var up = Text("↑ " + ByteFormat.Rate(point.Out), UpBrush, 12, dip);
        var when = Text(ago == 0 ? "now" : FormatAgo(ago) + " ago", LabelBrush, 11, dip);
        var width = Math.Max(Math.Max(down.Width, up.Width), when.Width) + 20;
        var height = down.Height + up.Height + when.Height + 14;
        var left = x + 12 + width > plot.Right ? x - 12 - width : x + 12;
        var box = new Rect(left, plot.Top + 4, width, height);

        var border = new Pen(GridBrush, 1);
        border.Freeze();
        dc.DrawRoundedRectangle(PanelBrush, border, box, 6, 6);
        dc.DrawText(down, new Point(box.Left + 10, box.Top + 6));
        dc.DrawText(up, new Point(box.Left + 10, box.Top + 6 + down.Height));
        dc.DrawText(when, new Point(box.Left + 10, box.Top + 8 + down.Height + up.Height));
    }

    /// <summary>Rounds the axis maximum up to a value whose quarters read cleanly (min 1 KB/s).</summary>
    private static double NiceMaximum(double peak)
    {
        if (peak <= 1024)
            return 1024;
        var unit = Math.Pow(1024, Math.Floor(Math.Log(peak, 1024)));
        var scaled = peak / unit;
        foreach (var candidate in new double[] { 1, 2, 4, 8, 10, 20, 40, 80, 100, 200, 400, 800 })
        {
            if (scaled <= candidate)
                return candidate * unit;
        }
        return 1024 * unit;
    }

    private static string FormatAgo(int seconds) =>
        seconds < 60 ? $"{seconds}s" : seconds % 60 == 0 ? $"{seconds / 60}m" : $"{seconds / 60}m {seconds % 60}s";

    private static FormattedText Text(string text, Brush brush, double size, double dip) =>
        new(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), size, brush, dip);

    private static DependencyProperty RegisterBrush(string name, Brush fallback) =>
        DependencyProperty.Register(name, typeof(Brush), typeof(TrafficChart),
            new FrameworkPropertyMetadata(fallback, FrameworkPropertyMetadataOptions.AffectsRender));
}
