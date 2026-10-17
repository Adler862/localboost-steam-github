using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace LocalBoost;

/// <summary>自绘小工具。所有控件共用的几何与缩放计算。</summary>
internal static class Ui
{
    public static GraphicsPath RoundedPath(RectangleF rect, float radius)
    {
        var path = new GraphicsPath();

        if (radius <= 0.5f)
        {
            path.AddRectangle(rect);
            return path;
        }

        // 直径不能超过任一边长，否则小控件上的圆角会画歪
        var d = Math.Min(radius * 2f, Math.Min(rect.Width, rect.Height));
        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    /// <summary>
    /// 只有右侧带圆角的路径。给贴在卡片右端的控件用（比如标题栏按钮），
    /// 让它们的填充能跟着卡片圆角走，而不是糊出一个方角。
    /// </summary>
    public static GraphicsPath RoundedRightPath(RectangleF rect, float radius)
    {
        var path = new GraphicsPath();

        if (radius <= 0.5f)
        {
            path.AddRectangle(rect);
            return path;
        }

        var d = Math.Min(radius * 2f, Math.Min(rect.Width, rect.Height));
        path.AddLine(rect.Left, rect.Top, rect.Right - d, rect.Top);
        path.AddArc(rect.Right - d, rect.Top, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddLine(rect.Right - d, rect.Bottom, rect.Left, rect.Bottom);
        path.CloseFigure();
        return path;
    }

    /// <summary>把设计稿上的像素换算成当前 DPI 下的像素。</summary>
    public static int Scale(Control control, int px) =>
        (int)Math.Round(px * control.DeviceDpi / 96.0);

    /// <summary>同上，但保留小数。画线宽、细描边这类几何量用它。</summary>
    public static float ScaleF(Control control, float px) =>
        (float)(px * control.DeviceDpi / 96.0);

    public static void EnableSmoothing(Graphics g)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
    }
}

/// <summary>
/// 玻璃卡片：一块不透明填充的区域。子控件设 BackColor = Transparent 就能透出这层底。
///
/// 注意它是**直角**的（Radius 默认留给调用方覆盖为 0）：窗口的圆角统一由 DWM 提供，
/// 卡片再圆一次就会在圆角内侧多出一圈轮廓。
/// </summary>
internal sealed class GlassCard : Panel
{
    public int Radius { get; set; } = 8;

    /// <summary>填充色留空表示用主题的默认卡片色。</summary>
    public Color? Fill { get; set; }

    /// <summary>
    /// 默认不描边。卡片是贴着窗口边缘铺的，画一圈边线会在窗口最外缘形成
    /// 一条多余的白线；分区靠底色差和卡片之间的缝隙区分就够了。
    /// </summary>
    public bool ShowStroke { get; set; }

    public GlassCard()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw
            | ControlStyles.SupportsTransparentBackColor,
            true);

        BackColor = Color.Transparent;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var theme = Theme.Current;
        Ui.EnableSmoothing(e.Graphics);

        var radius = Ui.Scale(this, Radius);
        var bounds = new RectangleF(0, 0, Width - 1, Height - 1);
        using var path = Ui.RoundedPath(bounds, radius);

        using (var brush = new SolidBrush(Fill ?? theme.CardFill))
            e.Graphics.FillPath(brush, path);

        if (ShowStroke)
        {
            using var pen = new Pen(theme.CardStroke, 1f);
            e.Graphics.DrawPath(pen, path);
        }
    }
}

internal enum ButtonKind
{
    /// <summary>强调色实心，用于主操作。</summary>
    Primary,

    /// <summary>半透明底 + 描边，用于次要操作。</summary>
    Secondary,

    /// <summary>平时不画底，只有悬停才出现，用于轻量操作。</summary>
    Ghost,
}

/// <summary>Win11 风格的圆角按钮。</summary>
internal sealed class AccentButton : Control
{
    private bool _hover;
    private bool _pressed;

    /// <summary>自己创建的字体。见 <see cref="Dispose(bool)"/> 的说明。</summary>
    private Font? _ownFont;

    public ButtonKind Kind { get; set; } = ButtonKind.Secondary;

    public int Radius { get; set; } = 6;

    public AccentButton()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw
            | ControlStyles.SupportsTransparentBackColor
            | ControlStyles.Selectable,
            true);

        BackColor = Color.Transparent;
        Cursor = Cursors.Hand;
        TabStop = true;

        // Control.Font 赋值后 WinForms 不回收它（认为字体归调用方所有），
        // 所以自己 new 的字体要留个引用，在自己的 Dispose 里释放。
        _ownFont = new Font("Microsoft YaHei UI", 9F);
        Font = _ownFont;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // 只释放自己 new 的那个：Control.Font 在未显式赋值时返回的是环境字体，
            // 释放它会把共享该字体的其它控件一起搞坏。
            _ownFont?.Dispose();
            _ownFont = null;
        }

        base.Dispose(disposing);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hover = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hover = false;
        _pressed = false;
        Invalidate();
        base.OnMouseLeave(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            _pressed = true;
            Focus();
            Invalidate();
        }

        base.OnMouseDown(e);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        _pressed = false;
        Invalidate();
        base.OnMouseUp(e);
    }

    protected override void OnEnabledChanged(EventArgs e)
    {
        Invalidate();
        base.OnEnabledChanged(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var theme = Theme.Current;
        Ui.EnableSmoothing(e.Graphics);

        // 按钮是直接挂在窗体上的，而窗体在材质模式下不绘制背景，
        // 透明底会取到未初始化的表面（表现为文字重影）。所以这里自己铺一层底。
        using (var baseBrush = new SolidBrush(theme.CardFill))
            e.Graphics.FillRectangle(baseBrush, ClientRectangle);

        var radius = Ui.Scale(this, Radius);
        var bounds = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        using var path = Ui.RoundedPath(bounds, radius);

        var (fill, stroke, text) = ResolveColors(theme);

        if (fill.A > 0)
        {
            using var brush = new SolidBrush(fill);
            e.Graphics.FillPath(brush, path);
        }

        if (stroke.A > 0)
        {
            using var pen = new Pen(stroke, 1f);
            e.Graphics.DrawPath(pen, path);
        }

        TextRenderer.DrawText(
            e.Graphics, Text, Font, new Rectangle(0, 0, Width, Height), text,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }

    private (Color Fill, Color Stroke, Color Text) ResolveColors(Theme theme)
    {
        if (!Enabled)
        {
            var faded = Color.FromArgb(theme.IsDark ? 14 : 10, theme.TextPrimary);
            return (Kind == ButtonKind.Primary
                    ? Color.FromArgb(40, theme.Accent)
                    : faded,
                Color.FromArgb(0, 0, 0, 0),
                Color.FromArgb(110, theme.TextPrimary));
        }

        switch (Kind)
        {
            case ButtonKind.Primary:
                var accent = _pressed ? theme.AccentPressed : _hover ? theme.AccentHover : theme.Accent;
                return (accent, Color.FromArgb(0, 0, 0, 0), theme.AccentText);

            case ButtonKind.Ghost:
                var ghost = _pressed ? theme.TitlePressed : _hover ? theme.TitleHover : Color.Transparent;
                return (ghost, Color.FromArgb(0, 0, 0, 0), theme.TextPrimary);

            default:
                var fill = _pressed ? theme.ControlPressed : _hover ? theme.ControlHover : theme.ControlFill;
                return (fill, theme.ControlStroke, theme.TextPrimary);
        }
    }
}

/// <summary>Win11 那种胶囊开关。开关状态直接反映到规则是否启用。</summary>
internal sealed class ToggleSwitch : Control
{
    private bool _hover;
    private bool _checked;

    public bool Checked
    {
        get => _checked;
        set
        {
            if (_checked == value)
                return;

            _checked = value;
            Invalidate();
            CheckedChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public event EventHandler? CheckedChanged;

    public ToggleSwitch()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw
            | ControlStyles.SupportsTransparentBackColor,
            true);

        BackColor = Color.Transparent;
        Cursor = Cursors.Hand;
        Size = new Size(40, 20);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hover = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hover = false;
        Invalidate();
        base.OnMouseLeave(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
            Checked = !Checked;

        base.OnMouseDown(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var theme = Theme.Current;
        Ui.EnableSmoothing(e.Graphics);

        using (var baseBrush = new SolidBrush(theme.CardFill))
            e.Graphics.FillRectangle(baseBrush, ClientRectangle);

        var inset = Ui.Scale(this, 2);
        var height = Height - inset * 2;
        var track = new RectangleF(inset, inset, Width - inset * 2, height);
        var radius = height / 2f;
        using var trackPath = Ui.RoundedPath(track, radius);

        var trackColor = Checked
            ? (_hover ? theme.AccentHover : theme.Accent)
            : (_hover ? theme.ControlHover : theme.ControlStroke);

        using (var brush = new SolidBrush(trackColor))
            e.Graphics.FillPath(brush, trackPath);

        if (!Checked)
        {
            using var pen = new Pen(theme.ControlStroke, 1f);
            e.Graphics.DrawPath(pen, trackPath);
        }

        // 滑块：开启时贴右，关闭时贴左
        var pad = Ui.Scale(this, 3);
        var knobSize = height - pad * 2;
        var knobX = Checked ? track.Right - knobSize - pad : track.Left + pad;
        var knob = new RectangleF(knobX, track.Top + pad, knobSize, knobSize);

        using var knobBrush = new SolidBrush(Checked ? Color.White : theme.TextSecondary);
        e.Graphics.FillEllipse(knobBrush, knob);
    }
}

/// <summary>标题栏右侧的最小化 / 关闭按钮。</summary>
internal sealed class CaptionButton : Control
{
    private bool _hover;
    private bool _pressed;

    /// <summary>true 表示这是关闭按钮（悬停变红）。</summary>
    public bool IsClose { get; set; }

    /// <summary>
    /// 右侧圆角半径。默认 0（直角）——窗口本身的圆角由 DWM 提供，
    /// 这里再圆一次就会在圆角内侧多出一圈轮廓，看起来就是"圆角外面套了个方框"。
    /// </summary>
    public int CornerRadius { get; set; }

    public CaptionButton()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw
            | ControlStyles.SupportsTransparentBackColor,
            true);

        BackColor = Color.Transparent;
        Cursor = Cursors.Hand;
        Size = new Size(46, 32);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hover = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hover = false;
        _pressed = false;
        Invalidate();
        base.OnMouseLeave(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            _pressed = true;
            Invalidate();
        }

        base.OnMouseDown(e);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        _pressed = false;
        Invalidate();
        base.OnMouseUp(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var theme = Theme.Current;
        Ui.EnableSmoothing(e.Graphics);

        if (_hover || _pressed)
        {
            var fill = IsClose
                ? theme.CloseHover
                : _pressed ? theme.TitlePressed : theme.TitleHover;

            // 按钮贴在卡片右端，填充必须跟着卡片的圆角走，
            // 否则会在窗口右上角糊出一个方块，把圆角盖掉
            var bounds = new RectangleF(0, 0, Width - 1, Height - 1);
            using var path = Ui.RoundedRightPath(bounds, Ui.Scale(this, CornerRadius));
            using var brush = new SolidBrush(fill);
            e.Graphics.FillPath(brush, path);
        }

        var glyphColor = _hover && IsClose ? Color.White : theme.TextPrimary;
        using var pen = new Pen(glyphColor, 1.2f);

        var cx = Width / 2f;
        var cy = Height / 2f;

        if (IsClose)
        {
            var arm = Ui.ScaleF(this, 5f);
            e.Graphics.DrawLine(pen, cx - arm, cy - arm, cx + arm, cy + arm);
            e.Graphics.DrawLine(pen, cx + arm, cy - arm, cx - arm, cy + arm);
        }
        else
        {
            var bar = Ui.ScaleF(this, 5.5f);
            e.Graphics.DrawLine(pen, cx - bar, cy, cx + bar, cy);
        }
    }
}

/// <summary>状态指示灯，运行中会有一圈柔光。</summary>
internal sealed class StatusDot : Control
{
    private Color _color = Color.Gray;
    private bool _glow;

    public Color DotColor
    {
        get => _color;
        set
        {
            _color = value;
            Invalidate();
        }
    }

    /// <summary>开启后画一圈光晕，用来表示"正在运行"。</summary>
    public bool Glow
    {
        get => _glow;
        set
        {
            _glow = value;
            Invalidate();
        }
    }

    public StatusDot()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw
            | ControlStyles.SupportsTransparentBackColor,
            true);

        BackColor = Color.Transparent;
        Size = new Size(14, 14);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Ui.EnableSmoothing(e.Graphics);

        using (var baseBrush = new SolidBrush(Theme.Current.CardFill))
            e.Graphics.FillRectangle(baseBrush, ClientRectangle);

        var size = Math.Min(Width, Height);
        var core = new RectangleF((Width - size) / 2f, (Height - size) / 2f, size, size);

        if (_glow)
        {
            var haloSize = size * 1.9f;
            var halo = new RectangleF(
                (Width - haloSize) / 2f, (Height - haloSize) / 2f, haloSize, haloSize);
            using var haloBrush = new SolidBrush(Color.FromArgb(48, _color));
            e.Graphics.FillEllipse(haloBrush, halo);
        }

        var border = Ui.ScaleF(this, 1.5f);
        var dot = new RectangleF(core.X + border, core.Y + border,
            core.Width - border * 2, core.Height - border * 2);
        using var brush = new SolidBrush(_color);
        e.Graphics.FillEllipse(brush, dot);
    }
}

/// <summary>
/// 自绘日志视图。不用 TextBox 是因为它的滚动条是经典控件的浅色样式，
/// 在深色界面里非常突兀——WinForms 也没法定制。
/// </summary>
internal sealed class LogView : Control
{
    private readonly List<string> _lines = [];
    private int _scroll;
    private bool _autoScroll = true;
    private bool _hoverScroll;

    /// <summary>自己创建的字体。见 <see cref="Dispose(bool)"/> 的说明。</summary>
    private Font? _ownFont;

    public int MaxLines { get; set; } = 2000;

    public LogView()
    {
        SetStyle(
            ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer
            | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw
            | ControlStyles.SupportsTransparentBackColor,
            true);

        BackColor = Color.Transparent;

        _ownFont = new Font("Consolas", 8.75F);
        Font = _ownFont;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _ownFont?.Dispose();
            _ownFont = null;
        }

        base.Dispose(disposing);
    }

    public void Append(string text)
    {
        // 传进来的可能是多行文本（比如 hosts 写入结果里带了换行），
        // 必须拆成独立的行——否则一整段会被当成一行，绘制时自动换行就会和下一行叠在一起
        foreach (var raw in text.Split('\n'))
            _lines.Add(raw.TrimEnd('\r'));

        if (_lines.Count > MaxLines)
        {
            var drop = _lines.Count - MaxLines;
            _lines.RemoveRange(0, drop);
            _scroll = Math.Max(0, _scroll - drop);
        }

        if (_autoScroll)
            _scroll = MaxScroll;

        Invalidate();
    }

    public void ClearAll()
    {
        _lines.Clear();
        _scroll = 0;
        _autoScroll = true;
        Invalidate();
    }

    /// <summary>
    /// 单行高度。必须用 <see cref="Font.GetHeight(float)"/> 按本控件的实际 DPI 算：
    /// <c>Font.Height</c> 是按 96 DPI 给的定值，150% 缩放下会明显小于实际渲染高度，
    /// 结果就是每条日志都往下一行压。
    /// </summary>
    private int LineHeight => (int)Math.Ceiling(Font.GetHeight(DeviceDpi)) + Ui.Scale(this, 3);

    private int VisibleLines => Math.Max(1, (Height - Ui.Scale(this, 8)) / Math.Max(1, LineHeight));

    private int MaxScroll => Math.Max(0, _lines.Count - VisibleLines);

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        ScrollBy(-e.Delta / 120 * 3);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hoverScroll = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hoverScroll = false;
        Invalidate();
        base.OnMouseLeave(e);
    }

    private void ScrollBy(int lines)
    {
        var target = Math.Clamp(_scroll + lines, 0, MaxScroll);
        if (target == _scroll)
            return;

        _scroll = target;
        // 手动滚上去就不再自动跟到底，滚回底部则恢复跟随
        _autoScroll = _scroll >= MaxScroll;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var theme = Theme.Current;
        Ui.EnableSmoothing(e.Graphics);

        // 比卡片略暗一点，做出"内凹"的感觉
        using (var background = new SolidBrush(
                   theme.IsDark ? Color.FromArgb(0x5A, 0, 0, 0) : Color.FromArgb(0x1E, 0, 0, 0)))
        {
            using var path = Ui.RoundedPath(new RectangleF(0, 0, Width - 1, Height - 1), Ui.Scale(this, 6));
            e.Graphics.FillPath(background, path);
        }

        e.Graphics.SetClip(new Rectangle(Ui.Scale(this, 2), Ui.Scale(this, 2),
            Math.Max(0, Width - Ui.Scale(this, 16)), Math.Max(0, Height - Ui.Scale(this, 4))));

        var lineHeight = LineHeight;
        var y = Ui.Scale(this, 4);
        var last = Math.Min(_lines.Count, _scroll + VisibleLines);

        for (var i = _scroll; i < last; i++)
        {
            TextRenderer.DrawText(
                e.Graphics, _lines[i], Font, new Point(Ui.Scale(this, 8), y), theme.IsDark
                    ? Color.FromArgb(0xCF, 0xCF, 0xD4)
                    : Color.FromArgb(0x2A, 0x2A, 0x2E),
                // SingleLine 是必须的：否则超长行会自动折行，而 y 只按一行推进，
                // 折出来的第二行就会压在下一条日志上
                TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix
                | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);

            y += lineHeight;
        }

        e.Graphics.ResetClip();

        PaintScrollThumb(e.Graphics, theme);
    }

    private void PaintScrollThumb(Graphics g, Theme theme)
    {
        if (MaxScroll <= 0)
            return;

        var inset = Ui.Scale(this, 5);
        var trackHeight = Height - inset * 2;
        if (trackHeight <= 0)
            return;

        var thumbHeight = Math.Max(Ui.ScaleF(this, 28f), trackHeight * (float)VisibleLines / _lines.Count);
        var progress = (float)_scroll / MaxScroll;
        var thumbTop = inset + (trackHeight - thumbHeight) * progress;

        var thumbWidth = Ui.ScaleF(this, 5f);
        var rect = new RectangleF(Width - inset - thumbWidth, thumbTop, thumbWidth, thumbHeight);
        using var path = Ui.RoundedPath(rect, thumbWidth / 2f);
        using var brush = new SolidBrush(Color.FromArgb(
            _hoverScroll ? 150 : 96, theme.TextSecondary.R, theme.TextSecondary.G, theme.TextSecondary.B));
        g.FillPath(brush, path);
    }
}
