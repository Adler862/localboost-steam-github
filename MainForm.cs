using System.Collections.Concurrent;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace LocalBoost;

/// <summary>
/// 主窗口。Win11 风格：无边框、自绘标题栏、圆角玻璃卡片。
///
/// 玻璃效果走的是「亚克力材质 + 透明键」这条路：窗口底色填成一个魔数色并设为透明键，
/// 于是没被卡片盖住的地方就露出 DWM 的亚克力模糊。如果系统不支持（Win10 或关了透明效果），
/// 自动退回自绘渐变底色，界面不会坏。
/// </summary>
internal sealed class MainForm : Form
{
    // 以下常量都是「设计稿像素」，基准 96 DPI / 100% 缩放。
    // 运行时一律经 S() 换算后再用 —— 绝不能直接当像素用：系统缩放 150% 时
    // 字体按点值放大 1.5 倍，而坐标不跟着放大会让文字撑破容器、互相重叠。
    //
    // Pad = 0 是刻意的：圆角只能有一层来源。窗口留白 + 卡片圆角 + 按钮圆角
    // 会形成三层嵌套，视觉上就是"圆角外面套一圈方框"。所以卡片一律直角、
    // 贴着窗口边缘铺，圆角只由窗口本身（DWM）提供。
    private const int Pad = 0;
    private const int Gap = 8;           // 卡片之间的缝，露出窗口材质
    private const int TitleHeight = 44;
    private const int RowHeight = 30;
    private const int CaptionWidth = 46;
    private const byte GlassTintAlpha = 0x9E;

    private const int DesignWidth = 748;
    private const int DesignHeight = 648;
    private const int DesignMinWidth = 660;
    private const int DesignMinHeight = 560;

    /// <summary>
    /// 设计稿像素 → 当前 DPI 像素。
    ///
    /// 必须每次布局/绘制时现算，不能缓存成字段：窗口被拖到另一块缩放比例
    /// 不同的显示器上时 DeviceDpi 会变，缓存住就会错位。
    /// </summary>
    private int S(int px) => Ui.Scale(this, px);

    private readonly string _rulesPath;
    private readonly IpOptimizer _optimizer = new();
    private readonly LocalCertAuthority _ca = new();

    private List<AccelRule> _allRules = [];
    private IReadOnlyList<string> _ruleWarnings = [];
    private ProxyHost? _host;
    private bool _exiting;
    private string _material = "纯色";

    private readonly TitleBar _titleBar = new();
    private readonly GlassCard _statusCard = new();
    private readonly GlassCard _rulesCard = new();
    private readonly GlassCard _logCard = new();

    private readonly StatusDot _dot = new();
    private readonly Label _statusText = new();
    private readonly Label _detailText = new();
    private readonly Label _rulesTitle = new();
    private readonly Label _logTitle = new();

    private readonly AccentButton _btnToggle = new();
    private readonly AccentButton _btnCert = new();
    private readonly AccentButton _btnHostsOn = new();
    private readonly AccentButton _btnHostsOff = new();
    private readonly AccentButton _btnProxy = new();

    private readonly LogView _logView = new();
    private readonly NotifyIcon _tray = new();
    private readonly CaptionButton _btnMinimize = new();
    private readonly CaptionButton _btnClose = new() { IsClose = true };
    private readonly List<(AccelRule Rule, Label Label, ToggleSwitch Toggle)> _rows = [];

    /// <summary>待显示的日志。可能由后台线程写入，所以用并发队列。</summary>
    private readonly ConcurrentQueue<string> _pendingLogs = new();

    /// <summary>日志批量冲刷用的 UI 定时器。</summary>
    private readonly System.Windows.Forms.Timer _logFlush = new() { Interval = 100 };

    /// <summary>
    /// 自建字体缓存。
    ///
    /// 给 <see cref="Control.Font"/> 赋值之后 WinForms 不负责回收字体（它认为字体归调用方所有），
    /// 所以凡是我们自己 new 出来的字体都得自己管生命周期，退出时统一释放。
    /// 顺带避免"每条规则各 new 一个同样的字体"。
    /// </summary>
    private readonly Dictionary<(string Family, float Size, FontStyle Style), Font> _fonts = [];

    /// <summary>正在按 DPI 重设尺寸。用于挡住重入，见 <see cref="ApplyDpiScale"/> 的说明。</summary>
    private bool _applyingDpiScale;

    /// <summary>上一次的窗口状态。用于识别"从最小化/最大化回到正常"这个时刻。</summary>
    private FormWindowState _lastWindowState = FormWindowState.Normal;

    /// <summary>正在执行"缩到托盘"。同样用于挡重入。</summary>
    private bool _hidingToTray;

    public MainForm(string rulesPath)
    {
        _rulesPath = rulesPath;

        Text = "LocalBoost";

        // 布局全部手算，再让 WinForms 按字体自动缩放只会和我们的换算打架。
        // 窗口尺寸在 OnHandleCreated 里按实际 DPI 放大，这里先给设计稿尺寸。
        AutoScaleMode = AutoScaleMode.None;
        ClientSize = new Size(DesignWidth, DesignHeight);
        MinimumSize = new Size(DesignMinWidth, DesignMinHeight);

        StartPosition = FormStartPosition.Manual;
        FormBorderStyle = FormBorderStyle.None;
        DoubleBuffered = true;
        Font = FontOf("Microsoft YaHei UI", 9F);
        KeyPreview = true;

        // 无边框窗口最大化会盖住任务栏，手动限一下
        MaximizedBounds = Screen.PrimaryScreen?.WorkingArea ?? Screen.GetWorkingArea(Point.Empty);

        BuildTree();
        BuildTray();
        LoadRules();
        ApplyThemeToControls();
        LayoutEverything();
        ApplyStatus();

        AppendLog("就绪。首次使用按「安装根证书」→「一键加速」两步走。");

        // 日志先入队、由定时器批量刷到界面上，避免高并发时逐行 BeginInvoke 灌爆消息队列
        _logFlush.Tick += (_, _) => FlushLogs();
        _logFlush.Start();

        // 系统切换深浅色时跟着变
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        CenterOnWorkingArea();
    }

    /// <summary>
    /// 手动按工作区居中。
    ///
    /// 不用 StartPosition = CenterScreen：那个在 DPI 感知的进程里会按逻辑坐标算，
    /// 实测能偏出几百像素，甚至让窗口贴到屏幕边上——一旦贴边，Windows 会把那一侧
    /// 的圆角去掉，看起来就是"两边圆角不对称"。
    /// </summary>
    private void CenterOnWorkingArea()
    {
        var area = Screen.FromControl(this).WorkingArea;
        Location = new Point(
            area.Left + Math.Max(0, (area.Width - Width) / 2),
            area.Top + Math.Max(0, (area.Height - Height) / 2));
    }

    // ------------------------------------------------------------ 窗口外观

    /// <summary>
    /// 无边框窗口要显式带 WS_THICKFRAME，否则 DWM 不会给它圆角和投影，
    /// 系统也不会提供边缘拖拽缩放。副作用是客户区会被让出 8px 给非客户区，
    /// 布局全是按 ClientSize 算的，所以会自动适应。
    /// </summary>
    protected override CreateParams CreateParams
    {
        get
        {
            const int WS_THICKFRAME = 0x00010000;
            var cp = base.CreateParams;
            cp.Style |= WS_THICKFRAME;
            return cp;
        }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyDpiScale();
        ApplyWindowMaterial();
    }

    /// <summary>
    /// 按当前显示器的 DPI 重设窗口尺寸。
    ///
    /// 本程序是 PerMonitorV2 DPI 感知的，系统不会替我们做位图拉伸，
    /// 所以窗口该多大、控件摆在哪，必须自己跟着 DPI 走。
    /// 设计稿按 100% 画（748×648），这里按 DeviceDpi/96 等比放大。
    /// </summary>
    /// <summary>
    /// 按当前显示器的 DPI 重设窗口尺寸。
    ///
    /// ⚠️ 这个方法只能在**正常状态**下改尺寸，否则会栈溢出（0xC00000FD）。
    ///
    /// 原因是这样绕起来的：本方法挂在 <see cref="OnDpiChanged"/> 上，而 WinForms 在
    /// **隐藏窗口、最小化、最大化**的过程中也会触发 DpiChanged。于是
    /// 「改 ClientSize → 触发 Resize / DPI 变化 → 又进到这里改 ClientSize」形成递归；
    /// 最小化那条路径还算收敛（Hide 与 ShowInTaskbar 第二次调用就短路了），
    /// 最大化那条路径会一直递归下去，直到栈耗尽、进程瞬间消失。
    /// 最小化时 ClientSize 是 0x0、最大化时尺寸归系统管，改它们也没有意义。
    ///
    /// ⚠️ **但守卫里绝不能加 <c>!Visible</c>**：本方法是从 <see cref="OnHandleCreated"/>
    /// 调用的，而那一刻窗口**还没显示**，加了这个判断就会在启动时直接返回、
    /// 整个 DPI 缩放失效 —— 125% 下窗口比布局小 25%，按钮行会被窗口边缘裁掉。
    /// 这个坑已经踩过一次了。
    /// </summary>
    private void ApplyDpiScale()
    {
        if (!IsHandleCreated || WindowState != FormWindowState.Normal)
            return;

        // 再防一层重入：下面改的是窗口尺寸，会同步触发 Resize / DpiChanged
        if (_applyingDpiScale)
            return;

        _applyingDpiScale = true;
        try
        {
            var scale = DeviceDpi / 96.0;

            ClientSize = new Size(
                (int)Math.Round(DesignWidth * scale),
                (int)Math.Round(DesignHeight * scale));

            MinimumSize = new Size(
                (int)Math.Round(DesignMinWidth * scale),
                (int)Math.Round(DesignMinHeight * scale));

            // 无边框窗口最大化会盖住任务栏，而且工作区尺寸跟着显示器走，
            // 所以不能只在构造时算一次。
            MaximizedBounds = Screen.FromControl(this).WorkingArea;
        }
        finally
        {
            _applyingDpiScale = false;
        }
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);

        ApplyDpiScale();
        LayoutEverything();
        _titleBar.Restyle();
        _logView.Invalidate();
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if (_material == "纯色")
        {
            // 用纯色而不是渐变：按钮这类自绘控件会把按钮色合成到这个底色上，
            // 渐变会让按钮和它周围的背景对不上，看起来又像围了一圈框。
            using var brush = new SolidBrush(Theme.Current.WindowTop);
            e.Graphics.FillRectangle(brush, ClientRectangle);
            return;
        }

        // 材质模式下什么都不画：客户区空着，DWM 的 Mica 才透得出来。
        // 卡片之间那几像素的缝，就是靠这里露出来的。
    }

    private void ApplyWindowMaterial()
    {
        if (!IsHandleCreated)
            return;

        var theme = Theme.Current;

        // 让整块客户区都成为"窗口材质区"，只在标题栏生效是不够的
        Win11.ExtendFrameIntoClientArea(Handle);
        _material = Win11.ApplyWindowMaterial(Handle, theme.BackdropTint, GlassTintAlpha);

        // 不用 TransparencyKey：那会把窗口变成 layered，材质和圆角会一起失效
        BackColor = theme.WindowTop;
        TransparencyKey = Color.Empty;

        Win11.ApplyRoundCorners(Handle);
        Win11.RemoveWindowBorder(Handle);
        Win11.ApplyTitleBarTheme(Handle, theme.IsDark);

        _titleBar.Restyle();
        Invalidate(true);

        AppendLog($"窗口材质：{_material}（Windows 11：{(Win11.IsWindows11 ? "是" : "否")}）");
    }

    /// <summary>
    /// 尺寸变化。
    ///
    /// 注意里面这层"状态回到正常就重算尺寸"：最大化期间我们刻意不动 ClientSize
    /// （尺寸归系统管），如果这期间窗口被拖到了另一块缩放比例不同的显示器上，
    /// 必须等它回到正常状态时补算一次，否则会一直按旧的缩放比例渲染。
    /// </summary>
    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);

        if (WindowState == FormWindowState.Normal && _lastWindowState != FormWindowState.Normal)
            ApplyDpiScale();

        _lastWindowState = WindowState;

        LayoutEverything();
    }

    /// <summary>无边框窗口要自己处理边缘缩放。</summary>
    protected override void WndProc(ref Message m)
    {
        const int WM_NCHITTEST = 0x0084;
        const int HTCLIENT = 1;

        if (m.Msg == WM_NCHITTEST && WindowState == FormWindowState.Normal)
        {
            base.WndProc(ref m);
            if ((int)m.Result == HTCLIENT)
            {
                m.Result = (IntPtr)HitTestBorders(PointToClient(new Point(
                    unchecked((short)(long)m.LParam), unchecked((short)((long)m.LParam >> 16)))));
            }

            return;
        }

        base.WndProc(ref m);
    }

    private int HitTestBorders(Point client)
    {
        // 缩放后热区也要跟着变，否则 150% 下边缘几乎点不中
        var grip = S(7);
        var left = client.X <= grip;
        var right = client.X >= ClientSize.Width - grip;
        var top = client.Y <= grip;
        var bottom = client.Y >= ClientSize.Height - grip;

        const int HTLEFT = 10, HTRIGHT = 11, HTTOP = 12, HTTOPLEFT = 13,
                  HTTOPRIGHT = 14, HTBOTTOM = 15, HTBOTTOMLEFT = 16, HTBOTTOMRIGHT = 17;

        if (left && top) return HTTOPLEFT;
        if (right && top) return HTTOPRIGHT;
        if (left && bottom) return HTBOTTOMLEFT;
        if (right && bottom) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;

        return 1;   // HTCLIENT
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Escape && WindowState == FormWindowState.Maximized)
            WindowState = FormWindowState.Normal;

        base.OnKeyDown(e);
    }

    // ------------------------------------------------------------ 控件树

    private void BuildTree()
    {
        // 尺寸统一交给 LayoutEverything 按 DPI 换算，这里只设内容
        _titleBar.Title = "LocalBoost";
        _titleBar.Subtitle = "Steam / GitHub 本地加速";

        _statusCard.Radius = 0;

        _statusText.Font = FontOf("Microsoft YaHei UI", 12F, FontStyle.Bold);
        _statusText.AutoSize = true;
        _statusText.BackColor = Color.Transparent;

        _detailText.AutoSize = true;
        _detailText.BackColor = Color.Transparent;

        _rulesTitle.Text = "加速规则";
        _rulesTitle.AutoSize = true;
        _rulesTitle.BackColor = Color.Transparent;

        _logTitle.Text = "日志";
        _logTitle.AutoSize = true;
        _logTitle.BackColor = Color.Transparent;

        _btnToggle.Kind = ButtonKind.Primary;
        _btnToggle.Text = "一键加速";
        _btnToggle.Click += async (_, _) => await ToggleAsync();

        _btnCert.Text = "安装根证书";
        _btnCert.Click += (_, _) => InstallCertificate();

        _btnHostsOn.Text = "写入 hosts";
        _btnHostsOn.Click += (_, _) => WriteHosts();

        _btnHostsOff.Text = "清理 hosts";
        _btnHostsOff.Click += (_, _) => ClearHosts();

        _btnProxy.Text = "开启系统代理";
        _btnProxy.Click += (_, _) => ToggleSystemProxy();

        _logCard.Radius = 0;
        _rulesCard.Radius = 0;

        _logCard.Controls.AddRange([_logTitle, _logView]);
        _rulesCard.Controls.Add(_rulesTitle);
        _statusCard.Controls.AddRange([_dot, _statusText, _detailText]);

        // 最小化 / 关闭跟着标题栏走，这样窗口移动和最大化时不用另外同步位置
        _btnMinimize.Click += (_, _) => WindowState = FormWindowState.Minimized;
        _btnClose.Click += (_, _) => Close();   // 走 FormClosing，缩到托盘而不是退出
        _titleBar.Controls.AddRange([_btnMinimize, _btnClose]);

        Controls.AddRange([_logCard, _rulesCard, _statusCard, _btnToggle, _btnCert,
            _btnHostsOn, _btnHostsOff, _btnProxy, _titleBar]);
    }

    private void BuildTray()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("显示主界面", null, (_, _) => ShowFromTray());
        menu.Items.Add("启动加速", null, async (_, _) => await StartAsync());
        menu.Items.Add("停止加速", null, async (_, _) => await StopAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("退出", null, async (_, _) => await ExitAsync());

        _tray.Icon = TrayIcon.Create(false);
        _tray.Text = "LocalBoost —— 未运行";
        _tray.ContextMenuStrip = menu;
        _tray.Visible = true;
        // 这里原先挂着「一最小化就缩到托盘」。已移除，原因有三：
        //   1. README 写的是「关窗口」才缩托盘，最小化也缩属于行为与文档不符；
        //   2. 缩到托盘后任务栏上没有按钮，用户想"最小化后最大化"根本无从操作，
        //      只能先经托盘恢复 —— 这正是闪退那次的操作路径；
        //   3. HideToTray 里会改 ShowInTaskbar（会重建窗口句柄），
        //      在 Resize 事件里做这件事本身就是自找重入。
        // 现在最小化就是正常最小化，只有关闭窗口才缩到托盘。
        _tray.DoubleClick += (_, _) => ShowFromTray();

        FormClosing += (_, e) =>
        {
            if (_exiting)
                return;

            // 系统注销 / 关机 / 任务管理器结束任务必须放行，
            // 否则会看到"LocalBoost 阻止关机"。这时不再做优雅收尾：
            // 进程马上就会结束，操作系统的资源回收比我们抢时间更可靠。
            if (e.CloseReason is CloseReason.WindowsShutDown or CloseReason.TaskManagerClosing)
            {
                _exiting = true;
                return;
            }

            // 平时关窗口不退出：加速服务跟着窗口一起断掉会很烦
            e.Cancel = true;
            HideToTray();
        };
    }

    // ------------------------------------------------------------ 布局

    private void LayoutEverything()
    {
        if (ClientSize.Width <= 0 || ClientSize.Height <= 0)
            return;

        var pad = S(Pad);
        var gap = S(Gap);
        var titleHeight = S(TitleHeight);
        var inner = ClientSize.Width - pad * 2;

        // 标题栏本身也是一块卡片，整窗就是"卡片堆叠"，缝隙露出窗口材质
        var y = S(8);
        _titleBar.SetBounds(pad, y, inner, titleHeight);

        var captionWidth = S(CaptionWidth);
        _btnClose.SetBounds(_titleBar.Width - captionWidth, 0, captionWidth, titleHeight);
        _btnMinimize.SetBounds(_titleBar.Width - captionWidth * 2, 0, captionWidth, titleHeight);

        y += titleHeight + gap;

        var statusHeight = S(74);
        _statusCard.SetBounds(pad, y, inner, statusHeight);
        LayoutStatusCard();

        y += statusHeight + gap;

        // 规则卡片高度跟着规则条数走
        var rulesHeight = S(40) + _rows.Count * S(RowHeight) + S(8);
        _rulesCard.SetBounds(pad, y, inner, rulesHeight);
        LayoutRulesCard();

        y += rulesHeight + gap;

        // 按钮组往右靠，但留出右边距——贴着窗口边缘不好看
        var buttonWidth = S(116);
        var buttonGap = S(8);
        var buttonHeight = S(34);
        var leftMargin = S(8);
        var rightMargin = S(16);

        var primaryWidth = buttonWidth + S(12);
        var groupWidth = primaryWidth + (buttonWidth + buttonGap) * 4;

        // 兜底：窗口窄到放不下整排时按比例收缩，宁可按钮小一点，也不要被窗口边缘裁掉。
        //
        // 这道兜底是有来历的：曾因为 DPI 换算漏了一步，125% 下窗口比布局小 25%，
        // 而"按设计宽度算"这里是刚好够用的 —— 结果最后一个按钮被裁掉。
        // 与其相信"算出来够用"，不如让它无论如何都不越界。
        var available = ClientSize.Width - leftMargin - rightMargin;
        if (groupWidth > available && available > 0)
        {
            var ratio = (double)available / groupWidth;
            buttonWidth = Math.Max(S(64), (int)(buttonWidth * ratio));
            buttonGap = Math.Max(S(4), (int)(buttonGap * ratio));
            primaryWidth = Math.Max(S(72), (int)(primaryWidth * ratio));
            groupWidth = primaryWidth + (buttonWidth + buttonGap) * 4;
        }

        var bx = Math.Max(leftMargin, ClientSize.Width - groupWidth - rightMargin);

        _btnToggle.SetBounds(bx, y, primaryWidth, buttonHeight);
        _btnCert.SetBounds(bx + primaryWidth + buttonGap, y, buttonWidth, buttonHeight);
        _btnHostsOn.SetBounds(bx + primaryWidth + buttonGap * 2 + buttonWidth, y, buttonWidth, buttonHeight);
        _btnHostsOff.SetBounds(bx + primaryWidth + buttonGap * 3 + buttonWidth * 2, y, buttonWidth, buttonHeight);
        _btnProxy.SetBounds(bx + primaryWidth + buttonGap * 4 + buttonWidth * 3, y, buttonWidth, buttonHeight);

        y += buttonHeight + gap;

        var logHeight = Math.Max(S(80), ClientSize.Height - y - pad);
        _logCard.SetBounds(pad, y, inner, logHeight);
        LayoutLogCard();
    }

    private void LayoutStatusCard()
    {
        var dot = S(16);
        _dot.SetBounds(S(18), S(20), dot, dot);
        _statusText.Location = new Point(S(44), S(18));
        _detailText.Location = new Point(S(20), S(44));
    }

    private void LayoutRulesCard()
    {
        _rulesTitle.Location = new Point(S(18), S(12));

        var cardWidth = _rulesCard.ClientSize.Width;
        var rowHeight = S(RowHeight);
        var toggleWidth = S(40);
        var toggleHeight = S(20);

        for (var i = 0; i < _rows.Count; i++)
        {
            var (_, label, toggle) = _rows[i];
            var top = S(38) + i * rowHeight;

            label.SetBounds(S(18), top, cardWidth - S(18) - S(62), rowHeight);
            label.TextAlign = ContentAlignment.MiddleLeft;

            toggle.SetBounds(cardWidth - S(18) - toggleWidth, top + S(5), toggleWidth, toggleHeight);
        }
    }

    private void LayoutLogCard()
    {
        _logTitle.Location = new Point(S(18), S(12));
        _logView.SetBounds(S(10), S(32), Math.Max(S(60), _logCard.ClientSize.Width - S(20)),
            Math.Max(S(30), _logCard.ClientSize.Height - S(42)));
    }

    // ------------------------------------------------------------ 主题

    private void ApplyThemeToControls()
    {
        var theme = Theme.Current;

        _titleBar.Invalidate();
        _statusCard.Invalidate();
        _rulesCard.Invalidate();
        _logCard.Invalidate();
        _dot.Invalidate();

        foreach (var (_, label, toggle) in _rows)
        {
            label.ForeColor = theme.TextPrimary;
            label.Invalidate();
            toggle.Invalidate();
        }

        _statusText.ForeColor = theme.TextPrimary;
        _detailText.ForeColor = theme.TextSecondary;

        _rulesTitle.ForeColor = theme.TextSecondary;
        _logTitle.ForeColor = theme.TextSecondary;

        _dot.DotColor = _host is { IsRunning: true } ? theme.Success : theme.Idle;

        _logView.Invalidate();

        foreach (var button in new[] { _btnToggle, _btnCert, _btnHostsOn, _btnHostsOff, _btnProxy })
            button.Invalidate();

        _titleBar.Restyle();
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category is not (UserPreferenceCategory.General or UserPreferenceCategory.Color
            or UserPreferenceCategory.VisualStyle))
            return;

        if (IsDisposed || !IsHandleCreated)
            return;

        try
        {
            BeginInvoke(() =>
            {
                Theme.Refresh(Win11.IsSystemDarkMode());
                ApplyWindowMaterial();
                ApplyThemeToControls();
                LayoutEverything();
                ApplyStatus();
            });
        }
        catch (InvalidOperationException)
        {
            // 句柄在这两行之间被销毁了，界面已经在收尾，忽略即可。
            // 这个回调跑在非 UI 线程上，抛出去会直接崩进程。
        }
    }

    // ------------------------------------------------------------ 规则

    /// <summary>用当前勾选状态重建规则表，并带上加载期告警。</summary>
    private RuleBook BuildRuleBook() => RuleBook.Create(_allRules, _ruleWarnings);

    private void LoadRules()
    {
        var book = RuleBook.Load(_rulesPath);
        _allRules = book.Rules.ToList();
        _ruleWarnings = book.Warnings;

        foreach (var warning in _ruleWarnings)
            AppendLog($"! {warning}");

        foreach (var rule in _allRules)
        {
            var wildcard = rule.Hosts.Any(h => h.StartsWith("*.", StringComparison.Ordinal));
            var sample = rule.Hosts.FirstOrDefault() ?? "";
            var suffix = rule.Hosts.Length > 1 ? $" 等 {rule.Hosts.Length} 个" : "";
            var note = wildcard ? "  ·  通配，需代理模式" : "";

            var label = new Label
            {
                Text = $"{rule.Tag}    {sample}{suffix}{note}",
                BackColor = Color.Transparent,
                AutoSize = false,
                Font = FontOf("Microsoft YaHei UI", 9F),
            };

            var toggle = new ToggleSwitch { Checked = rule.Enabled };
            var captured = rule;
            toggle.CheckedChanged += (_, _) =>
            {
                captured.Enabled = toggle.Checked;
                AppendLog($"{(toggle.Checked ? "启用" : "停用")}规则：{captured.Tag}（重新加速后生效）");
            };

            _rows.Add((rule, label, toggle));
            _rulesCard.Controls.Add(label);
            _rulesCard.Controls.Add(toggle);
        }
    }

    // ------------------------------------------------------------ 操作

    private async Task ToggleAsync()
    {
        if (_host is { IsRunning: true })
            await StopAsync();
        else
            await StartAsync();
    }

    private async Task StartAsync()
    {
        if (_host is { IsRunning: true })
            return;

        if (!_ca.IsRootInstalled())
        {
            var answer = MessageBox.Show(this,
                "还没有安装根证书，浏览器会一直报证书错误。现在就安装吗？",
                "LocalBoost", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

            if (answer != DialogResult.Yes)
                return;

            InstallCertificate();
        }

        if (!Cli.HostsInstalled())
        {
            try
            {
                AppendLog(Cli.InstallHosts(BuildRuleBook()));
            }
            catch (UnauthorizedAccessException)
            {
                ShowError("写入 hosts 失败，权限不足。\n请右键以管理员身份运行本程序。");
                return;
            }
            catch (Exception ex)
            {
                ShowError($"写入 hosts 失败：{ex.Message}");
                return;
            }
        }

        // 勾选状态可能刚变过，按当前选择重建规则表和宿主
        var book = BuildRuleBook();
        _host = new ProxyHost(book, _optimizer, _ca,
            ReadPort("LOCALBOOST_HTTPS_PORT", 443),
            ReadPort("LOCALBOOST_HTTP_PORT", 80),
            ReadPort("LOCALBOOST_PROXY_PORT", ProxyHost.DefaultProxyPort));
        _host.Log += AppendLog;

        _btnToggle.Enabled = false;
        try
        {
            await _host.StartAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"启动失败：{ex.Message}");
            ShowError($"启动失败：{ex.Message}\n\n最常见的原因是 443 端口被占用"
                    + "（VMware、IIS、Skype 都会占）。\n可以先用 netstat -ano | findstr :443 查一下。");
            _host = null;
        }
        finally
        {
            _btnToggle.Enabled = true;
            ApplyStatus();
        }
    }

    private async Task StopAsync()
    {
        if (_host is null)
            return;

        _btnToggle.Enabled = false;
        try
        {
            _host.Log -= AppendLog;
            await _host.StopAsync();
        }
        finally
        {
            _host = null;
            _btnToggle.Enabled = true;
            ApplyStatus();
        }
    }

    private void InstallCertificate()
    {
        try
        {
            Cli.RunCert(["cert", "install"], out var message);
            AppendLog(message.Replace(Environment.NewLine, " "));
            MessageBox.Show(this, message, "LocalBoost",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            ShowError($"安装证书失败：{ex.Message}");
        }
    }

    private void WriteHosts()
    {
        try
        {
            AppendLog(Cli.InstallHosts(BuildRuleBook()));
        }
        catch (UnauthorizedAccessException)
        {
            ShowError("写入 hosts 失败，权限不足。\n请右键以管理员身份运行本程序。");
        }
        catch (Exception ex)
        {
            ShowError($"写入 hosts 失败：{ex.Message}");
        }
    }

    private void ClearHosts()
    {
        try
        {
            AppendLog(Cli.RemoveHosts());
        }
        catch (Exception ex)
        {
            ShowError($"清理 hosts 失败：{ex.Message}");
        }
    }

    /// <summary>
    /// 开关系统代理（PAC 方式）。
    ///
    /// 注意方向：**关**这个动作不要求服务在运行 —— 服务停了但注册表没来得及还原时，
    /// 用户必须还能把它关掉，否则规则域名会一直打不开且无从下手。
    /// </summary>
    private void ToggleSystemProxy()
    {
        var dir = LocalCertAuthority.DefaultStoreDir;
        var systemProxy = new SystemProxy(dir);
        var pacPath = Path.Combine(dir, "localboost.pac");

        try
        {
            if (systemProxy.IsEnabledTo(pacPath))
            {
                AppendLog(systemProxy.Restore() ? "已还原系统代理设置。" : "系统代理没有被本程序改过，无需还原。");
            }
            else if (_host is { IsRunning: true })
            {
                AppendLog(_host.EnableSystemProxy());
            }
            else
            {
                ShowError("请先点「一键加速」。本地代理还没起来，"
                        + "现在开启系统代理会让规则域名全部打不开。");
            }
        }
        catch (Exception ex)
        {
            ShowError($"切换系统代理失败：{ex.Message}");
        }

        ApplyStatus();
    }

    /// <summary>
    /// 系统代理是否指向我们的 PAC。
    /// 不依赖服务是否在运行 —— 服务停了也得能如实显示状态。
    /// </summary>
    private static bool IsSystemProxyOn()
    {
        var dir = LocalCertAuthority.DefaultStoreDir;
        return new SystemProxy(dir).IsEnabledTo(Path.Combine(dir, "localboost.pac"));
    }

    private void ShowError(string message) =>
        MessageBox.Show(this, message, "LocalBoost", MessageBoxButtons.OK, MessageBoxIcon.Error);

    private static int ReadPort(string name, int fallback) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;

    // ------------------------------------------------------------ 状态与日志

    private void ApplyStatus()
    {
        var theme = Theme.Current;
        var running = _host is { IsRunning: true };

        _dot.DotColor = running ? theme.Success : theme.Idle;
        _dot.Glow = running;

        _statusText.Text = running ? "运行中" : "未运行";
        _titleBar.Running = running;

        if (running)
        {
            var hostsState = Cli.HostsInstalled() ? "hosts 已接管" : "hosts 未写入，加速不会生效";
            var proxyState = IsSystemProxyOn() ? "系统代理已接管" : "系统代理未开";
            _detailText.Text = $"监听 127.0.0.1:{_host!.HttpsPort}  ·  {hostsState}  ·  {proxyState}";
        }
        else
        {
            _detailText.Text = "本地反代未启动";
        }

        _btnToggle.Text = running ? "停止加速" : "一键加速";
        _btnHostsOn.Enabled = !running;

        _btnProxy.Text = IsSystemProxyOn() ? "关闭系统代理" : "开启系统代理";

        // 换图标时旧的要自己释放：NotifyIcon 不会替我们回收那个 Icon 对象，
        // 而 ApplyStatus 在每次启停 / 换主题时都会走到这里。
        var previousIcon = _tray.Icon;
        _tray.Icon = TrayIcon.Create(running);
        previousIcon?.Dispose();

        _tray.Text = running ? "LocalBoost —— 运行中" : "LocalBoost —— 未运行";

        _titleBar.Invalidate();
        _dot.Invalidate();
    }

    /// <summary>
    /// 记一行日志。
    ///
    /// 这里只入队、不直接写界面：反向代理每转一个请求就打一行，高并发下载时
    /// 后台线程会以极高频率进来，逐行 <c>BeginInvoke</c> 会让 UI 消息队列无界增长
    /// （内存上涨、界面卡死）。改由 <see cref="_logFlush"/> 在 UI 线程上批量冲刷。
    /// 队列是 FIFO，所以日志先后顺序不受影响。
    /// </summary>
    private void AppendLog(string line)
    {
        if (!string.IsNullOrEmpty(line))
            _pendingLogs.Enqueue(line);
    }

    /// <summary>由定时器在 UI 线程上调用，一次把积压的日志刷出去。</summary>
    private void FlushLogs()
    {
        if (IsDisposed || !IsHandleCreated)
            return;

        // 一次最多刷这么多行：积压太深时宁可丢掉早期内容，也不能让界面卡住
        const int budget = 200;
        var written = 0;

        while (written < budget && _pendingLogs.TryDequeue(out var line))
        {
            _logView.Append(line);
            written++;
        }

        if (!_pendingLogs.IsEmpty)
            _logView.Append($"…… 日志积压，已略过一批（还有 {_pendingLogs.Count} 行待显示）");
    }

    /// <summary>取（必要时创建）一个受本窗体托管的字体。见 <see cref="_fonts"/> 的说明。</summary>
    private Font FontOf(string family, float size, FontStyle style = FontStyle.Regular)
    {
        var key = (family, size, style);
        if (!_fonts.TryGetValue(key, out var font))
        {
            font = new Font(family, size, style);
            _fonts[key] = font;
        }

        return font;
    }

    /// <summary>
    /// 缩到托盘。
    ///
    /// 这个方法会被 <c>Resize</c> 事件调用（最小化时），而它自己又会引发窗口消息，
    /// 所以要有重入闸 —— 否则一次最小化可能被处理两遍。
    /// </summary>
    private void HideToTray()
    {
        if (_hidingToTray)
            return;

        _hidingToTray = true;
        try
        {
            Hide();
            ShowInTaskbar = false;
            _tray.ShowBalloonTip(1500, "LocalBoost 仍在后台运行",
                "加速服务没有停止。双击托盘图标可以重新打开界面。", ToolTipIcon.Info);
        }
        finally
        {
            _hidingToTray = false;
        }
    }

    private void ShowFromTray()
    {
        Show();
        ShowInTaskbar = true;
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private async Task ExitAsync()
    {
        _exiting = true;
        Enabled = false;

        try
        {
            if (_host is not null)
            {
                _host.Log -= AppendLog;
                await _host.StopAsync();
                _host = null;
            }
        }
        catch
        {
            // 退出阶段吞掉异常，别让窗口关不掉
        }

        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;

        // 先停掉日志冲刷，避免关闭过程中还有回调往已经在销毁的日志视图上写
        _logFlush.Stop();
        _tray.Visible = false;

        // NotifyIcon 不负责回收 Icon 对象，退出前自己释放
        _tray.Icon?.Dispose();
        _tray.Icon = null;
        _tray.Dispose();
        _ca.Dispose();

        Close();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _tray.Visible = false;
        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        base.OnFormClosed(e);
    }

    protected override void Dispose(bool disposing)
    {
        // 顺序刻意如此：先让基类把子控件都释放完，再回收我们自己 new 的字体。
        // 反过来会让还在销毁过程的控件去用已经释放的字体。
        base.Dispose(disposing);

        if (!disposing)
            return;

        _logFlush.Dispose();

        foreach (var font in _fonts.Values)
            font.Dispose();

        _fonts.Clear();
    }
}

/// <summary>
/// 自绘标题栏。放一个 Panel 而不是靠窗口坐标判断，是因为子控件会截获鼠标消息，
/// 直接画在 Panel 上最省心。
/// </summary>
internal sealed class TitleBar : Panel
{
    private bool _hover;
    private bool _dragging;
    private Point _grabPoint;
    private Point _formOrigin;

    public string Title { get; set; } = "";

    public string Subtitle { get; set; } = "";

    public bool Running { get; set; }

    public TitleBar()
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

    /// <summary>告诉标题栏窗口当前是不是玻璃模式，决定悬停底色要不要带透明度。</summary>
    public void Restyle() => Invalidate();

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
        base.OnMouseDown(e);

        if (e.Button != MouseButtons.Left || FindForm() is not { } form)
            return;

        if (form.WindowState == FormWindowState.Maximized)
            return;

        // 自己算位置拖动，不走系统的 WM_NCLBUTTONDOWN + HTCAPTION 移动循环：
        // 那条路依赖窗口有正常的非客户区，而「无边框 + WS_THICKFRAME」的组合下
        // 它并不会真的进入移动循环，表现就是按住标题栏拖不动。
        //
        // 坐标取自鼠标消息本身（e.Location → PointToScreen），不去查 Cursor.Position：
        // 全局查询在快速拖动时可能拿到滞后一帧的值。
        _dragging = true;
        _grabPoint = PointToScreen(e.Location);
        _formOrigin = form.Location;
        Capture = true;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);

        if (!_dragging || FindForm() is not { } form)
            return;

        var current = PointToScreen(e.Location);
        form.Location = new Point(
            _formOrigin.X + (current.X - _grabPoint.X),
            _formOrigin.Y + (current.Y - _grabPoint.Y));
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);

        if (e.Button != MouseButtons.Left)
            return;

        // 用 Capture 保证鼠标拖出标题栏范围后仍能收到移动和抬起的消息
        _dragging = false;
        Capture = false;
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);

        if (e.Button != MouseButtons.Left || FindForm() is not { } form)
            return;

        form.WindowState = form.WindowState == FormWindowState.Maximized
            ? FormWindowState.Normal
            : FormWindowState.Maximized;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var theme = Theme.Current;
        Ui.EnableSmoothing(e.Graphics);

        int S(int px) => Ui.Scale(this, px);

        // 标题栏是窗口顶端的一条：**圆角交给窗口本身（DWM），这里保持直角**。
        // 也不描边 —— 那条 1px 半透明描边会被反复合成到未清空的缓冲区上，
        // 鼠标每进出一次就叠一层，最后在卡片下缘显出一条越来越明显的白线。
        var bounds = new RectangleF(0, 0, Width, Height);
        using (var brush = new SolidBrush(theme.CardFill))
            e.Graphics.FillRectangle(brush, bounds);

        if (_hover)
        {
            using var hover = new SolidBrush(theme.TitleHover);
            e.Graphics.FillRectangle(hover, bounds);
        }

        var dotSize = S(8);
        using (var dotBrush = new SolidBrush(Running ? theme.Success : theme.Idle))
            e.Graphics.FillEllipse(dotBrush, S(18), Height / 2f - dotSize / 2f, dotSize, dotSize);

        // 一律按「量出来的实际高度」做垂直居中，不要写死 Height/2 - 11 这种偏移：
        // 那个偏移是按 100% 缩放调的，150% 下标题会被顶到卡片外面。
        using var titleFont = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold);
        var titleSize = TextRenderer.MeasureText(Title, titleFont, Size.Empty, TextFormatFlags.NoPadding);
        var titleX = S(34);
        TextRenderer.DrawText(
            e.Graphics, Title, titleFont,
            new Point(titleX, (Height - titleSize.Height) / 2), theme.TextPrimary,
            TextFormatFlags.NoPadding);

        // 副标题紧跟在标题实测宽度之后，不靠魔数偏移 —— 否则字宽随 DPI 变化就会压字
        using var subFont = new Font("Microsoft YaHei UI", 8.25F);
        var subSize = TextRenderer.MeasureText(Subtitle, subFont, Size.Empty, TextFormatFlags.NoPadding);
        TextRenderer.DrawText(
            e.Graphics, Subtitle, subFont,
            new Point(titleX + titleSize.Width + S(8), (Height - subSize.Height) / 2),
            theme.TextSecondary, TextFormatFlags.NoPadding);
    }
}

/// <summary>托盘图标用代码画，不依赖外部 ico 文件。</summary>
internal static class TrayIcon
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    public static Icon Create(bool running)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            var color = running ? Color.FromArgb(0x1D, 0x9E, 0x75) : Color.FromArgb(0x88, 0x87, 0x80);
            using var brush = new SolidBrush(color);
            g.FillEllipse(brush, 1, 1, 30, 30);

            using var font = new Font("Segoe UI", 17F, FontStyle.Bold, GraphicsUnit.Pixel);
            using var textBrush = new SolidBrush(Color.White);
            var format = new StringFormat
            {
                Alignment = StringAlignment.Center,
                LineAlignment = StringAlignment.Center,
            };
            g.DrawString("L", font, textBrush, new RectangleF(0, 0, 32, 32), format);
        }

        var handle = bitmap.GetHicon();
        try
        {
            using var temp = Icon.FromHandle(handle);
            return (Icon)temp.Clone();   // Clone 之后才能安全释放原生句柄
        }
        finally
        {
            DestroyIcon(handle);
        }
    }
}
