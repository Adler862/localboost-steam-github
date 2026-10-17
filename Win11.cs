using System.Drawing;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace LocalBoost;

/// <summary>
/// Win11 的窗口效果：圆角、深色标题栏、Mica / 亚克力材质，外加系统主题与强调色探测。
///
/// 这里全部是「能应用就应用，不能就静默降级」——在 Win10 或关闭了透明效果的机器上，
/// 调用会失败，界面退回纯色，但程序照常能用。
/// </summary>
internal static class Win11
{
    // ---- DwmSetWindowAttribute 的属性编号
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaWindowCornerPreference = 33;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaSystemBackdropType = 38;

    /// <summary>DWMWA_COLOR_NONE：让 DWM 不画边框。</summary>
    private const uint DwmColorNone = 0xFFFFFFFE;

    private const int DwmwcpRound = 2;

    // dwmapi 的 backdrop 取值
    private const int DwmsbtMainWindow = 2;        // Mica
    private const int DwmsbtTransientWindow = 3;   // 亚克力
    private const int DwmsbtNone = 1;

    // SetWindowCompositionAttribute 的取值（未文档化，Win10 起可用，作为 Mica 的兜底）
    private const int WcaAccentPolicy = 19;
    private const int AccentEnableAcrylicBlurBehind = 4;
    private const int AccentEnableBlurBehind = 3;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("user32.dll")]
    private static extern int SetWindowCompositionAttribute(IntPtr hwnd, ref WindowCompositionAttributeData data);

    [StructLayout(LayoutKind.Sequential)]
    private struct AccentPolicy
    {
        public int AccentState;
        public int AccentFlags;
        public int GradientColor;
        public int AnimationId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowCompositionAttributeData
    {
        public int Attribute;
        public IntPtr Data;
        public int SizeOfData;
    }

    public static bool IsWindows11 => Environment.OSVersion.Version.Build >= 22000;

    // ------------------------------------------------------------ 窗口效果

    /// <summary>标题栏跟着深浅色走，不然深色界面配白色标题栏会很割裂。</summary>
    public static void ApplyTitleBarTheme(IntPtr handle, bool dark)
    {
        var value = dark ? 1 : 0;
        TrySet(handle, DwmwaUseImmersiveDarkMode, value);
    }

    public static void ApplyRoundCorners(IntPtr handle)
    {
        TrySet(handle, DwmwaWindowCornerPreference, DwmwcpRound);
    }

    /// <summary>
    /// 去掉 DWM 给窗口画的那一圈 1px 边框。
    ///
    /// Windows 11 会给活动窗口描一圈亮灰色的边，在深色界面上很扎眼——尤其是
    /// 这种"四周留白 + 浮动卡片"的设计里，它会在卡片外面又框出一个矩形，
    /// 看起来像一条莫名其妙的白边。DWMWA_COLOR_NONE 可以整条去掉。
    /// </summary>
    public static void RemoveWindowBorder(IntPtr handle)
    {
        // 22H2 之前不支持这个属性，失败就保持系统默认
        TrySet(handle, DwmwaBorderColor, unchecked((int)DwmColorNone));
    }

    /// <summary>
    /// 给窗口铺背景材质，返回实际用上的方案名（显示在日志里方便排障）。
    ///
    /// 注意：只有「非 layered」窗口才能吃到这些材质。所以这里绝不能配合
    /// TransparencyKey 使用——那样窗口会退化成 layered，材质和圆角都会一起失效。
    /// </summary>
    public static string ApplyWindowMaterial(IntPtr handle, Color tint, byte tintAlpha)
    {
        if (IsWindows11)
        {
            if (TrySet(handle, DwmwaSystemBackdropType, DwmsbtMainWindow))
                return "Mica";

            if (TrySet(handle, DwmwaSystemBackdropType, DwmsbtTransientWindow))
                return "Acrylic（DWM）";
        }

        return ApplyAcrylicFallback(handle, tint, tintAlpha) ? "Acrylic（旧接口）" : "纯色";
    }

    public static void ClearBackdrop(IntPtr handle)
    {
        TrySet(handle, DwmwaSystemBackdropType, DwmsbtNone);
        ApplyAcrylicFallback(handle, Color.Black, 0, disable: true);
    }

    private static bool ApplyAcrylicFallback(IntPtr handle, Color tint, byte alpha, bool disable = false)
    {
        var policy = new AccentPolicy
        {
            AccentState = disable ? 0 : AccentEnableAcrylicBlurBehind,
            AccentFlags = 2,
            // GradientColor 是 ABGR 排列，不是 ARGB
            GradientColor = (alpha << 24) | (tint.B << 16) | (tint.G << 8) | tint.R,
        };

        var size = Marshal.SizeOf<AccentPolicy>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(policy, ptr, false);
            var data = new WindowCompositionAttributeData
            {
                Attribute = WcaAccentPolicy,
                Data = ptr,
                SizeOfData = size,
            };
            return SetWindowCompositionAttribute(handle, ref data) != 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    private static bool TrySet(IntPtr handle, int attribute, int value)
    {
        try
        {
            return DwmSetWindowAttribute(handle, attribute, ref value, sizeof(int)) == 0;
        }
        catch
        {
            return false;
        }
    }

    // ------------------------------------------------------------ 系统主题

    /// <summary>系统当前是不是深色模式（读的是"应用"而不是"系统"那一项）。</summary>
    public static bool IsSystemDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int light)
                return light == 0;
        }
        catch
        {
            // 读不到就按深色走，反正用户还能看
        }

        return true;
    }

    /// <summary>系统强调色。注册表里是 0xAABBGGRR 排列。</summary>
    public static Color GetAccentColor()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\DWM");
            if (key?.GetValue("AccentColor") is int raw)
            {
                var value = unchecked((uint)raw);
                var r = (byte)(value & 0xFF);
                var g = (byte)((value >> 8) & 0xFF);
                var b = (byte)((value >> 16) & 0xFF);
                var color = Color.FromArgb(r, g, b);

                // 强调色偶尔会撞成太暗或太灰的值，那样按钮会看不见，用默认蓝兜底
                var brightness = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
                if (brightness is > 0.08 and < 0.92 && Math.Abs(r - g) + Math.Abs(g - b) > 24)
                    return color;
            }
        }
        catch
        {
            // 落到默认色
        }

        return Color.FromArgb(0x0F, 0x6C, 0xBD);
    }

    /// <summary>
    /// 把窗口的客户区让给 DWM 材质：不调用这个，Mica 只会出现在标题栏。
    /// -1 表示整个客户区都用窗口材质。
    /// </summary>
    public static void ExtendFrameIntoClientArea(IntPtr handle)
    {
        try
        {
            var margins = new Margins { Left = -1, Right = -1, Top = -1, Bottom = -1 };
            DwmExtendFrameIntoClientArea(handle, ref margins);
        }
        catch
        {
            // 失败就维持普通窗口
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Margins
    {
        public int Left;
        public int Right;
        public int Top;
        public int Bottom;
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd, ref Margins margins);
}
