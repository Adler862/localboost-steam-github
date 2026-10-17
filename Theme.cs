using System.Drawing;

namespace LocalBoost;

/// <summary>
/// 一套跟随系统深浅色的配色。数值是照着 Win11 的实际观感调的，
/// 卡片和控件用带 alpha 的白/黑叠在窗口底色上，出来就是玻璃分层的效果。
/// </summary>
internal sealed class Theme
{
    public required bool IsDark { get; init; }

    public required Color WindowTop { get; init; }
    public required Color WindowBottom { get; init; }

    public required Color TextPrimary { get; init; }
    public required Color TextSecondary { get; init; }

    public required Color CardFill { get; init; }
    public required Color CardStroke { get; init; }

    public required Color Divider { get; init; }

    public required Color ControlFill { get; init; }
    public required Color ControlHover { get; init; }
    public required Color ControlPressed { get; init; }
    public required Color ControlStroke { get; init; }

    public required Color Accent { get; init; }
    public required Color AccentHover { get; init; }
    public required Color AccentPressed { get; init; }
    public required Color AccentText { get; init; }

    public required Color Success { get; init; }
    public required Color Idle { get; init; }
    public required Color Danger { get; init; }

    public required Color TitleHover { get; init; }
    public required Color TitlePressed { get; init; }
    public required Color CloseHover { get; init; }

    /// <summary>材质色调，交给 DWM 当窗口背景用。</summary>
    public required Color BackdropTint { get; init; }

    public static Theme Current { get; private set; } = CreateDark();

    /// <summary>系统主题变化时触发，界面收到后重绘。</summary>
    public static event Action? Changed;

    public static void Refresh(bool dark)
    {
        Current = dark ? CreateDark() : CreateLight();
        Changed?.Invoke();
    }

    private static Theme CreateDark()
    {
        var accent = Win11.GetAccentColor();
        return new Theme
        {
            IsDark = true,

            // 带一点点冷调的深灰，比纯 #202020 更有材质感
            WindowTop = Color.FromArgb(0x26, 0x26, 0x2A),
            WindowBottom = Color.FromArgb(0x1A, 0x1A, 0x1D),

            TextPrimary = Color.FromArgb(0xFF, 0xFF, 0xFF),
            TextSecondary = Color.FromArgb(0xB4, 0xB4, 0xB8),

            // 卡片必须是不透明的：GDI 的半透明绘制在窗口材质区上是与"黑色"混合，
            // 结果不可控。留白处露出的 Mica 才是玻璃感的来源。
            CardFill = Color.FromArgb(0xFF, 0x2A, 0x2A, 0x2E),
            CardStroke = Color.FromArgb(28, 255, 255, 255),

            Divider = Color.FromArgb(18, 255, 255, 255),

            ControlFill = Color.FromArgb(16, 255, 255, 255),
            ControlHover = Color.FromArgb(30, 255, 255, 255),
            ControlPressed = Color.FromArgb(12, 255, 255, 255),
            ControlStroke = Color.FromArgb(24, 255, 255, 255),

            Accent = accent,
            AccentHover = Lighten(accent, 0.12f),
            AccentPressed = Lighten(accent, -0.10f),
            AccentText = Color.White,

            Success = Color.FromArgb(0x6C, 0xCB, 0x5F),
            Idle = Color.FromArgb(0xA6, 0xA6, 0xAC),
            Danger = Color.FromArgb(0xFF, 0x99, 0xA4),

            TitleHover = Color.FromArgb(22, 255, 255, 255),
            TitlePressed = Color.FromArgb(12, 255, 255, 255),
            CloseHover = Color.FromArgb(0xC4, 0x2B, 0x1C),

            BackdropTint = Color.FromArgb(0x20, 0x20, 0x20),
        };
    }

    private static Theme CreateLight()
    {
        var accent = Win11.GetAccentColor();
        return new Theme
        {
            IsDark = false,

            WindowTop = Color.FromArgb(0xF6, 0xF6, 0xF8),
            WindowBottom = Color.FromArgb(0xEC, 0xEC, 0xEF),

            TextPrimary = Color.FromArgb(0x1A, 0x1A, 0x1A),
            TextSecondary = Color.FromArgb(0x5E, 0x5E, 0x62),

            // 浅色下卡片要提亮，靠不透明的白把层次拉开
            CardFill = Color.FromArgb(0xFF, 0xFC, 0xFC, 0xFE),
            CardStroke = Color.FromArgb(24, 0, 0, 0),

            Divider = Color.FromArgb(16, 0, 0, 0),

            ControlFill = Color.FromArgb(190, 255, 255, 255),
            ControlHover = Color.FromArgb(240, 255, 255, 255),
            ControlPressed = Color.FromArgb(150, 255, 255, 255),
            ControlStroke = Color.FromArgb(28, 0, 0, 0),

            Accent = accent,
            AccentHover = Lighten(accent, 0.10f),
            AccentPressed = Lighten(accent, -0.10f),
            AccentText = Color.White,

            Success = Color.FromArgb(0x0F, 0x7B, 0x0F),
            Idle = Color.FromArgb(0x8A, 0x8A, 0x8E),
            Danger = Color.FromArgb(0xC4, 0x2B, 0x1C),

            TitleHover = Color.FromArgb(18, 0, 0, 0),
            TitlePressed = Color.FromArgb(10, 0, 0, 0),
            CloseHover = Color.FromArgb(0xC4, 0x2B, 0x1C),

            BackdropTint = Color.FromArgb(0xF3, 0xF3, 0xF3),
        };
    }

    private static Color Lighten(Color color, float amount)
    {
        float r = color.R, g = color.G, b = color.B;

        if (amount >= 0)
        {
            r += (255 - r) * amount;
            g += (255 - g) * amount;
            b += (255 - b) * amount;
        }
        else
        {
            r *= 1 + amount;
            g *= 1 + amount;
            b *= 1 + amount;
        }

        return Color.FromArgb(color.A, (int)r, (int)g, (int)b);
    }
}
