using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace LocalBoost;

/// <summary>
/// 开关 Windows 的系统代理（走 PAC），并保证能**完整还原**用户原来的设置。
///
/// 还原这件事必须做到位：只记住"设了什么"是不够的，还要记住"原来有没有这个值"。
/// 用户原本没有 AutoConfigURL 的话，关闭时必须把值删掉而不是写个空字符串。
/// 另外快照要落盘 —— 程序被强杀（任务管理器结束进程）时内存里的备份就没了，
/// 下次启动还能凭磁盘上的快照把系统代理改回去。
/// </summary>
public sealed class SystemProxy
{
    private const string SettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;

    /// <summary>会碰到的值。顺序即恢复顺序。</summary>
    private static readonly string[] WatchedValues =
        ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"];

    private readonly string _backupPath;

    public SystemProxy(string storageDir)
    {
        _backupPath = Path.Combine(storageDir, "system-proxy.backup.json");
    }

    /// <summary>PAC 脚本对应的 file:// URL。</summary>
    public static string ToFileUrl(string pacPath) =>
        "file:///" + pacPath.Replace('\\', '/').TrimStart('/');

    /// <summary>当前系统代理是不是已经指向我们的 PAC。</summary>
    public bool IsEnabledTo(string pacPath)
    {
        var current = ReadValue("AutoConfigURL");
        return current.Kind == nameof(RegistryValueKind.String)
               && string.Equals(current.Text, ToFileUrl(pacPath), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 把用户原有的代理设置快照下来（只在还没快照时做，避免把"我们改过的值"当成原始值）。
    /// </summary>
    public void Snapshot()
    {
        if (File.Exists(_backupPath))
            return;

        var saved = WatchedValues.ToDictionary(name => name, ReadValue);
        File.WriteAllText(_backupPath, JsonSerializer.Serialize(saved));
    }

    /// <summary>把系统代理指向本地 PAC。</summary>
    public void Enable(string pacPath)
    {
        Snapshot();

        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey, writable: true)
                        ?? throw new InvalidOperationException("打不开 Internet Settings 注册表键");

        key.SetValue("AutoConfigURL", ToFileUrl(pacPath), RegistryValueKind.String);
        Notify();
    }

    /// <summary>恢复快照里的原始设置，然后删掉快照。返回是否真的做了恢复。</summary>
    public bool Restore()
    {
        if (!File.Exists(_backupPath))
            return false;

        Dictionary<string, SavedValue>? saved;
        try
        {
            saved = JsonSerializer.Deserialize<Dictionary<string, SavedValue>>(File.ReadAllText(_backupPath));
        }
        catch (JsonException)
        {
            // 快照损坏：至少把 AutoConfigURL 清掉，不能把用户永久指在一个失效的 PAC 上
            saved = null;
        }

        using (var key = Registry.CurrentUser.OpenSubKey(SettingsKey, writable: true))
        {
            if (key is null)
                return false;

            if (saved is null)
            {
                key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            }
            else
            {
                foreach (var name in WatchedValues)
                {
                    if (!saved.TryGetValue(name, out var value) || value.Kind is null)
                    {
                        // 原本就没有这个值 → 必须删掉，而不是写空
                        key.DeleteValue(name, throwOnMissingValue: false);
                        continue;
                    }

                    if (value.Kind == nameof(RegistryValueKind.DWord))
                        key.SetValue(name, (int)value.Number!, RegistryValueKind.DWord);
                    else
                        key.SetValue(name, value.Text ?? "", RegistryValueKind.String);
                }
            }
        }

        Notify();
        File.Delete(_backupPath);
        return true;
    }

    /// <summary>
    /// 读用户原有的手工代理，翻译成 PAC 兜底指令。
    /// 返回 false 表示"没有手工代理"或"格式太复杂、翻译不了"（后者要提醒用户会被绕过）。
    /// </summary>
    public static bool TryGetManualProxyDirective(out string directive, out bool wasTooComplex)
    {
        directive = "DIRECT";
        wasTooComplex = false;

        var enable = ReadValue("ProxyEnable");
        if (enable.Kind != nameof(RegistryValueKind.DWord) || (int)enable.Number! != 1)
            return false;

        var server = ReadValue("ProxyServer");
        var text = server.Text?.Trim();
        if (string.IsNullOrEmpty(text))
            return false;

        // "http=1.2.3.4:8080;https=..." 这种按协议分流的写法没法等价翻译成一条 PAC 指令
        if (text.Contains('=') || text.Contains(';'))
        {
            wasTooComplex = true;
            return false;
        }

        directive = text.Contains(':') ? $"PROXY {text}" : $"PROXY {text}:8080";
        return true;
    }

    private static SavedValue ReadValue(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey, writable: false);
        if (key is null || key.GetValue(name) is not { } raw)
            return new SavedValue(null, null, null);

        var kind = key.GetValueKind(name);
        return kind switch
        {
            RegistryValueKind.DWord => new SavedValue(kind.ToString(), null, Convert.ToInt32(raw, CultureInfo.InvariantCulture)),
            _ => new SavedValue(kind.ToString(), raw.ToString(), null),
        };
    }

    /// <summary>通知 WinINET 设置变了，否则已运行的浏览器不会立刻生效。</summary>
    private static void Notify()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);

    private sealed record SavedValue(string? Kind, string? Text, int? Number);
}
