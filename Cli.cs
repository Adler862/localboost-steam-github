namespace LocalBoost;

/// <summary>
/// 命令行子命令。图形界面里的按钮复用这里的同一批方法，避免两套逻辑走偏。
/// </summary>
public static class Cli
{
    /// <summary>hosts 托管区块的开始标记。</summary>
    public const string MarkBegin = "# >>> LocalBoost managed >>>";

    /// <summary>hosts 托管区块的结束标记。</summary>
    public const string MarkEnd = "# <<< LocalBoost managed <<<";

    public static string HostsFilePath => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts")
        : "/etc/hosts";

    public static void PrintUsage()
    {
        Console.WriteLine("""
            LocalBoost - 极简本地加速（仅 Steam + GitHub）

            不带参数直接运行会打开图形界面。也可以用命令行：

              LocalBoost run                 启动本地反代（默认 443 / 80）
              LocalBoost cert install        安装本地根证书到「计算机」信任库（需要管理员）
              LocalBoost cert remove         卸载本地根证书
              LocalBoost cert path           显示密钥材料目录
              LocalBoost hosts install       把规则域名写入 hosts 指向 127.0.0.1（需要管理员）
              LocalBoost hosts remove        清理写入的 hosts 条目
              LocalBoost hosts list          查看 hosts 托管状态（只读，不修改）
              LocalBoost proxy status        查看系统代理与本地代理端口
              LocalBoost proxy install [端口] 开启系统代理（指向本地 PAC）
              LocalBoost proxy remove        还原系统代理
              LocalBoost rules               列出当前规则表
              LocalBoost probe <host>        对某个域名做 IP 优选诊断

            全局参数：
              --rules <路径>                   指定规则文件（默认用程序目录下的 rules.json）

            环境变量：
              LOCALBOOST_RULES                 规则文件路径（优先级低于 --rules）
              LOCALBOOST_HTTPS_PORT            默认 443
              LOCALBOOST_HTTP_PORT             默认 80
              LOCALBOOST_PROXY_PORT            本地 HTTP 代理端口，默认 18080（被占用会自动换端口）
            """);
    }

    public static async Task<int> RunProbeAsync(string[] args, RuleBook rules, IpOptimizer optimizer)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("用法：LocalBoost probe <host>");
            return 1;
        }

        var host = args[1].ToLowerInvariant().Trim();
        if (!rules.TryGet(host, out var rule))
        {
            Console.Error.WriteLine($"{host} 不在规则表内");
            return 1;
        }

        var upstream = RuleBook.UpstreamHostOf(rule, host);
        Console.WriteLine($"规则：{rule.Tag}  上游：{upstream}:{rule.Port}");
        Console.WriteLine($"SNI：{(string.IsNullOrWhiteSpace(rule.ServerName) ? upstream : rule.ServerName)}");
        Console.WriteLine();

        // 诊断视图保留全部候选；线路整体不可达时靠 trace 定位是解析问题还是连通性问题
        var results = await optimizer.DiagnoseAsync(upstream, rule, CancellationToken.None);
        if (results.Count == 0)
        {
            Console.WriteLine("一个候选 IP 都没解析到。采集过程：");
            foreach (var line in optimizer.Trace)
                Console.WriteLine($"  {line}");
            Console.WriteLine();
            Console.WriteLine("如果 DoH 全部失败：本机可能只有走代理才能出站，");
            Console.WriteLine("DoH 客户端跟随系统代理，请确认 HTTPS_PROXY 或系统代理设置可用。");
            return 1;
        }

        // 列宽必须按**显示宽度**补，不能直接用 {0,-18}：中文/全角在等宽字体里占两列，
        // 按字符数补齐会让整张表错位（"--" 和 "不可达" 会挤在一起）。
        Console.WriteLine($"{Pad("IP", 18)}{Pad("耗时", 10, right: true)}  {Pad("证书", 6)}{Pad("数据", 6)}{Pad("状态", 6)}{Pad("体积", 10)}{Pad("说明", 4)}");
        foreach (var r in results)
        {
            var elapsed = r.Reachable ? $"{r.TotalMs,6}ms" : "   --  ";
            var state = r.Reachable ? r.CertificateValid ? "有效" : "无效" : "不可达";
            var data = !r.Reachable ? "--" : r.DataFlowing ? "通" : "不通";
            var status = r.StatusCode?.ToString() ?? "--";
            var size = r.Size?.ToString() ?? "--";

            // 空壳要显式标注：它状态是 200、数据也"通"，不标出来用户看不出问题在哪
            var note = r.Error ?? (r.LooksEmpty ? "⚠ 空壳（状态正常但正文极小）" : "");

            Console.WriteLine($"{Pad(r.Address.ToString(), 18)}{elapsed}  {Pad(state, 6)}{Pad(data, 6)}{Pad(status, 6)}{Pad(size, 10)}{note}");
        }

        Console.WriteLine();

        // 「证书有效但数据不通」是链路层阻断的典型特征：握手能过、一传数据就被重置。
        // 这种情况必须单独说清楚，否则用户看到一排"证书有效"会以为优选结果没问题。
        var flowing = results.Count(r => r.DataFlowing);
        if (flowing == 0 && results.Any(r => r.Reachable))
        {
            Console.WriteLine("⚠ 没有一个候选能真正收到数据：TLS 握手都成功了，但一发请求连接就被重置。");
            Console.WriteLine("  这是链路层阻断的典型特征（不是证书问题，也不是本机配置问题），");
            Console.WriteLine("  换网络（如手机热点）通常能立刻验证。");
            Console.WriteLine();
        }

        // 同一台服务器的不同边缘 IP 表现可能不同：实测 github.com 的出口里
        // 有的返回 200、有的返回 400/403。这种情况要提示，否则用户会以为是网站挂了。
        if (flowing > 0 && !results.Any(r => r.StatusCode is >= 200 and < 400))
        {
            var codes = results.Where(r => r.StatusCode is not null)
                .Select(r => r.StatusCode!.Value).Distinct().OrderBy(c => c);
            Console.WriteLine($"⚠ 所有能连上的出口都返回错误状态（{string.Join(" / ", codes)}），没有一个给出正常响应。");
            Console.WriteLine("  这不是链路问题 —— 直连同一台服务器也会得到相同结果，");
            Console.WriteLine("  通常是出口 IP 被对方限流或拒绝（共享 IP 被邻居牵连时很常见）。");
            Console.WriteLine();
        }

        if (!results[0].Reachable)
        {
            Console.WriteLine("全部候选都连不上。这通常意味着本机直连不到上游（只有代理能出站的网络、");
            Console.WriteLine("或被限制出口）。采集过程：");
            foreach (var line in optimizer.Trace)
                Console.WriteLine($"  {line}");
            return 1;
        }

        // 状态 200 但正文极小（"空壳"）是最隐蔽的一类坏出口：
        // 它连状态码都是对的，探针按老判据会把它和真首页当成等价，然后按耗时选中它，
        // 用户看到的是"能连上、页面全白"。这里必须显式点名。
        var shells = results.Where(r => r.LooksEmpty).ToList();
        if (shells.Count > 0)
        {
            Console.WriteLine($"⚠ 有 {shells.Count} 个出口状态正常但正文极小（空壳），已排到错误状态之后：");
            foreach (var s in shells.Take(4))
                Console.WriteLine($"    {s.Address}  状态 {s.StatusCode}  正文 {s.Size}");
            Console.WriteLine("  这类出口会让浏览器白屏，排查时最容易误判成\"网络问题\"。");
            Console.WriteLine();
        }

        var best = results[0];
        Console.WriteLine($"推荐：{best.Address}（{best.TotalMs}ms，证书{(best.CertificateValid ? "有效" : "无效")}，"
                          + $"数据{(best.DataFlowing ? "通" : "不通")}，状态 {best.StatusCode?.ToString() ?? "无"}）");
        return 0;
    }

    /// <summary>
    /// 按**显示宽度**补空格。
    ///
    /// <c>string.PadRight</c> 数的是字符数，而中日韩文字与全角符号在等宽字体里占两列。
    /// 直接用它补中文列，表头和数据行的竖线会错开 —— 本项目就出现过
    /// "0.205.243.160   --   不可达" 这种挤在一起的输出，看着像数据错了。
    ///
    /// 代理对（emoji 之类）按一个字形算两列，与 <see cref="char.IsSurrogate"/> 的配对规则一致。
    /// </summary>
    internal static string Pad(string text, int width, bool right = false)
    {
        var display = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                display += 2;
                i++;
                continue;
            }

            display += IsWide(text[i]) ? 2 : 1;
        }

        var fill = new string(' ', Math.Max(0, width - display));
        return right ? fill + text : text + fill;
    }

    /// <summary>该字符在等宽终端里是否占两列（CJK、全角形式、全角标点）。</summary>
    private static bool IsWide(char c) =>
        c is >= '\u1100' and <= '\u115F'      // 谚文字母
          or >= '\u2E80' and <= '\u303E'      // 部首扩展、CJK 符号标点
          or >= '\u3041' and <= '\u33FF'      // 假名、注音、CJK 兼容
          or >= '\u3400' and <= '\u4DBF'      // 扩展 A
          or >= '\u4E00' and <= '\u9FFF'      // 基本汉字
          or >= '\uA000' and <= '\uA4CF'      // 彝文
          or >= '\uAC00' and <= '\uD7A3'      // 谚文音节
          or >= '\uF900' and <= '\uFAFF'      // CJK 兼容表意
          or >= '\uFE30' and <= '\uFE4F'      // CJK 兼容形式
          or >= '\uFF00' and <= '\uFF60'      // 全角 ASCII
          or >= '\uFFE0' and <= '\uFFE6';     // 全角符号

    public static void RunRules(RuleBook rules)
    {
        foreach (var rule in rules.Rules)
        {
            Console.WriteLine($"{(rule.Enabled ? "[启用]" : "      ")} {rule.Tag,-16} {string.Join(", ", rule.Hosts)}");
            if (!string.IsNullOrWhiteSpace(rule.Upstream))
                Console.WriteLine($"                 upstream -> {rule.Upstream}");
            if (rule.StaticIps is { Length: > 0 })
                Console.WriteLine($"                 ip -> {string.Join(", ", rule.StaticIps)}");
            if (!string.IsNullOrWhiteSpace(rule.ServerName))
                Console.WriteLine($"                 sni -> {rule.ServerName}");
        }

        PrintWarnings(rules);
    }

    /// <summary>加载期告警统一在这里打出来，命令行与界面共用同一份文案。</summary>
    public static void PrintWarnings(RuleBook rules)
    {
        if (rules.Warnings.Count == 0)
            return;

        Console.WriteLine();
        Console.WriteLine($"规则表有 {rules.Warnings.Count} 条告警：");
        foreach (var warning in rules.Warnings)
            Console.WriteLine($"  ! {warning}");
    }

    public static void RunCert(string[] args, out string message)
    {
        var action = args.Length > 1 ? args[1].ToLowerInvariant() : "install";
        using var ca = new LocalCertAuthority();

        switch (action)
        {
            case "install":
                // 用 EnsureInstalled 而不是 IsRootInstalled + InstallRoot：
                // 后者在"计算机库已装好"时会提前返回，用户库里的历史副本就永远清不掉了。
                var alreadyInstalled = ca.EnsureInstalled();

                message = alreadyInstalled
                    ? "根证书已在「计算机 → 受信任的根证书颁发机构」中，无需重复安装。"
                    : "根证书已安装到「计算机 → 受信任的根证书颁发机构」。";

                message += Environment.NewLine
                         + "浏览器需要完全退出再重开才会读取新的信任库。"
                         + Environment.NewLine
                         + "Chrome/Edge 会缓存 HSTS 策略，已访问过的站点请到 "
                         + "chrome://net-internals/#hsts 里 Delete domain security policies 清掉。";
                return;

            case "remove":
                message = ca.UninstallRoot()
                    ? "已从计算机信任库移除根证书。"
                    : "根证书移除失败，多半是权限不足——请以管理员身份重新运行后重试。"
                      + Environment.NewLine
                      + "（若「当前用户」证书库里还留着一份旧副本，它不影响浏览器，可忽略。）";
                return;

            case "path":
                message = $"密钥材料目录（DPAPI 加密，仅当前 Windows 账户可解密）：{ca.StoragePath}";
                return;

            default:
                message = $"未知动作：{action}";
                return;
        }
    }

    /// <summary>
    /// 系统代理（PAC 方式）的开关。
    ///
    /// PAC 由 ProxyHost 在服务启动时生成；这里的 install 是给"服务已经在跑、
    /// 想从命令行打开系统代理"的场景用的，会按当前 rules.json 重写一遍 PAC。
    /// </summary>
    public static void RunProxy(string[] args, RuleBook rules, out string message)
    {
        var dir = LocalCertAuthority.DefaultStoreDir;
        var pacPath = Path.Combine(dir, "localboost.pac");
        var systemProxy = new SystemProxy(dir);

        var action = args.Length > 1 ? args[1].ToLowerInvariant() : "status";

        switch (action)
        {
            case "status":
                message = (systemProxy.IsEnabledTo(pacPath)
                              ? "系统代理：已指向 LocalBoost 的 PAC"
                              : "系统代理：未开启（也未被本程序改成 PAC 方式）")
                        + Environment.NewLine
                        + $"本地代理端口：{ReadProxyPort(args, dir)}"
                        + Environment.NewLine
                        + $"PAC 文件：{pacPath}";
                return;

            case "install":
                {
                    var port = ReadProxyPort(args, dir);
                    SystemProxy.TryGetManualProxyDirective(out var directive, out _);

                    File.WriteAllText(pacPath, PacScript.Build(rules, port, directive));
                    systemProxy.Enable(pacPath);

                    message = $"已开启系统代理，规则域名走 127.0.0.1:{port}。"
                            + Environment.NewLine
                            + "前提是加速服务正在运行，否则规则域名会打不开。"
                            + Environment.NewLine
                            + "用完执行 LocalBoost proxy remove 还原。";
                    return;
                }

            case "remove":
                message = systemProxy.Restore()
                    ? "已还原系统代理设置。"
                    : "系统代理没有被本程序改过，无需还原。";
                return;

            default:
                message = $"未知动作：{action}（可用 install / remove / status）";
                return;
        }
    }

    /// <summary>
    /// 端口来源优先级：命令行参数 → 服务启动时落盘的端口文件 → 默认端口。
    /// 服务启动时若偏好端口被占用会回退到临时端口，所以必须以落盘值为准。
    /// </summary>
    private static int ReadProxyPort(string[] args, string storageDir)
    {
        if (args.Length > 2 && int.TryParse(args[2], out var explicitPort) && explicitPort is > 0 and < 65536)
            return explicitPort;

        try
        {
            var portFile = Path.Combine(storageDir, "localboost.port");
            if (File.Exists(portFile) && int.TryParse(File.ReadAllText(portFile).Trim(), out var saved)
                && saved is > 0 and < 65536)
            {
                return saved;
            }
        }
        catch (IOException)
        {
            // 读不到就用默认值
        }

        return ProxyHost.DefaultProxyPort;
    }

    /// <summary>写入 hosts，把这些域名指向 127.0.0.1。返回给用户看的说明。</summary>
    public static string InstallHosts(RuleBook rules)
    {
        var lines = ReadHosts(out var path);
        lines = StripManagedBlock(lines);

        // hosts 不支持通配，"*.github.io" 这类只能走系统代理模式
        var exact = rules.EnabledHosts().Where(h => !h.StartsWith("*.", StringComparison.Ordinal)).ToList();
        var wildcards = rules.EnabledHosts().Where(h => h.StartsWith("*.", StringComparison.Ordinal)).ToList();

        lines.Add(MarkBegin);
        foreach (var host in exact)
            lines.Add($"127.0.0.1 {host}");
        lines.Add(MarkEnd);

        File.WriteAllLines(path, lines);

        var text = $"已写入 {exact.Count} 条 hosts：{path}{Environment.NewLine}"
                 + "记得重启浏览器，或执行 ipconfig /flushdns 刷新 DNS 缓存。";

        if (wildcards.Count > 0)
        {
            text += Environment.NewLine + Environment.NewLine
                  + "以下通配域名无法写进 hosts（hosts 不支持通配符），hosts 模式下对它们无效："
                  + Environment.NewLine
                  + $"  {string.Join(", ", wildcards)}";
        }

        return text;
    }

    /// <summary>清理 hosts 里由本工具写入的区块。</summary>
    public static string RemoveHosts()
    {
        var lines = ReadHosts(out var path);
        var cleaned = StripManagedBlock(lines);
        var removed = lines.Count - cleaned.Count;

        File.WriteAllLines(path, cleaned);
        return removed == 0
            ? $"hosts 里没有本工具写入的条目：{path}"
            : $"已清理 {removed} 行 hosts 条目：{path}";
    }

    /// <summary>当前 hosts 里是否已经写入了本工具的区块。</summary>
    public static bool HostsInstalled()
    {
        try
        {
            return ReadHosts(out _).Any(l => l.Trim() == MarkBegin);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 只读地报告 hosts 托管状态。
    /// 注意别把这个动作接到 RemoveHosts 上：用户想"看一眼"结果把条目清了是最糟糕的交互。
    /// </summary>
    public static string DescribeHosts()
    {
        var lines = ReadHosts(out var path);
        var begin = lines.FindIndex(l => l.Trim() == MarkBegin);

        if (begin < 0)
            return $"未写入：{path}（找不到本工具的托管区块）";

        var count = 0;
        while (begin + 1 + count < lines.Count && lines[begin + 1 + count].Trim() != MarkEnd)
            count++;

        return $"已写入 {count} 条规则域名指向 127.0.0.1：{path}";
    }

    private static List<string> ReadHosts(out string path)
    {
        path = HostsFilePath;
        return File.Exists(path) ? File.ReadAllLines(path).ToList() : [];
    }

    /// <summary>
    /// 去掉托管区块（含标记本身）。纯函数，不碰文件系统，所以被单元测试直接覆盖。
    /// 标记不配对（区块未闭合）时会把标记之后的全部内容一并去掉 —— 这是刻意选的方向：
    /// 宁可多删我们自己的区块，也不要留下半截托管内容导致下次重复写入。
    /// </summary>
    internal static List<string> StripManagedBlock(List<string> lines)
    {
        var begin = lines.FindIndex(l => l.Trim() == MarkBegin);
        if (begin < 0)
            return lines;

        var count = 1;
        while (begin + count < lines.Count && lines[begin + count].Trim() != MarkEnd)
            count++;

        lines.RemoveRange(begin, Math.Min(count + 1, lines.Count - begin));
        return StripManagedBlock(lines);
    }
}
