using System.Runtime.InteropServices;
using System.Text;

namespace LocalBoost;

/// <summary>
/// 程序入口：不带参数开图形界面，带参数走命令行。
/// 两种模式共用 ProxyHost 和 Cli，逻辑只有一份。
/// </summary>
internal static class Program
{
    private const int AttachParentProcess = -1;

    [STAThread]
    private static int Main(string[] args)
    {
        var rulesPath = Path.Combine(AppContext.BaseDirectory, "rules.json");

        if (!File.Exists(rulesPath))
        {
            const string missing = "找不到 rules.json，请确认它和程序在同一个目录。";
            if (args.Length == 0)
                MessageBox.Show(missing, "LocalBoost", MessageBoxButtons.OK, MessageBoxIcon.Error);
            else
                Console.Error.WriteLine(missing);
            return 1;
        }

        return args.Length == 0
            ? RunGui(rulesPath)
            : RunCli(args, rulesPath);
    }

    // ------------------------------------------------------------ 图形界面

    private static int RunGui(string rulesPath)
    {
        // manifest 里已经声明了 PerMonitorV2，这里再设一次是保险：
        // 若用 `dotnet LocalBoost.dll` 启动，进程读的是宿主 dotnet.exe 的清单，
        // 我们自己的 DPI 声明不生效，界面会被系统位图拉伸（变糊且坐标错位）。
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        try
        {
            Application.Run(new MainForm(rulesPath));
        }
        catch (Exception ex)
        {
            MessageBox.Show($"启动失败：{ex.Message}", "LocalBoost",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        return 0;
    }

    // ------------------------------------------------------------ 命令行

    private static int RunCli(string[] args, string rulesPath)
    {
        AttachConsoleToParent();
        TrySetUtf8Output();

        var command = args[0].ToLowerInvariant();

        try
        {
            var rules = RuleBook.Load(rulesPath);
            var optimizer = new IpOptimizer();

            switch (command)
            {
                case "help" or "-h" or "--help":
                    Cli.PrintUsage();
                    return 0;

                case "rules":
                    Cli.RunRules(rules);
                    return 0;

                case "probe":
                    return Cli.RunProbeAsync(args, rules, optimizer).GetAwaiter().GetResult();

                case "cert":
                    Cli.RunCert(args, out var certMessage);
                    Console.WriteLine(certMessage);
                    return 0;

                case "hosts":
                    return RunHostsCommand(args, rules);

                case "proxy":
                    Cli.RunProxy(args, rules, out var proxyMessage);
                    Console.WriteLine(proxyMessage);
                    return 0;

                case "run":
                    return RunServerAsync(rules, optimizer).GetAwaiter().GetResult();

                default:
                    Console.Error.WriteLine($"未知命令：{command}");
                    Cli.PrintUsage();
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"执行失败：{ex.Message}");
            return 1;
        }
    }

    private static int RunHostsCommand(string[] args, RuleBook rules)
    {
        var action = args.Length > 1 ? args[1].ToLowerInvariant() : "list";

        try
        {
            switch (action)
            {
                case "install":
                    Console.WriteLine(Cli.InstallHosts(rules));
                    return 0;
                case "remove":
                    Console.WriteLine(Cli.RemoveHosts());
                    return 0;
                case "list":
                    Console.WriteLine(Cli.DescribeHosts());
                    return 0;
                default:
                    Console.Error.WriteLine($"未知动作：{action}（可用 install / remove / list）");
                    return 1;
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("没有写入权限，请以管理员身份重新运行。");
            return 1;
        }
    }

    private static async Task<int> RunServerAsync(RuleBook rules, IpOptimizer optimizer)
    {
        using var ca = new LocalCertAuthority();

        Console.WriteLine($"密钥材料：{ca.StoragePath}");
        Console.WriteLine($"已安装到计算机信任库：{(ca.IsRootInstalled() ? "是" : "否（先执行 LocalBoost cert install）")}");

        Cli.PrintWarnings(rules);

        var host = new ProxyHost(
            rules, optimizer, ca,
            ReadPort("LOCALBOOST_HTTPS_PORT", 443),
            ReadPort("LOCALBOOST_HTTP_PORT", 80),
            ReadPort("LOCALBOOST_PROXY_PORT", ProxyHost.DefaultProxyPort));

        host.Log += Console.WriteLine;

        var stopped = new TaskCompletionSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stopped.TrySetResult();
        };

        try
        {
            await host.StartAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"监听失败：{ex.Message}");
            Console.Error.WriteLine("通常是 443 端口被占用。VMware、IIS、Skype 都会占它，");
            Console.Error.WriteLine("可以先用 netstat -ano | findstr :443 查一下。");
            return 2;
        }

        Console.WriteLine("Ctrl+C 停止");
        await stopped.Task;
        await host.StopAsync();
        return 0;
    }

    private static int ReadPort(string name, int fallback) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;

    // ------------------------------------------------------------ 控制台附着的杂活

    /// <summary>
    /// 程序编译成 WinExe（双击不开黑框），从命令行运行时没有控制台可写，
    /// 这里附着到父进程的控制台，probe / rules 这些命令才有输出。
    /// </summary>
    private static void AttachConsoleToParent()
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            if (!AttachConsole(AttachParentProcess))
                return;

            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
        }
        catch
        {
            // 附着不上就静默降级，不影响功能
        }
    }

    private static void TrySetUtf8Output()
    {
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
        }
        catch
        {
            // 没有控制台时设编码会抛，忽略
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int processId);
}
