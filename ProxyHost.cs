using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Forwarder;

namespace LocalBoost;

/// <summary>
/// 本地反代的宿主。命令行和图形界面都通过它启停服务，逻辑只此一份。
///
/// 用 StartAsync 而不是 RunAsync：图形界面里不能阻塞。
/// </summary>
public sealed class ProxyHost
{
    /// <summary>本地 HTTP 代理的偏好端口。被占用时会退到系统分配的临时端口。</summary>
    public const int DefaultProxyPort = 18080;

    private readonly RuleBook _rules;
    private readonly IpOptimizer _optimizer;
    private readonly LocalCertAuthority _ca;
    private readonly UpstreamConnector _connector;
    private readonly SystemProxy _systemProxy;

    private WebApplication? _app;
    private ExitInvoker? _invoker;
    private LocalProxy? _proxy;

    /// <summary>已经提示过"拒绝签发"的 SNI。见证书选择器里的说明。</summary>
    private readonly ConcurrentDictionary<string, byte> _refusedSni = new();

    public ProxyHost(
        RuleBook rules,
        IpOptimizer optimizer,
        LocalCertAuthority ca,
        int httpsPort,
        int httpPort,
        int proxyPort = DefaultProxyPort)
    {
        _rules = rules;
        _optimizer = optimizer;
        _ca = ca;
        _connector = new UpstreamConnector(optimizer, rules);
        _systemProxy = new SystemProxy(LocalCertAuthority.DefaultStoreDir);
        HttpsPort = httpsPort;
        HttpPort = httpPort;
        PreferredProxyPort = proxyPort;
    }

    /// <summary>运行期日志（启动、转发、预热、错误）。可能在后台线程触发，界面侧自行切线程。</summary>
    public event Action<string>? Log;

    public bool IsRunning => _app is not null;

    public int HttpsPort { get; }

    public int HttpPort { get; }

    private int PreferredProxyPort { get; }

    /// <summary>实际生效的本地代理端口。服务启动后才有意义。</summary>
    public int ProxyPort => _proxy?.Port ?? PreferredProxyPort;

    /// <summary>生成的 PAC 脚本路径。</summary>
    public string PacPath => Path.Combine(LocalCertAuthority.DefaultStoreDir, "localboost.pac");

    /// <summary>
    /// 实际端口落盘。命令行里的 <c>proxy</c> 子命令是另一个进程，
    /// 得靠这个文件才知道服务真正监听在哪个端口（偏好端口可能被占用而回退）。
    /// </summary>
    public string PortFilePath => Path.Combine(LocalCertAuthority.DefaultStoreDir, "localboost.port");

    /// <summary>系统代理当前是否指向我们的 PAC。</summary>
    public bool IsSystemProxyEnabled => _systemProxy.IsEnabledTo(PacPath);

    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_app is not null)
            return;

        var builder = WebApplication.CreateSlimBuilder(Array.Empty<string>());
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Server.Kestrel", LogLevel.Error);

        // 转发失败时 YARP 会打一整段异常堆栈（连内部调用栈一起），而下面我们自己的
        // 处理里已经用一行简明日志报了同样的信息（含 ForwarderError 代码）。
        // 两处重复只会把界面日志区刷满，还把真正有用的那行挤掉。
        builder.Logging.AddFilter("Yarp.ReverseProxy.Forwarder.HttpForwarder", LogLevel.None);

        // 443 是命脉：hosts 模式全靠它接住浏览器的请求，不可用就没法工作
        if (!IsPortFree(HttpsPort))
            throw new InvalidOperationException($"无法监听 {HttpsPort} 端口。{Environment.NewLine}{Environment.NewLine}{DescribePortProblem(HttpsPort)}");

        // 80 只是让 http:// 也能进得来，Steam 和 GitHub 都是全站 HTTPS，
        // 而且这个端口常被 Hyper-V / WSL / Docker 的保留段占掉——缺了不影响加速。
        var plainHttpAvailable = IsPortFree(HttpPort);

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Loopback, HttpsPort, listen =>
            {
                // 按 SNI 动态返回对应域名的证书，这是本地 MITM 反代的关键
                listen.UseHttps(https =>
                {
                    https.ServerCertificateSelector = (connection, host) =>
                    {
                        if (string.IsNullOrEmpty(host))
                            return null;

                        // 只给规则表内的域名签发。否则本机任何进程连上 127.0.0.1:443
                        // 报一个随机 SNI，就能让我们白签一张 RSA-2048 证书并永久缓存 ——
                        // 既是 CPU 消耗，也让证书缓存无界增长。
                        if (!_rules.TryGet(host, out _))
                        {
                            // 同一个 SNI 只提示一次。
                            //
                            // 实测有域名会被解析到 127.0.0.1 —— 例如 dns.sb 自己的 DoH 域名
                            // doh.dns.sb，它故意把自己的域名黑洞化（返回 127.0.0.1 / ::1），
                            // 用来让使用者意识到 DNS 被污染了。于是本机的 DoH 客户端每隔几秒
                            // 就来敲一次我们的 443，逐条打日志会把日志区刷满，
                            // 反而让人以为程序出了故障。
                            if (_refusedSni.TryAdd(host, 0))
                            {
                                Note($"[证书] 拒绝签发：{host} 不在规则表内"
                                   + "（同名请求不再逐条提示；这通常意味着某个程序把该域名解析到了本机）");
                            }

                            return null;
                        }

                        try
                        {
                            return _ca.GetOrIssue(host);
                        }
                        catch (Exception ex)
                        {
                            Note($"[证书] 签发失败 {host}：{ex.Message}");
                            return null;
                        }
                    };
                });
            });

            if (plainHttpAvailable)
                kestrel.Listen(IPAddress.Loopback, HttpPort);
        });

        builder.Services.AddHttpForwarder();
        builder.Services.AddSingleton(_rules);
        builder.Services.AddSingleton(_optimizer);
        _invoker = new ExitInvoker(_connector);
        _invoker.Log += Note;
        builder.Services.AddSingleton(_invoker);

        var app = builder.Build();
        app.Urls.Clear();

        app.Map("{**catch-all}", async context =>
        {
            var host = context.Request.Host.Host.TrimEnd('.');
            if (!_rules.TryGet(host, out var rule))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("LocalBoost: 该域名不在加速规则表内");
                return;
            }

            var upstream = RuleBook.UpstreamHostOf(rule, host);
            var scheme = rule.Port == 443 ? "https" : "http";
            var destination = $"{scheme}://{upstream}/";

            var forwarder = context.RequestServices.GetRequiredService<IHttpForwarder>();

            // 接住"空壳出口"：某些边缘 IP 会建连成功、TLS 成功、回 200，
            // 正文却只有几个字节。它不触发建连 failover，用户看到的是白屏。
            // 这里量转发出去的字节数，转发结束后把肇事 IP 标进冷却，让下一次请求换出口。
            var stub = StubDetector.Attach(context);

            var started = DateTime.Now;
            ForwarderError error;
            try
            {
                error = await forwarder.SendAsync(
                    context,
                    destination,
                    _invoker.Instance,
                    new ForwarderRequestConfig
                    {
                        // 上游一律尝试 HTTP/2，不支持时自动回落到 HTTP/1.1。
                        //
                        // **为什么不能钉死 HTTP/1.1**：实测同一个 GitHub 边缘出口
                        // （20.205.243.166）在强制 HTTP/1.1 时返回 `200 OK` 但正文
                        // **0 字节**并挂到超时；而协商过 ALPN 的请求同一 IP 返回
                        // **572,394 字节真首页**。浏览器自然是走 HTTP/2 的，
                        // 钉死 1.1 等于主动把自己降级到一条"会被空壳化"的路径上。
                        //
                        // 出口侧由 UpstreamConnector 完成 TLS 并声明 ALPN，
                        // 所以协商到 h2 时链路是真的能用 h2，不会出现
                        // "宣称 h2 却发 1.1 帧"的错配。
                        Version = HttpVersion.Version20,
                        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
                        ActivityTimeout = TimeSpan.FromMinutes(5),
                    },
                    PreserveHostTransformer.Instance);

                // 转发完成后才拿得到上游的真实状态码。空壳判据必须基于它，
                // 否则一直是默认的 200（见 StubTracker.StatusCode 的说明）。
                stub.Seal(context.Response.StatusCode);
            }
            finally
            {
                stub.Detach(context);
            }

            // 转发层只处理**空壳**：状态 2xx 但正文只有几个字节（用户看到白屏）。
            // 判据是确定的，可以放心标记。
            //
            // **刻意不处理 4xx/5xx**：那类状态码语义模糊 ——
            // 实测 api.github.com 的根路径就合法地返回 404，而 `GET /` 回 400
            // 的出口在别的请求上给过正常内容。本项目两次试图"顺手把错误状态也标记掉"
            // 都以误伤正常出口收场，所以这里只做有确定判据的那一件事。
            var status = stub.StatusCode;

            if (error == ForwarderError.None && stub.LooksLikeStub())
            {
                var size = stub.DeclaredLength is { } d
                    ? $"声明 {d} 字节"
                    : $"实收 {stub.Bytes} 字节";

                // **只标记 1 个候选**，不按连接层的尝试数批量标。
                //
                // 曾经一次标 3 个（= MaxAttempts），实测后果是整个候选池被一次拉黑：
                // 一次空壳事故就标掉 3 个、加上回退路径用掉的那个，池子直接见底，
                // 接下来的请求只能去试恒回 400 的出口。一次标一个虽然收敛慢，
                // 但不会把可用出口一起误伤 —— 而这个工具真正的病就是"误伤可用出口"。
                var demoted = await _optimizer.DemoteTopCandidatesAsync(
                    upstream,
                    rule,
                    1,
                    context.RequestAborted,
                    // 预检确认过可用的出口不许被标记 —— 见 PreflightCheck.WasConfirmedGood。
                    // 少了这道保护就会标错对象：把唯一能用的出口标掉、
                    // 真正回空壳的那个反而逃过，于是每次请求都继续选中它。
                    isProtected: ip => _connector.Preflight.WasConfirmedGood(upstream, ip));

                // 同时写进预检缓存：下一轮请求在**预检阶段**就会把它排除，
                // 不必再等一次白屏。这是把"事后补救"提前成"事前拦截"。
                foreach (var ip in demoted)
                    _connector.Preflight.MarkBad(upstream, ip);

                Note(demoted.Count > 0
                    ? $"[{rule.Tag}] {host} 空壳响应（状态 {status}，{size}），"
                      + $"已标记出口 {string.Join(", ", demoted)}，下次请求会换"
                    : $"[{rule.Tag}] {host} 空壳响应（状态 {status}，{size}），但没有候选可标记");
            }

            // 这里**不要**因为转发失败就去作废优选结果。试过了，在抖动网络上是有害的：
            // 一次失败 → 作废缓存 → 下次请求要重新做完整的多源采集与候选探测（实测 20~60 秒）
            // → 期间同域名的请求全排在信号量上干等 → 产生更多超时 → 继续作废，形成颠簸。
            // 实测加上它之后连原本正常的 github.com 都变成 504。
            var mark = error == ForwarderError.None ? "" : $" [{error}]";
            var exit = _invoker.LastExit ?? "无可用出口";
            Note($"[{rule.Tag}] {host} → {exit}{mark}");

            if (error != ForwarderError.None)
                await WriteUpstreamFailurePageAsync(context, host, error, Note);
        });

        try
        {
            await app.StartAsync(ct);
        }
        catch
        {
            // 启动失败必须在这里自己收尾：此时 _app 还没赋值，
            // StopAsync 会认为"没在运行"直接返回，于是这套 WebApplication
            // 和 HttpMessageInvoker 就永久泄漏了 —— 每次重试都会再漏一套。
            _invoker?.Dispose();
            _invoker = null;

            try { await app.DisposeAsync(); }
            catch { /* 清理阶段的异常不覆盖原始错误 */ }

            throw;
        }

        _app = app;

        foreach (var warning in _rules.Warnings)
            Note($"[规则] {warning}");

        StartLocalProxy();

        Note($"已启动，监听 127.0.0.1:{HttpsPort}"
             + (plainHttpAvailable
                 ? $"（明文 {HttpPort}）"
                 : $"（{HttpPort} 端口不可用，已跳过明文监听，不影响 HTTPS 加速）")
             + $"，生效域名 {_rules.EnabledHosts().Count()} 个");

        // 后台预热：先把规则里所有域名的最优 IP 算出来。
        // 不做这步，第一个请求要和 20 秒的连接超时预算抢时间做探测。
        _ = WarmUpAsync();
    }

    /// <summary>
    /// 候选出口全部连不上时，给浏览器一个能看懂的说明页。
    ///
    /// 默认情况下 YARP 只返回一个光秃秃的 502，浏览器把它渲染成通用的
    /// 「此网页无法正常运作 / 当前无法处理此请求」—— 使用者根本分不清是
    /// 本地加速服务坏了、目标站点挂了、还是自己这条线路到那段 IP 不通。
    /// 这是本工具最主要的失败模式（线路抖动是常态），所以值得明说。
    /// </summary>
    private static async Task WriteUpstreamFailurePageAsync(
        HttpContext context, string host, ForwarderError error, Action<string> note)
    {
        // 已经开始回响应体了就不能再改（理论上失败时还没写，但别赌）
        if (context.Response.HasStarted)
        {
            note($"[{host}] 转发失败但响应已开始，无法附加说明页（{error}）");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status502BadGateway;
        context.Response.ContentType = "text/html; charset=utf-8";

        var html = $$"""
            <!DOCTYPE html>
            <html lang="zh-CN"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{{host}} 暂时连不上 · LocalBoost</title>
            <style>
              :root { color-scheme: light dark; }
              body { margin:0; padding:56px 24px; line-height:1.75;
                     font-family:"Microsoft YaHei UI","Segoe UI",system-ui,sans-serif;
                     background:#f6f6f8; color:#1a1a1a; }
              main { max-width:640px; margin:0 auto; }
              h1 { font-size:20px; margin:0 0 16px; }
              .host { color:#0b5cad; }
              p, li { color:#444; margin:12px 0; }
              ul { padding-left:22px; }
              code { background:#e8e8ee; padding:2px 6px; border-radius:4px;
                     font-family:Consolas,monospace; font-size:13px; }
              .note { border-left:3px solid #c8c8d0; padding-left:12px;
                      color:#777; font-size:13px; }
              @media (prefers-color-scheme: dark) {
                body { background:#1f1f23; color:#e8e8ea; }
                .host { color:#8ab4f8; }
                p, li { color:#b9b9be; }
                code { background:#2a2a2e; }
                .note { border-left-color:#5a5a60; color:#9a9aa0; }
              }
            </style></head>
            <body><main>
              <h1><span class="host">{{host}}</span> 暂时连不上</h1>

              <p>本地加速服务已经接管了这个域名，但<b>优选出来的出口 IP 全部连接失败</b>，
                 请求没能转发出去。</p>

              <p>这通常说明当前线路到该站点所在的 IP 段不通（时段性抖动或网络管制），
                 <b>不是这个网站本身挂了，也不是证书或配置问题</b>。</p>

              <ul>
                <li>稍等一会儿刷新重试 —— 出口每次都会重新测速挑选，网络恢复后会自动变好</li>
                <li>换个网络（手机热点等）能立刻区分是不是本地线路的问题</li>
                <li>不想等的话，可以在界面里关掉加速并执行 <code>hosts remove</code> 恢复直连</li>
              </ul>

              <p class="note">
                错误类型：{{error}}<br>
                想自己看每个候选 IP 的探测结果：<code>LocalBoost.exe probe {{host}}</code>
              </p>
            </main></body></html>
            """;

        try
        {
            await context.Response.WriteAsync(html, context.RequestAborted);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            // 客户端提前断开（用户按了停止或刷新）时就别管了
        }
    }

    public async Task StopAsync()
    {
        if (_app is null)
            return;

        var app = _app;
        _app = null;

        try
        {
            await app.StopAsync(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // 停止阶段的异常不影响最终状态
        }

        try
        {
            await app.DisposeAsync();
        }
        catch
        {
            // 同上
        }

        _invoker?.Dispose();
        _invoker = null;

        _proxy?.Dispose();
        _proxy = null;

        try
        {
            File.Delete(PortFilePath);
        }
        catch (IOException)
        {
            // 删不掉只是留下一个过期的端口文件，不影响功能
        }

        // 停服务时必须把系统代理还回去：否则整个系统会被指在一个
        // 已经没人监听的 PAC 上，规则域名全部打不开，而且用户很难想到是这里。
        if (_systemProxy.Restore())
            Note("已还原系统代理设置");

        Note("已停止");
    }

    /// <summary>
    /// 起本地 HTTP 代理并生成 PAC。
    ///
    /// 代理监听失败不该拖垮整个服务：hosts 模式（443）仍是主力，
    /// 代理只是额外覆盖通配域名和不走 hosts 的程序。
    /// </summary>
    private void StartLocalProxy()
    {
        try
        {
            _proxy = new LocalProxy(_rules, _connector, PreferredProxyPort);
            _proxy.Log += Note;
            _proxy.Start();

            // 用户本来配着手工代理时，PAC 的兜底必须沿用那个代理，
            // 不能替成 DIRECT —— 那等于顺手改掉了用户其余所有流量的走向。
            var hasManual = SystemProxy.TryGetManualProxyDirective(out var directive, out var tooComplex);
            File.WriteAllText(PacPath, PacScript.Build(_rules, _proxy.Port, directive));
            File.WriteAllText(PortFilePath, _proxy.Port.ToString());

            Note($"[代理] 本地 HTTP 代理已监听 127.0.0.1:{_proxy.Port}（不必装根证书，CONNECT 是端到端直通）");

            if (hasManual)
                Note($"[代理] 检测到原有手工代理，规则域名之外的流量仍按「{directive}」走");
            else if (tooComplex)
                Note("[代理] 原有手工代理是按协议分流的复杂格式，PAC 无法等价表达；"
                   + "开启系统代理后，规则域名之外的流量会变成直连");
        }
        catch (Exception ex)
        {
            _proxy?.Dispose();
            _proxy = null;
            Note($"[代理] 本地 HTTP 代理启动失败（hosts 模式不受影响）：{ex.Message}");

            // 之前若开过系统代理，现在必须关掉，不然流量会被指向一个失效的代理
            if (_systemProxy.IsEnabledTo(PacPath))
            {
                _systemProxy.Restore();
                Note("[代理] 已还原系统代理，避免把流量指向失效的本地代理");
            }
        }
    }

    /// <summary>把系统代理指向本地 PAC。返回给用户看的说明。</summary>
    public string EnableSystemProxy()
    {
        if (_proxy is null)
            throw new InvalidOperationException("本地代理没起来，先点「一键加速」再开系统代理");

        var hasManual = SystemProxy.TryGetManualProxyDirective(out var directive, out var tooComplex);
        File.WriteAllText(PacPath, PacScript.Build(_rules, _proxy.Port, directive));
        _systemProxy.Enable(PacPath);

        var text = $"系统代理已指向本地 PAC，代理端口 {_proxy.Port}。"
                 + "浏览器新建的连接会自动生效，已打开的标签页刷新一次即可。";

        if (hasManual)
            text += Environment.NewLine + $"规则域名之外的流量仍按你原有的「{directive}」走。";
        else if (tooComplex)
            text += Environment.NewLine + Environment.NewLine
                  + "注意：你原本配置了按协议分流的手工代理，PAC 没法等价表达，"
                  + "已让规则域名之外的全部流量直连。如需两者共存请手工调整 PAC。";
        else
            text += Environment.NewLine + "规则域名之外一律直连。";

        return text;
    }

    /// <summary>还原系统代理设置。</summary>
    public string DisableSystemProxy() =>
        _systemProxy.Restore()
            ? "已把系统代理还原成开启前的设置。"
            : "系统代理没有被本程序改过，无需还原。";

    private async Task WarmUpAsync()
    {
        var pairs = _rules.Rules
            .Where(r => r.IsEnabled)
            .SelectMany(r => r.Hosts
                .Where(h => !h.StartsWith("*.", StringComparison.Ordinal))
                .Select(h => (Rule: r, Host: h)))
            .ToList();

        if (pairs.Count == 0)
            return;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        try
        {
            await Parallel.ForEachAsync(
                pairs,
                new ParallelOptions { MaxDegreeOfParallelism = 5, CancellationToken = cts.Token },
                async (pair, token) =>
                {
                    try { await _optimizer.ResolveBestAsync(pair.Host, pair.Rule, token); }
                    catch { /* 预热失败无所谓，正式请求时会重试 */ }
                });
        }
        catch
        {
            // 超时也无所谓，认到的域名已经进缓存了
        }

        Note($"预热完成，已为 {pairs.Count} 个域名算好优选 IP");
    }

    private void Note(string message) => Log?.Invoke($"{DateTime.Now:HH:mm:ss} {message}");

    /// <summary>探测端口能不能绑定。探测完立刻释放，所以存在极小的竞态窗口。</summary>
    private static bool IsPortFree(int port)
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.Loopback, port));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>
    /// 端口绑不上时给一份可操作的排查清单。
    /// 最常见的其实是 Hyper-V / WSL / Docker 把端口划进了保留段，
    /// 这种情况下 netstat 查不到任何占用者，容易让人一头雾水。
    /// </summary>
    private static string DescribePortProblem(int port) => $"""
        可能的原因，按常见程度排序：

        1) 被 Hyper-V / WSL / Docker 的保留端口段占掉了。
           这种情况 netstat 看不到任何进程，查保留段：
             netsh interface ipv4 show excludedportrange protocol=tcp
           释放办法（管理员执行，会重启 WSL 的网络）：
             net stop winnat
             net start winnat

        2) 被其它程序占用（VMware、IIS、Skype 都可能），查一下：
             netstat -ano | findstr :{port}

        3) 被安全软件拦截。
        """;
}
