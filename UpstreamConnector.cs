using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace LocalBoost;

/// <summary>
/// 「按优选 IP 建一条到上游的连接」的唯一实现。
///
/// 两条路径都走这里，不要再各写一份：
///   - MITM 反代（<see cref="ExitInvoker"/>）：需要 TLS，可改写 SNI；
///   - CONNECT 盲隧道（<see cref="LocalProxy"/>）：只要裸 TCP，TLS 由客户端自己完成。
///
/// 候选筛选、逐个 failover、私网过滤、系统 DNS 回退这些都是易错逻辑，
/// 抄成多份的话改一处漏一处（本项目已经因为两处过滤规则不一致吃过亏）。
/// </summary>
public sealed class UpstreamConnector
{
    /// <summary>
    /// 一次连接请求里最多试几个候选。
    ///
    /// **这个值从 3 提到 8 是实测定下来的，别调回去**：
    /// 实测 github.com 的候选池里多数出口已被 GitHub 拉黑
    /// （`.161`/`.165`/`.168` 回 400 Whoa there、`.167` 回 403、`.162` 回 404），
    /// 少数时通时断，而**唯一稳定的干净出口 `.166` 常常排在候选表第 2~8 位**。
    /// 只试 3 个就会在碰到它之前放弃，用户看到失败页 ——
    /// 而对手（Watt Toolkit）在同一个请求里把候选试到 6 遍，所以它总能碰上。
    /// 这就是"为什么 Watt 连得上、LocalBoost 连不上"的直接原因。
    ///
    /// 提到 8 的代价很小：一次连接 + TLS 握手实测只要 **~200ms**，
    /// 8 个全试一遍也就 1.6 秒左右（只有遇到"SYN 黑洞"才会各耗满
    /// <see cref="PerAttemptTimeout"/>）。**真正该收紧的是"等正文"的窗口，
    /// 不是"试几个"** —— 这两件事早先被混为一谈了。
    /// </summary>
    public const int MaxAttempts = 8;

    /// <summary>
    /// 单个候选 IP 的建连预算（TCP + TLS 握手 + ALPN），必须独立于调用方的 ConnectTimeout。
    /// 否则第一个 IP 如果是"SYN 无响应"（不发 RST 的黑洞），它会一直耗到
    /// 调用方的总超时，后面的 failover 根本没机会执行。
    ///
    /// **别再把这里往回收。** 曾经从 5 秒收到 3 秒，理由是"跨境握手正常 200~400ms" ——
    /// 但这条线路上的实测数据不支持这个前提：真首页出口 `20.205.243.166` 的
    /// "建连 + TLS 握手"落在 **225ms ~ 2454ms**，抖动时更久，于是它经常踩线超时；
    /// 再叠加"超时即拉黑"的旧逻辑，**唯一可用的出口被自己排除掉了**，
    /// 用户侧表现为错误页或 502（日志实证：
    /// `[预检] …未能确认可用出口，改由真实请求直接试 20.205.243.162` →
    /// `无可用出口 [RequestTimedOut]`，而 `.162` 是那个回 404 的坏出口）。
    ///
    /// 取 8 秒：足以覆盖实测的最坏握手，又能在"SYN 黑洞"上及时放弃转向下一个候选。
    /// 另外**超时不再等同于"出口不可用"**，见 <c>ConnectAsync</c> 里的处理 ——
    /// 那一条和这个数值同样重要，缺一个死循环就会回来。
    /// </summary>
    private static readonly TimeSpan PerAttemptTimeout = TimeSpan.FromSeconds(8);

    private readonly IpOptimizer _optimizer;
    private readonly RuleBook _rules;
    private readonly PreflightCheck _preflight;

    public UpstreamConnector(IpOptimizer optimizer, RuleBook rules, PreflightCheck? preflight = null)
    {
        _optimizer = optimizer;
        _rules = rules;
        _preflight = preflight ?? new PreflightCheck();
    }

    /// <summary>转发前的候选预检。转发阶段确认空壳时可调 <see cref="PreflightCheck.MarkBad"/> 省掉一轮探测。</summary>
    public PreflightCheck Preflight => _preflight;

    /// <summary>最近一次出口目标，仅用于日志展示。并发下是尽力而为的近似值。</summary>
    public string? LastExit { get; private set; }

    /// <summary>
    /// 出口层告警（证书校验被放宽、SNI 改写被跳过等）。
    /// </summary>
    public event Action<string>? Log;

    /// <summary>
    /// 建一条到 <paramref name="host"/> 的连接。
    ///
    /// <paramref name="tls"/> 为 true 时，443 端口会顺便完成 TLS 并可改写 SNI
    /// （MITM 路径）；为 false 时只返回裸 TCP，交给调用方（盲隧道）。
    /// </summary>
    public async Task<Stream> ConnectAsync(string host, int port, bool tls, CancellationToken ct)
    {
        // 每次连接都重新算，否则失败时日志会打印上一个请求的残留值，排障方向会被带偏
        LastExit = null;

        if (!_rules.TryGet(host, out var rule))
        {
            // 不在规则表内：走系统 DNS 正常连接。
            // tls=true 时这里只建 TCP，TLS 由上层（SocketsHttpHandler）自己完成，
            // 证书仍走严格校验，被劫持会被拦下。
            return await ConnectPlainAsync(host, port, ct);
        }

        if (!tls && !string.IsNullOrWhiteSpace(rule.ServerName))
        {
            Log?.Invoke($"[代理] {host} 配了 SNI 改写，但 CONNECT 盲隧道是端到端加密，"
                      + "改写不了 SNI —— 这条连接会按原始 SNI 走");
        }

        // 选出口：先预检、再实连；预检没确认出东西时退回按优选顺序直接试。
        //
        // **预检的作用**：拦住"建连成功、回 200、正文只有 4 字节"的空壳出口。
        // 那类出口在连接层完全健康，建连 failover 永远轮不到它，只能靠预检。
        //
        // **预检不是否决权**（这条是本项目反复吃亏换来的）：它返回 null 只代表
        // "没能在预算内确认哪个候选可用"，不代表候选都不可用。
        // 此时必须仍然让真实请求去试排在最前面的候选 ——
        // 早期版本在这里直接跳到"系统 DNS 回退"，等于放弃了加速、
        // 而且回退用的还是同一组 IP，纯属白绕一圈。
        var tried = new HashSet<IPAddress>();
        Exception? last = null;
        var preflightCameUpEmpty = false;

        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var candidates = await _optimizer.RankCandidatesAsync(host, rule, ct);

            var pending = candidates
                .Where(c => !tried.Contains(c))
                .Where(c => !_optimizer.IsCoolingDown(host, rule, c))
                .ToList();

            if (pending.Count == 0)
                break;      // 候选池已试遍，别再空转

            // **staticIps / extraIps 规则跳过预检**：
            //   - staticIps 是手工确定的固定上游（如 Steam 的 Akamai 边缘，
            //     必须配合 serverName 改 SNI 才有效），不存在"换个更好的"；
            //   - extraIps 是用户明确追加进来的候选（如某个时通时断的中转），
            //     语义就是"值得一试"。这类出口往往慢（实测 GitHub 的中转
            //     要 15~39 秒才吐首字节），预检 20 秒的预算会把它判成
            //     "没确认可用"，然后上层白等一轮 —— 等于把它白加了。
            //
            // 预检在这里给的还是**误导性结论**：它对根路径的 302/404
            // 这类正常小响应容易判成可疑。跳过它，让真实请求直接去试，
            // 失败时建连层本来就会换下一个候选。
            IPAddress? verified = null;
            if (rule.StaticIps is not { Length: > 0 } && rule.ExtraIps is not { Length: > 0 })
                verified = await _preflight.SelectVerifiedAsync(host, rule, tls, pending, ct);

            var ip = verified ?? pending[0];

            if (verified is null && !preflightCameUpEmpty)
            {
                preflightCameUpEmpty = true;
                Log?.Invoke($"[预检] {host} 没能在预算内确认可用出口，改由真实请求直接试 {ip}");
            }

            tried.Add(ip);

            try
            {
                var stream = await ConnectViaAsync(ip, port, host, rule, tls, ct);
                LastExit = $"{ip}:{port}{(attempt > 0 ? $" (第 {attempt + 1} 次尝试)" : "")}";
                return stream;
            }
            catch (Exception ex)
            {
                last = ex;

                // **超时不算"这个出口坏了"，不能因此把它拉黑。**
                //
                // 本项目踩过这个死循环：3 秒的建连预算对 github.com 的真首页出口
                // `.166` 来说太紧（实测它的"建连+TLS 握手"落在 225ms~2454ms，
                // 抖动时直接超 3 秒）。超时后把 `.166` 标黑，下一轮就只能从
                // 剩下那些返回 400/403/404 的坏出口里挑，用户看到错误页或 502；
                // 而 `.166` 本来只是"这一次慢了"。
                //
                // 真正的连接错误（拒绝连接、DNS/证书失败等）才代表这个出口不可用。
                // 调用方的取消（用户关掉加速、请求被放弃）同样不该牵连出口。
                if (ex is OperationCanceledException or TimeoutException && !ct.IsCancellationRequested)
                    Log?.Invoke($"[建连] {host} 试 {ip} 超时（{PerAttemptTimeout.TotalSeconds:0} 秒），"
                              + "换下一个候选；该出口不拉黑");
                else
                    _optimizer.ReportFailure(host, rule, ip);
            }
        }

        // 兜底：优选池全军覆没时回退到系统 DNS 直连。
        // 这条路径不享受加速，但保证「用了这个工具不会比不用更差」。
        try
        {
            var fallback = await ConnectPlainAsync(host, port, ct);
            LastExit = "系统 DNS 回退（未加速）";
            return fallback;
        }
        catch
        {
            // 回退也失败，把原始错误抛出去
        }

        throw last is null
            ? new HttpRequestException($"LocalBoost：{host} 没有可用 IP（候选池为空，或全部探测不可达）")
            : new HttpRequestException($"LocalBoost：{host} 的候选 IP 全部连接失败", last);
    }

    /// <summary>连到指定 IP；需要 TLS 时顺便完成握手并可改写 SNI。</summary>
    private async Task<Stream> ConnectViaAsync(
        IPAddress ip, int port, string host, AccelRule rule, bool tls, CancellationToken ct)
    {
        // 每个候选 IP 单独限时，保证 failover 能真的轮起来
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
        attempt.CancelAfter(PerAttemptTimeout);
        var token = attempt.Token;

        var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), token);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        if (!tls || port != 443)
            return new NetworkStream(socket, ownsSocket: true);

        var sni = !string.IsNullOrWhiteSpace(rule.ServerName) ? rule.ServerName! : host;
        var ssl = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);

        // 判断"SNI 是否被改写"必须比字符串，不能用 ReferenceEquals：
        // 那样即便 serverName 与主机名同值，只要不是同一个字符串实例就会被判成已改写，
        // 从而无缘由地放宽证书校验。
        var sniRewritten = !string.Equals(sni, host, StringComparison.OrdinalIgnoreCase);
        if (sniRewritten)
        {
            Log?.Invoke($"[安全] {host} 的上游 SNI 被规则改写为 {sni}，"
                      + "仅容忍证书名称不匹配，链与签名仍按严格标准校验");
        }

        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,

                // **必须声明 ALPN，否则永远协商不到 HTTP/2**。
                //
                // 这里原先是空的（注释写着"不发送 ALPN，上游会回落 HTTP/1.1"），
                // 加上 YARP 那边也钉死 1.1，整条链路就只能在 HTTP/1.1 上跑。
                // 实测同一个 GitHub 边缘出口在 HTTP/1.1 下返回 `200 OK` 但正文
                // **0 字节** —— 正是用户看到的白屏；而协商过 ALPN 的请求，同一 IP
                // 返回 **572,394 字节真首页**。浏览器走的就是后者。
                //
                // 顺序有讲究：h2 在前、http/1.1 兜底。上游不支持 h2 时会选
                // http/1.1，此时 YARP 的 RequestVersionOrLower 跟着回落，两边不会错配。
                ApplicationProtocols =
                [
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11,
                ],

                // 改写 SNI 后上游证书的名称必然对不上，只放过这一种错误；
                // 绝不能写成 (_,_,_,_) => true —— 那等于接受任意伪造证书。
                RemoteCertificateValidationCallback = sniRewritten ? AcceptNameMismatch : null,
            }, token);
        }
        catch
        {
            await ssl.DisposeAsync();
            throw;
        }

        return ssl;
    }

    /// <summary>
    /// SNI 被改写时的宽松校验：只容忍"名称不匹配"，
    /// 链不完整、签名无效、证书过期等一律拒绝。
    /// </summary>
    private static bool AcceptNameMismatch(
        object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors) =>
        errors is SslPolicyErrors.None or SslPolicyErrors.RemoteCertificateNameMismatch;

    /// <summary>
    /// 不在规则表内的域名，走系统 DNS 正常连接。
    ///
    /// 这里刻意**绕开 hosts 文件**（用 <see cref="SystemDnsQuery"/>）：hosts 模式下
    /// 规则域名在 hosts 里被指向 127.0.0.1，用 <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>
    /// 拿到的永远是环回，回退路径必然失败 —— 那正是 README 里承认过的局限，现在补上了。
    ///
    /// 同时必须滤掉环回与私有网段：拿污染结果去连会形成自环，或者打到内网（SSRF）。
    /// </summary>
    private static async Task<Stream> ConnectPlainAsync(string host, int port, CancellationToken ct)
    {
        var resolved = await SystemDnsQuery.ResolveAsync(host, ct);
        var ip = resolved.FirstOrDefault(IsRoutableUpstream)
                 ?? throw new HttpRequestException(
                     $"{host} 的解析结果里没有公网地址（只有环回或私有网段）——"
                     + "多半是 DNS 被污染，回退会形成自环或打到内网");

        var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), ct);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return new NetworkStream(socket, ownsSocket: true);
    }

    /// <summary>
    /// 回退路径可接受的上游地址：排除环回、链路本地与 RFC1918 私有网段。
    /// 注意这里**没有**排除 100.64.0.0/10（CGNAT）—— 部分运营商的透明缓存就在这个段里。
    /// </summary>
    private static bool IsRoutableUpstream(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal)
            return false;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return false;   // 目前只走 IPv4，IPv6 优选还没做

        var b = address.GetAddressBytes();
        if (b[0] == 169 && b[1] == 254) return false;   // 链路本地
        if (b[0] == 10) return false;                   // 10/8
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;   // 172.16/12
        if (b[0] == 192 && b[1] == 168) return false;   // 192.168/16
        if (b[0] == 0) return false;                    // 0.0.0.0/8

        return true;
    }
}
