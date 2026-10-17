using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LocalBoost;

/// <summary>
/// 转发前的**候选预检**：在把真实请求承诺给某个出口之前，先确认它真的会给内容。
///
/// **为什么必须有这一层**：YARP 的 <c>SendAsync</c> 一旦开始把响应写回浏览器
/// 就没法回头，所以"挑错出口 → 换个 IP 重来"在转发层做不到。
/// 实测 github.com 有一类出口会建连成功、TLS 成功、回 `200 OK`，正文却只有
/// **4 个字节**。这类响应在连接层完全健康，建连 failover 永远不会触发，
/// 用户看到的就是白屏。
///
/// **这层被删过一次又加回来，原因值得记住**：删掉是因为它在某个网络相位下
/// 否决了**整个候选池**，然后回退去试恒回 400 的出口，比不加更糟。
/// 根因是它拿"读到多少字节"当判据，而唯一能给出真首页的出口
/// （<c>20.205.243.166</c>）首字节要 1~16 秒 —— 读取窗口里只攒到十几个字节，
/// 就被当成空壳否掉了。**"读得少"和"是空壳"是两件事，当时混为一谈了。**
///
/// 现在按**信号强度**分层，见 <see cref="Judge"/>：
///   确凿的空壳证据（2xx 但正文声明/实际只有几个字节）→ 否决；
///   读到 206（Partial Content）或正文足够多 → 确认可用；
///   其余（读得少、超时、被重置）→ **绝不否决**，留给真实请求去试。
/// </summary>
public sealed class PreflightCheck
{
    /// <summary>正文字节数达到这个值就算"确认有内容"。与探测阶段共用同一判据。</summary>
    internal const int MinBodyBytes = ProbeResult.EmptyBodyThreshold;

    /// <summary>读响应头与正文的上限。只判断"有没有内容"，不必读完整个包体。</summary>
    private const int ReadCap = 16 * 1024;

    /// <summary>
    /// 单个候选的预算。
    ///
    /// 给到 20 秒，是因为唯一可用的出口首字节要 1~16 秒 —— 窗口比这短，
    /// 就会重演"把好出口误杀"的老问题。只等**第一个能判定的事实**：
    /// 一旦看到确凿证据（空壳的 Content-Length、或 206、或足够多的正文）立刻返回，不白等。
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    /// <summary>
    /// 整轮预检的总预算。超了就收手，让上层用真实请求去试第一个候选。
    ///
    /// 上限保证用户不会对着转圈无限等；而"超时不等于否决"（见 <see cref="Judge"/>），
    /// 所以收手也不会把候选错误地拉黑。
    /// </summary>
    private static readonly TimeSpan TotalBudget = TimeSpan.FromSeconds(24);

    /// <summary>通过验证的出口缓存多久。期间同一出口不再重复预检。</summary>
    private static readonly TimeSpan PassTtl = TimeSpan.FromMinutes(5);

    /// <summary>判定"未通过"的缓存时长。故意很短：网络相位会变，不该长期拉黑。</summary>
    private static readonly TimeSpan FailTtl = TimeSpan.FromSeconds(45);

    /// <summary>并行预检候选的上限。别对同一个站点同时发太多请求，会被限流。</summary>
    private const int MaxParallelChecks = 3;

    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.Ordinal);

    /// <summary>
    /// 被预检**确认可用**过的出口（<c>host|ip</c>）。
    ///
    /// 存在的唯一目的：**禁止降级逻辑误伤它们**。
    /// 本项目踩过这个坑 —— 降级时按"探测体积小"挑可疑候选，把
    /// `206 / ~11字节` 的 `.166`（唯一能给真首页的出口）判成可疑并标记掉，
    /// 真正回 4 字节空壳的 `.169` 反而因为"体积正常"逃过标记，
    /// 于是每次请求都继续选中坏出口，形成死循环。
    ///
    /// 预检的结论建立在**真实响应的状态码**上（2xx/3xx + 206 带内容 + 声明长度足够），
    /// 比"探测时读到几个字节"可信得多，所以以它为准。
    /// </summary>
    private readonly ConcurrentDictionary<string, byte> _confirmed = new(StringComparer.Ordinal);

    /// <summary>这个出口是否被预检确认过可用（用于避免降级时误伤）。</summary>
    public bool WasConfirmedGood(string host, IPAddress ip) =>
        _confirmed.ContainsKey(Key(host, ip));

    /// <summary>预检结论。</summary>
    internal enum Verdict
    {
        /// <summary>确认有真实内容，可以放心转发。</summary>
        Good,

        /// <summary>**确凿**是空壳或错误页，应当换下一个候选。</summary>
        Bad,

        /// <summary>没测出来（超时 / 被重置 / 读到的字节不足以判断）。**不否决**这个出口。</summary>
        Unknown,
    }

    private sealed record Entry(Verdict Verdict, DateTimeOffset ExpiresAt);

    private static string Key(string host, IPAddress ip) => $"{host}|{ip}";

    /// <summary>
    /// 按优先级挑一个通过预检的候选。
    ///
    /// 按 <see cref="MaxParallelChecks"/> 分批并行查，先出结果先返回 ——
    /// 排在前面又通过的就是最优解。
    /// </summary>
    /// <param name="candidates">按优选顺序排列的候选。</param>
    /// <returns>确认可用的出口；没有确认的返回 null（调用方应改用真实请求去试第一个候选）。</returns>
    public async Task<IPAddress?> SelectVerifiedAsync(
        string host,
        AccelRule rule,
        bool tls,
        IReadOnlyList<IPAddress> candidates,
        CancellationToken ct)
    {
        if (candidates.Count == 0)
            return null;

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TotalBudget);

        for (var offset = 0; offset < candidates.Count; offset += MaxParallelChecks)
        {
            if (budget.IsCancellationRequested)
                return null;

            var batch = candidates.Skip(offset).Take(MaxParallelChecks).ToList();
            var tasks = batch.Select(ip => CheckAsync(host, rule, ip, tls, budget.Token)).ToList();

            for (var i = 0; i < tasks.Count; i++)
            {
                // 预算耗尽后不再等剩下的任务：它们多半会得到 Unknown，
                // 而 Unknown 本来就不否决候选，等下去只是白等。
                if (budget.IsCancellationRequested)
                    return null;

                var verdict = await tasks[i];

                if (verdict == Verdict.Good)
                    return batch[i];

                // Bad 明确排除；Unknown 也跳过这一轮 —— 但 Unknown **不进缓存**、
                // 也不写冷却，所以它只是"这次不选它"，不是"把它拉黑"。
            }
        }

        return null;
    }

    /// <summary>把某个出口标记为坏（转发阶段确认空壳时用，省掉下一轮的预检）。</summary>
    public void MarkBad(string host, IPAddress ip) =>
        _cache[Key(host, ip)] = new Entry(Verdict.Bad, DateTimeOffset.UtcNow + FailTtl);

    private async Task<Verdict> CheckAsync(
        string host, AccelRule rule, IPAddress ip, bool tls, CancellationToken ct)
    {
        if (_cache.TryGetValue(Key(host, ip), out var hit) && hit.ExpiresAt > DateTimeOffset.UtcNow)
            return hit.Verdict;

        var verdict = await MeasureAsync(host, rule, ip, tls, ct);

        // Unknown 不进缓存：没测出来不代表它坏，下次还得重新看
        if (verdict != Verdict.Unknown)
        {
            var ttl = verdict == Verdict.Good ? PassTtl : FailTtl;
            _cache[Key(host, ip)] = new Entry(verdict, DateTimeOffset.UtcNow + ttl);
        }

        // 记下"确认可用"，供降级逻辑避让（见 _confirmed 的说明）
        if (verdict == Verdict.Good)
            _confirmed[Key(host, ip)] = 0;

        return verdict;
    }

    private static async Task<Verdict> MeasureAsync(
        string host, AccelRule rule, IPAddress ip, bool tls, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(Timeout);

        var token = linked.Token;
        var port = rule.Port;

        var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), token);

            if (!tls || port != 443)
                return Verdict.Unknown;   // 非 TLS 规则不预检

            var sni = !string.IsNullOrWhiteSpace(rule.ServerName) ? rule.ServerName! : host;
            var sniRewritten = !string.Equals(sni, host, StringComparison.OrdinalIgnoreCase);

            await using var ssl = new SslStream(
                new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);

            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,

                // 与真实转发保持一致地声明 ALPN
                ApplicationProtocols =
                [
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11,
                ],

                RemoteCertificateValidationCallback = sniRewritten ? AcceptNameMismatch : null,
            }, token);

            // 协商到 h2 就不在这儿验：本方法只会说 HTTP/1.1，
            // 硬验只会得到错误结论。交给真实请求与转发层检测。
            var negotiated = ssl.NegotiatedApplicationProtocol.Protocol;
            if (!negotiated.IsEmpty &&
                !negotiated.Span.SequenceEqual(SslApplicationProtocol.Http11.Protocol.Span))
            {
                return Verdict.Unknown;
            }

            return await JudgeAsync(ssl, host, token);
        }
        catch (Exception ex) when (ex is IOException or SocketException
                                      or OperationCanceledException or InvalidOperationException
                                      or AuthenticationException)
        {
            return Verdict.Unknown;
        }
        finally
        {
            socket.Dispose();
        }
    }

    private static async Task<Verdict> JudgeAsync(Stream ssl, string host, CancellationToken ct)
    {
        // GET + Range 而不是 HEAD：个别中间盒会拦 HEAD 却放行 GET。
        // 用 Range 还能换来一个额外信号 —— 真资源会回 206（见 Judge）。
        var request = Encoding.ASCII.GetBytes(
            $"GET / HTTP/1.1\r\n"
            + $"Host: {host}\r\n"
            + "User-Agent: LocalBoost-preflight\r\n"
            + "Range: bytes=0-0\r\n"
            + "Accept: */*\r\n"
            + "Connection: close\r\n\r\n");

        await ssl.WriteAsync(request, ct);
        await ssl.FlushAsync(ct);

        var buffer = new byte[ReadCap];
        var total = 0;
        var headerEnd = -1;

        // 读到**能判定**为止，而不是"读到一点就判"。
        // 每读一段就问一次 Judge：拿到确凿结论立刻收手；还判不出来就继续等，直到超时。
        // 这样慢而真的出口（首字节 1~16 秒）有机会自证，
        // 而空壳出口凭借响应头里的 Content-Length，第一段就能被定性。
        while (total < buffer.Length)
        {
            var read = await ssl.ReadAsync(buffer.AsMemory(total), ct);
            if (read <= 0)
                break;              // 对端关连接，就用手上的字节判

            total += read;

            if (headerEnd < 0)
                headerEnd = FindHeaderEnd(buffer, total);

            var verdict = Judge(buffer, total, headerEnd);
            if (verdict != Verdict.Unknown)
                return verdict;
        }

        return Judge(buffer, total, headerEnd);
    }

    /// <summary>
    /// 判定一次预检的结果。
    ///
    /// **信号强度分层**是这个类被删掉又加回来的核心教训：
    /// 只有**确凿**证据才允许否决一个出口；读得少 / 超时一律不否决。
    /// </summary>
    internal static Verdict Judge(byte[] buffer, int total, int headerEnd)
    {
        if (total < 12)
            return Verdict.Unknown;      // 连状态行都没读全

        var text = Encoding.ASCII.GetString(buffer, 0, Math.Min(total, 512));
        var status = ParseStatusCode(text);

        if (status is null)
            return Verdict.Unknown;

        // 重定向正文为空是正常的（实测 raw.githubusercontent.com 根路径回 301 + 0 字节）
        if (status is >= 300 and < 400)
            return Verdict.Good;

        if (status is < 200 or >= 400)
            return Verdict.Bad;          // 400 / 403 / 404 都是实锤

        // 声明了长度就以它为准 —— 这也正是空壳的实锤：
        // 实测空壳出口回的就是 `Content-Length: 4`
        var declared = ParseContentLength(text);
        if (declared is { } len)
            return len >= MinBodyBytes ? Verdict.Good : Verdict.Bad;

        // 没声明长度：算头部之后实到了多少正文
        var bodyBytes = headerEnd >= 0 ? Math.Max(0, total - headerEnd) : 0;

        if (bodyBytes >= MinBodyBytes)
            return Verdict.Good;

        // 206 = Partial Content：上游确认"这是个有内容的真资源"，
        // 只是我们发的 Range 只取 1 字节。看到它就足以确认出口可用 ——
        // 这正是唯一可用的 .166 给出的响应（实测 `206 / ~11字节`）。
        if (status == 206 && bodyBytes > 0)
            return Verdict.Good;

        // 到这里：状态 2xx、没声明长度、正文没攒够、也不是 206。
        // **不能判 Bad** —— 它可能只是首字节出得慢（.166 要 1~16 秒）。
        // 返回 Unknown 让调用方继续读；读满窗口仍无结论就放行给真实请求。
        return Verdict.Unknown;
    }

    private static int? ParseStatusCode(string text)
    {
        if (!text.StartsWith("HTTP/", StringComparison.Ordinal))
            return null;

        var space = text.IndexOf(' ');
        if (space < 0)
            return null;

        var code = 0;
        var digits = 0;
        for (var i = space + 1; i < text.Length && char.IsAsciiDigit(text[i]); i++)
        {
            code = (code * 10) + (text[i] - '0');
            digits++;
        }

        return digits == 3 && code is >= 100 and <= 599 ? code : null;
    }

    private static long? ParseContentLength(string text)
    {
        var at = 0;

        while (true)
        {
            var lineEnd = text.IndexOf('\n', at);
            var line = (lineEnd < 0 ? text[at..] : text[at..lineEnd]).TrimEnd('\r');

            if (line.Length == 0)
                return null;             // 头部结束

            var colon = line.IndexOf(':');
            if (colon > 0 && line.AsSpan(0, colon).Trim()
                    .Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                var raw = line[(colon + 1)..].Trim();
                return long.TryParse(raw, out var v) && v >= 0 ? v : null;
            }

            if (lineEnd < 0)
                return null;

            at = lineEnd + 1;
        }
    }

    private static bool AcceptNameMismatch(
        object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors) =>
        errors is SslPolicyErrors.None or SslPolicyErrors.RemoteCertificateNameMismatch;

    private static int FindHeaderEnd(byte[] buffer, int length)
    {
        for (var i = 2; i < length; i++)
        {
            if (buffer[i] != (byte)'\n')
                continue;

            if (buffer[i - 1] == (byte)'\n')
                return i + 1;

            if (i >= 3 && buffer[i - 1] == (byte)'\r' && buffer[i - 2] == (byte)'\n' && buffer[i - 3] == (byte)'\r')
                return i + 1;
        }

        return -1;
    }
}
