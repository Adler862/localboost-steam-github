using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace LocalBoost;

/// <summary>
/// 单个候选出口的探测结果。
/// </summary>
/// <param name="Address">候选 IP。</param>
/// <param name="Reachable">TCP + TLS 握手是否成功。</param>
/// <param name="CertificateValid">握手时拿到的证书是否通过校验（含名称匹配）。</param>
/// <param name="DataFlowing">
/// 发一个最小请求后**是否真的收到了响应字节**。
///
/// 这一项和 <paramref name="Reachable"/> 必须分开：实测 github.com 有 7 个出口
/// TLS 握手 300ms 就过、证书也有效，但一开始传数据连接就被重置（典型的链路层阻断）。
/// 只看握手会把它们全判成"好"，于是每次请求都挑中最快的那张假好牌，用户看到持续 502。
/// </param>
/// <param name="TotalMs">从发起连接到收到第一个响应字节（或失败）的耗时。</param>
/// <param name="Error">失败原因，成功时为 null。</param>
/// <param name="StatusCode">
/// 探测请求收到的 HTTP 状态码，拿不到状态行时为 null。
///
/// 为什么要单独记它：**同一台服务器的不同边缘 IP 表现可能并不一样**。
/// 实测 github.com 的 7 个出口，直连时有的返回 200（真首页）、
/// 有的返回 400 / 403 / 404 —— 只看"有没有数据"会把它们当成等价的，
/// 于是按耗时挑中最快的那个坏出口，用户浏览器里就是 GitHub 的
/// "Bad request" / "Whoa there!" 页面。这不是链路问题，是挑错了出口。
/// </param>
/// <param name="Size">
/// 补测时的响应体积。见 <see cref="ResponseSize"/> ——
/// 光有状态码还不够：坏出口里有一类会伪装成 `200 OK`，但正文是空的。
/// 只有补测过的候选才有这一项，一阶段握手候选为 null。
/// </param>
public sealed record ProbeResult(
    IPAddress Address,
    bool Reachable,
    bool CertificateValid,
    long TotalMs,
    string? Error,
    bool DataFlowing,
    int? StatusCode,
    ResponseSize? Size = null)
{
    /// <summary>正文小到这个字节数以下、状态却是好的，就按空壳处理。</summary>
    internal const int EmptyBodyThreshold = 512;

    /// <summary>
    /// 出口是否"看着像空壳"：状态是好的，但正文小到不可能是真实页面。
    ///
    /// **为什么必须有这一项**：实测 github.com 的出口里，
    /// `20.205.243.166` 返回 200 + 约 572 KB 真首页，
    /// 而 **`20.205.243.169` 返回 200 + 4 字节空体**。
    /// 旧判据（证书有效 → 收到过字节 → 状态 2xx）把两者当成完全等价，
    /// 于是按握手耗时决胜 —— 4 字节那个更快、被选中，
    /// 用户浏览器里就是"能连上、但页面一片空白"。
    ///
    /// 这比 400/403 那一类坏出口隐蔽得多：它连状态码都是对的。
    ///
    /// **判据必须区分"响应结束"与"还没传完"**（<see cref="ResponseSize.EndOfResponseReached"/>）：
    /// chunked 响应没有 <c>Content-Length</c>，"读到了多少字节"只反映**读取时机**。
    /// 实测两个出口的失败形态完全不同：
    ///   - `.169`（空壳）：给 4 个字节后**干净关闭**，读到的字节数就是全部正文；
    ///   - `.166`（真首页）：正文要 7~25 秒，链路抖动时会**传到 400~500 KB 后卡住**
    ///     —— 这是"没传完"，不是"内容为空"。
    /// 拿"实读字节数"一律比阈值，会把 `.166` 这种慢而真的出口误杀
    /// （本项目踩过：探测把它量成 `~11字节`，比空壳的 `~4字节` 只好一点，
    /// 于是排序每次都在两个之间随机）。
    ///
    /// 所以：**只有确认对端已结束响应、且总量确实很小，才算空壳**。
    /// 声明了长度时直接采信声明值（与网络相位无关）。
    /// </summary>
    public bool LooksEmpty => Size is { } size
        && StatusCode is >= 200 and < 400
        && (size.Declared
            ? size.BodyBytes < EmptyBodyThreshold
            : size.EndOfResponseReached && size.BodyBytes < EmptyBodyThreshold);
}

/// <summary>
/// 补测时量到的响应体积。
///
/// 优先取服务器自己声明的 <c>Content-Length</c>：不必真的把正文读下来，
/// 所以对 codeload 那种几十兆的压缩包也零成本，而且**与当前网络相位无关**
/// —— 链路半死、正文读不出来时，头里的长度依然可信。
/// 没有声明长度（chunked）时才退化成"实际读到了多少字节"。
/// </summary>
/// <param name="BodyBytes">正文大小：优先 Content-Length，否则为实际读到的字节数。</param>
/// <param name="Declared">是否来自 Content-Length 声明（true 时 <paramref name="BodyBytes"/> 是精确值）。</param>
/// <param name="EndOfResponseReached">
/// 对端是否已经结束这条响应（读到读取循环的自然结束）。
///
/// **这一项是区分"空壳"和"还没传完"的唯一依据**，必须记录：
/// 未声明长度时，实读字节数只是"读到此刻为止"的快照 ——
/// 真首页出口 `.166` 正文要 7~25 秒，抖动时会在传到 400~500 KB 处停住，
/// 此时实读字节数远小于真实体积，但**它并不是空壳**。
/// 只有对端干净结束（`Connection: close` 后读到 EOF）、总量又极小，
/// 才说明这条响应的全部内容就是那么点。
/// </param>
public sealed record ResponseSize(long BodyBytes, bool Declared, bool EndOfResponseReached = false)
{
    public override string ToString() => Declared
        ? $"{BodyBytes}字节"
        : EndOfResponseReached ? $"~{BodyBytes}字节(已结束)" : $"~{BodyBytes}字节(未完)";
}

/// <summary>
/// IP 优选引擎。整份工具的效果主要由它决定，代理框架本身几乎不影响速度。
///
/// 三件事：
///   1. 攒候选 IP（规则指定 > DoH 多源 > 系统 DNS）
///   2. 并发探测，用「TCP 连接 + TLS 握手」的总耗时排序
///   3. 按域名缓存结果，定期复测
///
/// 测到 TLS 握手为止是必须的：只测 TCP 握手会被中间设备伪造的 SYN-ACK 骗到，
/// 测出来的延迟全是假的。同时记录证书是否有效，无效的 IP 一律排在后面。
/// </summary>
public sealed class IpOptimizer
{
    /// <summary>
    /// 一阶段（TCP + TLS 握手）单个候选的超时。
    ///
    /// **这个值必须覆盖本线路上真实的最坏握手**，否则会把可用出口判成"不可达"、
    /// 直接从候选池里抹掉 —— 比排错顺序更糟，因为它连被比较的机会都没有。
    ///
    /// 实测（2026-10-16 夜）真首页出口 `20.205.243.166` 的
    /// 「建连 + TLS 握手」在 0.2 秒到 10.5 秒之间大幅波动；
    /// 取 5 秒时它经常被判"不可达"，于是 probe 推荐了**证书无效**的 `.163`
    /// （排序第一档就是证书有效性，它本不该有机会）。
    /// 而同一时刻直连 `.166` 只要 1.67 秒就能拿到 572 KB 真首页。
    ///
    /// 一阶段是**并行**跑的（见 <see cref="ProbeManyAsync"/>），
    /// 所以抬高它不会线性拖慢整轮探测。
    /// </summary>
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// 补测（发真实请求看响应）的总预算。
    ///
    /// **必须大于 <see cref="BodyPeekGrace"/>，也要容得下
    /// <see cref="BodyPeekBudget"/>**：后两者都是在这个总预算之内再开的小超时，
    /// 总预算比它们短的话，等正文那一步会被父级 token 提前掐掉，
    /// 调大宽限就成了摆设（本项目踩过：改了宽限却毫无效果）。
    ///
    /// 6 秒 → 16 秒是**必要**的放宽：实测真首页出口 `.166` 的正文要 7~25 秒，
    /// 6 秒预算会在它把内容吐出来之前就掐断，于是它被记成"只有 1 KB"，
    /// 与 4 字节空壳几乎无法区分 —— 这正是"优选反复选中空壳"的最后一环。
    /// 代价只在补测最前面几个候选时付出，且结果有 15 分钟缓存。
    /// </summary>
    private static readonly TimeSpan DataProbeTimeout = TimeSpan.FromSeconds(40);

    /// <summary>
    /// 读完响应头之后，再给多少时间等正文的第一个字节。
    ///
    /// **这个值调过一轮，别轻易往回缩**。原先是 800ms，实测把唯一可用的出口误杀了：
    /// github.com 的 20.205.243.166 握手 197ms，但吐首页首字节要 1.0~16 秒
    /// （线路抖动大时更慢）。800ms 等不到就判"数据不通"，它直接掉到候选表第 8 位，
    /// 于是优选只能从那些"握手快、但返回 400/403 错误页"的出口里挑，
    /// 用户看到的是错误页或白屏 —— 而真正能用的那个出口被自己排除掉了。
    ///
    /// 取 3 秒是**保守**选择：足以把"首字节出得慢但内容真实"的出口从"连不上"里
    /// 区分出来，又不会让整轮补测慢到不可接受。
    /// 注意这一步只等**第一个字节**，不读完整个正文：
    /// 有 Content-Length 的响应在读完头部时就已经定论，根本不会走到这里。
    /// </summary>
    private static readonly TimeSpan BodyPeekGrace = TimeSpan.FromSeconds(12);

    /// <summary>
    /// 单个候选最多花多少时间等正文。
    ///
    /// **给足时间**是这个工具能不能挑对出口的关键：实测真首页出口 `.166`
    /// 的正文要 7~25 秒才传完，而且经常传一会儿停一会儿。
    /// 给太短会把它记成"只有 1 KB"，与 4 字节空壳几乎无法区分，
    /// 于是排序退化成比握手耗时 —— 那就又回到"选中空壳、用户白屏"的老问题。
    ///
    /// 上限存在的意义是别让一轮探测无限拖下去：这一项是按候选计的，
    /// 而补测只串行做最前面几个（见 <see cref="DataCheckCount"/>）。
    /// </summary>
    private static readonly TimeSpan BodyPeekBudget = TimeSpan.FromSeconds(35);

    /// <summary>
    /// 正文最多读到多少字节就够下结论。
    ///
    /// 判定"空壳 vs 有内容"只需要 <see cref="ProbeResult.EmptyBodyThreshold"/>，
    /// 但**体积是要用来横向比较的**：`.166` 能给出几 KB 以上，空壳只能给 4 字节，
    /// 读到 4 KB 就足以把两者彻底分开，且不必真把首页 572 KB 拉下来
    /// （codeload 那种几十兆的包更不能拉）。
    /// </summary>
    private const int BodyReadCap = 4 * 1024;

    /// <summary>
    /// 日常优选时补测多少个候选。见 <see cref="ProbeManyAsync"/>：**串行**补测，
    /// 因为同时对同一个站点发一堆请求确实不礼貌（也容易被限流）。
    ///
    /// **这个上限必须宽到能覆盖整个可用候选池**，理由见
    /// <see cref="ProbeManyAsync"/> 里 <c>toCheck</c> 处的长注释：
    /// 只有补测过的候选才有体积，而体积是排序里区分"真内容"和"空壳"的唯一依据。
    /// 曾经取 4，结果真首页出口 `.166` 常因握手不在最前面而**从未被补测**，
    /// 排序时与 4 字节空壳打平，最终按耗时选中空壳 —— 用户看到白屏。
    ///
    /// 取 8：github.com 这类站点的可用候选通常不到十个，够用；
    /// 又留了个上限，避免某些域名解析出几十个地址时把一轮优选拖太久。
    /// </summary>
    private const int DataCheckCount = 8;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(15);

    /// <summary>首次失败的冷却时长；之后每次失败翻倍，见 <see cref="CooldownFor"/>。</summary>
    private static readonly TimeSpan FailureCooldown = TimeSpan.FromMinutes(2);

    /// <summary>冷却时长的上限。有它才不会把出口永久拉黑 —— 网络抖动是暂时的。</summary>
    private static readonly TimeSpan MaxCooldown = TimeSpan.FromMinutes(30);

    /// <summary>失败次数的计数上限，避免指数退避溢出。</summary>
    private const int MaxPenalty = 16;

    private const int MaxProbeConcurrency = 12;

    // 顺序按国内可达性排；还是要逐个试，因为任何一个都可能被本地网络挡掉
    private static readonly string[] DohTemplates =
    [
        "https://dns.alidns.com/resolve?name={0}&type=A",
        "https://doh.360.cn/resolve?name={0}&type=A",
        "https://dns.google/resolve?name={0}&type=A",
        "https://doh.dns.sb/resolve?name={0}&type=A",
    ];

    // 这里刻意跟随系统代理。公司网、校园网、以及带壳/CI 的环境常常
    // 只有走代理才能出站，把 UseProxy 关掉就会直接拿不到候选 IP。
    // （出口转发的那个 invoker 必须关代理，两者不是一回事。）
    private static readonly HttpClient DohClient = new(new SocketsHttpHandler
    {
        UseProxy = true,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    { Timeout = TimeSpan.FromSeconds(5) };

    private readonly ConcurrentDictionary<string, IpRanking> _rankings = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _cooldown = new();

    /// <summary>每个候选累积的失败次数，决定冷却时长（见 <see cref="CooldownFor"/>）。</summary>
    private readonly ConcurrentDictionary<string, int> _penalty = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new();
    private readonly List<string> _trace = [];
    private readonly object _traceLock = new();

    private void Note(string line)
    {
        lock (_traceLock) { _trace.Add(line); }
    }

    private sealed record IpRanking(IReadOnlyList<ProbeResult> Probes, DateTimeOffset ExpiresAt)
    {
        /// <summary>按当前排序规则得出的出口顺序（最好的在前）。</summary>
        public List<IPAddress> Order => Rank(Probes).Select(r => r.Address).ToList();
    }

    /// <summary>最近一次候选采集的过程记录，用于排障。候选为空时最有用。</summary>
    public IReadOnlyList<string> Trace
    {
        get { lock (_traceLock) { return _trace.ToArray(); } }
    }

    /// <summary>为某个上游域名挑出当前最优 IP。拿不到候选或全部不可达时返回 null。</summary>
    public async Task<IPAddress?> ResolveBestAsync(
        string upstreamHost,
        AccelRule rule,
        CancellationToken ct)
    {
        var list = await GetRankingAsync(upstreamHost, rule, ct);
        if (list is null || list.Count == 0)
            return null;

        foreach (var ip in list)
        {
            if (!IsCooling(upstreamHost, rule.Tag, ip))
                return ip;
        }

        // 全部候选都在冷却：只放过**惩罚最轻**的那一个，其余保持冷却。
        //
        // 早先这里是把冷却全部清空再返回 list[0]。那有个致命的自相抵消：
        // 一次空壳事故会标记掉前几个候选（正好等于连接层的尝试数），
        // 于是下一次请求立刻触发"全冷却"→ 清空 → 又把最差的那个排回第一，
        // 坏出口永远被重新选中，冷却形同虚设。
        // 按惩罚轻重放行，能让反复出问题的出口被越推越后，而不是每次复位。
        var mildest = list
            .OrderBy(ip => PenaltyOf(upstreamHost, rule.Tag, ip))
            .ThenBy(ip => list.IndexOf(ip))
            .First();

        Note($"候选全部在冷却，放行惩罚最轻的 {mildest}");
        return mildest;
    }

    /// <summary>
    /// 报告某个 IP 不可用，让它在冷却期内不再被选中。
    ///
    /// 除了"连不上"，这层还有一个更隐蔽的用途：**响应是空壳的出口**。
    /// 空壳在建连阶段完全成功（TCP + TLS + 200 状态行），单纯的重连 failover
    /// 永远轮不到它 —— 只有在这里把它标掉，下一次请求才会换出口。
    ///
    /// **冷却时长按失败次数递增**（<see cref="FailureCooldown"/> 起，每次翻倍，
    /// 上限 <see cref="MaxCooldown"/>）。固定时长挡不住"反复出问题的出口"：
    /// 两分钟一过它又回到第一位，用户就又白屏一次。递增能把顽固的坏出口
    /// 逐步推到后面，而偶尔抖一下的出口只被短暂跳过。
    /// </summary>
    public void ReportFailure(string upstreamHost, AccelRule rule, IPAddress ip)
    {
        var key = CooldownKey(upstreamHost, rule.Tag, ip);
        var penalty = _penalty.AddOrUpdate(key, 1, (_, old) => Math.Min(old + 1, MaxPenalty));
        _cooldown[key] = DateTimeOffset.UtcNow + CooldownFor(penalty);
    }

    /// <summary>第 n 次失败对应的冷却时长：指数退避，封顶 <see cref="MaxCooldown"/>。</summary>
    internal static TimeSpan CooldownFor(int penalty)
    {
        var factor = Math.Pow(2, Math.Max(0, penalty - 1));
        var seconds = FailureCooldown.TotalSeconds * factor;
        return seconds >= MaxCooldown.TotalSeconds ? MaxCooldown : TimeSpan.FromSeconds(seconds);
    }

    /// <summary>某个候选累积的失败次数，用于"全冷却时放行惩罚最轻的那个"。</summary>
    private int PenaltyOf(string host, string tag, IPAddress ip) =>
        _penalty.TryGetValue(CooldownKey(host, tag, ip), out var n) ? n : 0;

    /// <summary>
    /// 某个候选当前是否处于冷却期（刚失败过、暂不选用）。
    ///
    /// 给调用方用来**避免同一次请求里反复试同一个 IP**：
    /// <see cref="ResolveBestAsync"/> 在全部候选都冷却时会清空冷却再给一次机会，
    /// 于是上层循环可能拿到刚刚已经失败过的那个 IP，白白多耗一个超时预算。
    /// </summary>
    public bool IsCoolingDown(string upstreamHost, AccelRule rule, IPAddress ip) =>
        IsCooling(upstreamHost, rule.Tag, ip);

    /// <summary>
    /// 按优选顺序列出候选（最好的在前）。给需要"逐个换"的调用方使用。
    ///
    /// 返回的是**快照**：后续的 <see cref="ReportFailure"/> 不会改变这个列表，
    /// 这样上层遍历时不会因为冷却变化而跳过或重复某个候选。
    /// </summary>
    public async Task<IReadOnlyList<IPAddress>> RankCandidatesAsync(
        string upstreamHost, AccelRule rule, CancellationToken ct)
    {
        var list = await GetRankingAsync(upstreamHost, rule, ct);
        return list ?? [];
    }

    /// <summary>
    /// 把**确实没给出内容的候选**标记为失败，促使下一次请求换出口。
    ///
    /// **为什么需要这个方法**：转发完成后才发现响应是"空壳"（2xx 但正文只有几个字节）。
    /// 这时想知道"刚才到底用了哪个 IP"，但拿不到 ——
    /// <see cref="UpstreamConnector"/> 的连接回调是 <c>SocketsHttpHandler</c> 的连接池
    /// 在**另一个异步上下文**里调用的，<c>AsyncLocal</c> 不会从子任务反向流回请求流程
    /// （本项目试过，拿不到值）。而共享字段在并发下又会把 A 请求的出口标到 B 上。
    ///
    /// **标谁**：只标 <see cref="IsProblematic"/> 为真的候选，并且**跳过
    /// <paramref name="isProtected"/> 判定为受保护的**（预检确认过可用的那些）。
    /// 这两道过滤缺一不可 —— 本项目踩过的坑就是降级标错了对象：
    /// 把唯一能用的 `.166` 标掉、真正回空壳的 `.169` 反而逃过，于是死循环。
    /// </summary>
    /// <param name="count">最多标几个，用于限流。宁可小步快跑，也不要一次把候选池拉黑。</param>
    /// <param name="isProtected">返回 true 的候选不会被标记（传 null 表示不设保护）。</param>
    /// <returns>被标记的候选，供调用方写日志。</returns>
    public async Task<IReadOnlyList<IPAddress>> DemoteTopCandidatesAsync(
        string upstreamHost,
        AccelRule rule,
        int count,
        CancellationToken ct,
        Func<IPAddress, bool>? isProtected = null)
    {
        if (count <= 0)
            return [];

        var probes = await GetProbesAsync(upstreamHost, rule, ct);

        var marked = probes
            .Where(IsProblematic)
            .Where(r => isProtected is null || !isProtected(r.Address))
            .Take(count)
            .Select(r => r.Address)
            .ToList();

        foreach (var ip in marked)
            ReportFailure(upstreamHost, rule, ip);

        return marked;
    }

    /// <summary>
    /// 这个候选是不是"没给出内容"？
    ///
    /// 四种情形算：
    ///   1. 连不上；
    ///   2. 连上但一个字节都没收到（<c>DataFlowing == false</c>）；
    ///   3. 拿到了空壳：2xx 但正文极小（<see cref="ProbeResult.LooksEmpty"/>）；
    ///   4. **拿到过一点字节、但状态是 2xx、体积却小得可疑** ——
    ///      这是 <see cref="ProbeResult.LooksEmpty"/> 盖不到的一类：
    ///      没有声明长度（chunked）时它只认"一个字节都没有"，而实测空壳出口
    ///      会给出 `~4字节`（<c>DataFlowing=true</c>）。
    ///      漏掉这一类的后果很严重：它会成为**唯一"看起来没问题"的候选**，
    ///      于是降级时被跳过、永远不被标记，每次请求都继续选中它。
    ///
    /// **刻意不含"状态码是 4xx/5xx"**：那类判断太容易误伤 ——
    /// 实测 <c>api.github.com</c> 的根路径本来就合法地返回 404。
    /// 状态码的影响交给排序档位去做（见 <see cref="Rank"/>）。
    /// </summary>
    private static bool IsProblematic(ProbeResult r)
    {
        if (!r.Reachable || !r.DataFlowing || r.LooksEmpty)
            return true;

        // 情形 4：拿到过字节、但体积小到不可能是真内容。
        //
        // **刻意不看 Declared**：实测空壳出口给的是 `~4字节`（未声明长度），
        // 早先这里只按"声明长度"判，于是它成了唯一"看起来没问题"的候选 ——
        // 降级时被跳过、永远不被标记，每次请求都继续选中它。
        //
        // 注意这一条也会把 `~11字节` 的真首页出口 `.166` 判成可疑：
        // 单靠探测的体积确实分不出它和空壳。所以调用方**必须**配合
        // "预检确认过的出口不许标记"那道保护（见 DemoteTopCandidatesAsync 的 isProtected），
        // 否则就会标错对象、把唯一能用的出口拉黑。
        return r.StatusCode is >= 200 and < 300
               && r.Size is { BodyBytes: < ProbeResult.EmptyBodyThreshold };
    }

    /// <summary>取某域名的探测明细（带缓存）。</summary>
    private async Task<IReadOnlyList<ProbeResult>> GetProbesAsync(
        string upstreamHost, AccelRule rule, CancellationToken ct)
    {
        var key = $"{rule.Tag}|{upstreamHost}";
        if (_rankings.TryGetValue(key, out var hit) && hit.ExpiresAt > DateTimeOffset.UtcNow)
            return hit.Probes;

        await GetRankingAsync(upstreamHost, rule, ct);

        return _rankings.TryGetValue(key, out var again) ? again.Probes : [];
    }

    private bool IsCooling(string host, string tag, IPAddress ip) =>
        _cooldown.TryGetValue(CooldownKey(host, tag, ip), out var until)
        && until > DateTimeOffset.UtcNow;

    private void ClearCooldowns(string host, string tag)
    {
        var prefix = $"{host}|{tag}|";
        foreach (var key in _cooldown.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList())
            _cooldown.TryRemove(key, out _);
    }

    private static string CooldownKey(string host, string tag, IPAddress ip) => $"{host}|{tag}|{ip}";

    private async Task<List<IPAddress>?> GetRankingAsync(
        string upstreamHost,
        AccelRule rule,
        CancellationToken ct)
    {
        var key = $"{rule.Tag}|{upstreamHost}";
        if (_rankings.TryGetValue(key, out var hit) && hit.ExpiresAt > DateTimeOffset.UtcNow)
            return hit.Order;

        var gate = _gates.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            if (_rankings.TryGetValue(key, out var again) && again.ExpiresAt > DateTimeOffset.UtcNow)
                return again.Order;

            var candidates = rule.StaticIps is { Length: > 0 }
                ? ParseAll(rule.StaticIps)
                : await GatherCandidatesAsync(upstreamHost, rule, ct);

            if (candidates.Count == 0)
                return null;

            // **手工指定了 staticIps 就不再"优选"**，直接按声明顺序用。
            //
            // 这类规则里的 IP 不是"从解析结果里挑一个"，而是**用户已经确定的目标**
            // （例如 Steam 的 Akamai 边缘：必须同时配合 serverName 改写 SNI 才有效，
            // 换一个 IP 就没有意义）。对它再做一轮完整探测 + 预检纯属浪费：
            //
            // 实测（2026-10-17）Steam 那两条规则每个域名首访要多花 4~20 秒，
            // 主要耗在预检把 Akamai 根路径的 302 / 小响应误判成"没确认可用"
            // 之后又白等一轮预算。而 staticIps 只有两三个，建连层的 failover
            // 本来就够用 —— 死 IP 会自己走到下一个。
            //
            // 注意仍然返回探测明细（这里用一阶段结果占位），
            // 让上层的冷却/降级逻辑保持可用的数据结构。
            if (rule.StaticIps is { Length: > 0 })
            {
                var placeholders = candidates
                    .Select(ip => new ProbeResult(ip, Reachable: true, CertificateValid: true,
                                                  TotalMs: 0, Error: null, DataFlowing: false, StatusCode: null))
                    .ToList();
                _rankings[key] = new IpRanking(placeholders, DateTimeOffset.UtcNow + CacheTtl);
                return candidates;
            }

            var ranked = await ProbeManyAsync(candidates, rule.Port, upstreamHost, rule.ServerName, allWithData: false, ct);

            // 顺序由 Rank 现算（IpRanking.Order 会重新排），这里只存探测明细。
            // 存明细而不是存算好的顺序，是为了让"降级坏出口"能有的放矢 ——
            // 需要知道哪个候选**实际拿到了内容**，而不是只知道它排第几。
            if (!ranked.Any(r => r.Reachable))
                return null;

            _rankings[key] = new IpRanking(ranked, DateTimeOffset.UtcNow + CacheTtl);
            return _rankings[key].Order;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>诊断用：返回全部候选 IP 的探测明细，按推荐顺序排列。</summary>
    public async Task<IReadOnlyList<ProbeResult>> DiagnoseAsync(
        string upstreamHost,
        AccelRule rule,
        CancellationToken ct)
    {
        var candidates = rule.StaticIps is { Length: > 0 }
            ? ParseAll(rule.StaticIps)
            : await GatherCandidatesAsync(upstreamHost, rule, ct);

        var results = await ProbeManyAsync(candidates, rule.Port, upstreamHost, rule.ServerName, allWithData: true, ct);

        // 诊断视图要列出全部候选，包括探测失败的那些——
        // 否则遇到「所有 IP 都连不上」时会误报成「没解析到 IP」，排查方向完全错。
        //
        // 这里刻意**不照抄 Rank 的分档**：Rank 先按"证书有效 → 数据通"分组，
        // 那是给真实转发选出口用的；诊断表要让人一眼看出"哪个出口是空壳"，
        // 所以把 HealthRank（含空壳）放在第一顺位。表格首行同时也是给出的"推荐"。
        return results
            .OrderBy(HealthRank)
            .ThenBy(r => r.CertificateValid ? 0 : 1)
            .ThenBy(r => r.TotalMs)
            .ToList();
    }

    /// <summary>
    /// 出口排序。**总顺序：先看有没有内容，再看内容好不好，最后才比快慢。**
    ///
    /// 为什么"内容优先"必须排在最前面：实测 github.com 的出口里
    /// `.161`/`.162`/`.165`/`.167`/`.168` 都**握手最快**（更低的耗时），
    /// 但它们返回 400/403/404 —— 而唯一能给真首页的 `.166` 首字节要 1~16 秒。
    /// 只要让"耗时"参与决胜，这些坏出口就会靠"快"赢，`.166` 永远排不上来，
    /// 用户看到的就一直是错误页或白屏。
    ///
    /// 这一条是本项目反复踩坑的核心：**"快"在这个场景里不是优点，是陷阱** ——
    /// 快而错 > 慢而对，用户宁可多等几秒也不要一个打不开的页面。
    /// </summary>
    /// <remarks>
    /// 倒数第二档是"已确认有内容"优先于"没量到体积"，**这一档不能省**：
    /// <see cref="ProbeResult.LooksEmpty"/> 对未补测的候选恒为 false（体积是 null），
    /// 若只靠上面那一档，未补测的候选会和"量到几 KB 真内容"的候选并列，
    /// 再被 <see cref="HealthRank"/>（两者都是 0）与握手耗时决胜 ——
    /// 于是**未测量的空壳出口靠"握手更快"胜出**。
    /// 实测正是如此：真实转发选中 `.169` 并返回 502，而 `probe` 推荐 `.166`。
    /// 拿未测量的东西和已测量的比，等于没测。
    /// </remarks>
    internal static IEnumerable<ProbeResult> Rank(IEnumerable<ProbeResult> results) =>
        results.Where(r => r.Reachable)
               .OrderBy(r => r.CertificateValid ? 0 : 1)   // 证书名不匹配的出口在真实转发里也用不了
               .ThenBy(r => r.DataFlowing ? 0 : 1)         // 补测过且真的拿到过响应字节
               .ThenBy(r => r.LooksEmpty ? 1 : 0)          // 空壳（200 但正文极小）排在有内容的之后
               .ThenBy(HealthRank)                         // 状态码档位
               .ThenBy(r => r.Size is { BodyBytes: > 0, Declared: false } ? 0 : 1)
               .ThenBy(r => r.TotalMs);                    // 最后才比握手耗时

    private async Task<List<IPAddress>> GatherCandidatesAsync(string host, AccelRule rule, CancellationToken ct)
    {
        lock (_traceLock) { _trace.Clear(); }

        var seen = new HashSet<IPAddress>();
        var result = new List<IPAddress>();

        // 规则里追加的候选先放进来：这些是"已知值得一试"的地址
        // （例如某个时通时断的中转），让优选和其他候选一起评。
        // 放在最前面只是为了让诊断表更容易看到它，最终顺序仍由 Rank 决定。
        if (rule.ExtraIps is { Length: > 0 })
        {
            var added = 0;
            foreach (var raw in rule.ExtraIps)
            {
                if (IPAddress.TryParse(raw, out var ip) && IsUsable(ip) && seen.Add(ip))
                {
                    result.Add(ip);
                    added++;
                }
            }
            if (added > 0)
                Note($"规则追加候选：{added} 个");
        }

        foreach (var ip in await ResolveViaDohAsync(host, ct))
        {
            if (seen.Add(ip)) result.Add(ip);
        }

        try
        {
            // 必须走 SystemDnsQuery 而不是 Dns.GetHostAddressesAsync：
            // 后者遵循 hosts，而 hosts 模式下规则域名正好被我们指向了 127.0.0.1，
            // 于是这个来源拿到的永远是环回（过滤后 0 条），等于失效。
            var system = await SystemDnsQuery.ResolveAsync(host, ct);
            var accepted = 0;
            foreach (var ip in system)
            {
                if (IsUsable(ip) && seen.Add(ip)) { result.Add(ip); accepted++; }
            }
            Note($"系统 DNS：返回 {system.Count} 条，采纳 {accepted} 条");
        }
        catch (Exception ex)
        {
            Note($"系统 DNS 失败：{ex.GetType().Name}");
        }

        var before = result.Count;
        ExpandNeighbors(result, seen);
        if (result.Count > before)
            Note($"候选偏少，向同网段扩展：{before} → {result.Count} 个");

        return result;
    }

    /// <summary>
    /// 候选向同 /24 网段做小幅扩展。
    ///
    /// 大型站点（GitHub、Steam CDN）的负载均衡在同一网段里排着一串等价 IP，
    /// 但 DoH 往往只返回其中一两个——恰好那个在当前网络不通时，优选就没得选了。
    /// 往两边各探几个，常能把同段里可用的兄弟节点捞出来。
    ///
    /// 只在候选偏少时启用，避免对 IP 段做过多的无谓连接尝试。
    /// </summary>
    private static void ExpandNeighbors(List<IPAddress> candidates, HashSet<IPAddress> seen, int radius = 6)
    {
        if (candidates.Count is 0 or >= 4)
            return;

        foreach (var baseBytes in candidates.Select(c => c.GetAddressBytes()).ToList())
        {
            for (var delta = -radius; delta <= radius; delta++)
            {
                if (delta == 0)
                    continue;

                var last = baseBytes[3] + delta;
                if (last is < 1 or > 254)
                    continue;

                var ip = new IPAddress(new[] { baseBytes[0], baseBytes[1], baseBytes[2], (byte)last });
                if (seen.Add(ip))
                    candidates.Add(ip);
            }
        }
    }

    /// <summary>
    /// 过滤掉不该参与优选的 IP。
    /// 127.0.0.0/8 尤其重要：本机 443 上跑着别的服务（或者就是自己）时，
    /// 它会以 0ms 的假延迟拿到第一名，直接把流量打成自环。
    /// </summary>
    private static bool IsUsable(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return false;

        var b = ip.GetAddressBytes();
        return (b[0]) switch
        {
            0 => false,                              // 0.0.0.0/8
            10 => false,                             // 私有
            127 => false,                            // 环回 -> 自环炸弹
            >= 224 => false,                         // 组播与保留段
            169 => b[1] != 254,                      // 169.254.0.0/16 链路本地
            172 => b[1] is < 16 or > 31,             // 172.16.0.0/12
            192 => b[1] != 168,                      // 192.168.0.0/16
            _ => true,
        };
    }

    private static List<IPAddress> ParseAll(string[] raw)
    {
        var list = new List<IPAddress>();
        foreach (var s in raw)
        {
            if (IPAddress.TryParse(s, out var ip) && IsUsable(ip))
                list.Add(ip);
        }
        return list;
    }

    private async Task<List<IPAddress>> ResolveViaDohAsync(string host, CancellationToken ct)
    {
        // 全部来源累加，候选池越大优选空间越大
        var found = new List<IPAddress>();
        var seen = new HashSet<IPAddress>();

        foreach (var template in DohTemplates)
        {
            try
            {
                var url = string.Format(template, Uri.EscapeDataString(host));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(TimeSpan.FromSeconds(5));

                await using var stream = await DohClient.GetStreamAsync(url, linked.Token);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: linked.Token);

                if (doc.RootElement.TryGetProperty("Answer", out var answers))
                {
                    foreach (var answer in answers.EnumerateArray())
                    {
                        if (!answer.TryGetProperty("type", out var type) || type.GetInt32() != 1)
                            continue;
                        if (!answer.TryGetProperty("data", out var data))
                            continue;
                        if (IPAddress.TryParse(data.GetString(), out var ip) && IsUsable(ip) && seen.Add(ip))
                            found.Add(ip);
                    }
                }

                Note($"DoH {HostOf(template)}：采纳 {found.Count} 条");
            }
            catch (Exception ex)
            {
                Note($"DoH {HostOf(template)} 失败：{ex.GetType().Name} {Truncate(ex.Message)}");
            }
        }

        return found;
    }

    private static string HostOf(string template)
    {
        try { return new Uri(template).Host; }
        catch { return template; }
    }

    private static string Truncate(string s) => s.Length <= 60 ? s : s[..60] + "…";

    private static async Task<List<ProbeResult>> ProbeManyAsync(
        List<IPAddress> candidates,
        int port,
        string upstreamHost,
        string? sniOverride,
        bool allWithData,
        CancellationToken ct)
    {
        if (candidates.Count == 0)
            return [];

        // 第一阶段：并行做 TCP + TLS 握手。这一步便宜，可以放开并发。
        using var throttle = new SemaphoreSlim(MaxProbeConcurrency);
        var handshakes = await Task.WhenAll(candidates.Select(async ip =>
        {
            await throttle.WaitAsync(ct);
            try
            {
                return await ProbeOneAsync(ip, port, upstreamHost, sniOverride, withData: false, ct);
            }
            finally
            {
                throttle.Release();
            }
        }));

        // 第二阶段：补发真实请求，看对方给不给正常响应。
        //
        // 只给**按握手耗时排在最前面的几个**补测，而且**串行**做。两个原因：
        //   1. 省时间 —— 候选可能有十几个，逐个补测太慢；
        //   2. **同时向对方发十几个请求很容易被限流**，结果全部超时、
        //      什么也测不出来，还把原本有效的握手耗时排序也弄丢了。
        //      实测吃过这个亏：并行补测时全表变成 5005ms 超时。
        var ordered = handshakes
            .Where(r => r.Reachable)
            .OrderBy(r => r.CertificateValid ? 0 : 1)
            .ThenBy(r => r.TotalMs)
            .ToList();

        // **必须给足候选做真实请求补测，不能只测"握手最快的前几个"。**
        //
        // 这里曾经是 `DataCheckCount = 4`，而它是"优选反复选中空壳"的最后一环：
        // 排序 <see cref="Rank"/> 的第 3 位是 `LooksEmpty`，而**只有补测过的候选才有体积**
        // ——没补测的候选体积为 null、`LooksEmpty` 恒为 false，于是它和真首页出口
        // 在"空壳"这一档上打平，接着比 `HealthRank`（两者都是 0），最后按握手耗时决胜，
        // 空壳 `.169` 通常更快 → 被选中 → 用户白屏。
        //
        // 实测（2026-10-16，干净链路）：`.166` 的握手耗时经常不在最前面，
        // 于是它常常掉在"前 4 快"之外、**从未被补测**，体积永远是 null。
        // 诊断表（<see cref="DiagnoseAsync"/>，会补测全部候选）显示 `.166` 排第一，
        // 而真实转发却选中 `.169` —— 这个矛盾就是本条造成的。
        //
        // 补测是串行的（见下），单次几百毫秒，候选池通常只有十来个，代价可接受；
        // 而选错出口的代价是用户看到白屏，两者不对等。
        var toCheck = allWithData ? ordered : ordered.Take(DataCheckCount).ToList();

        var checkedMap = new Dictionary<IPAddress, ProbeResult>();
        foreach (var candidate in toCheck)
        {
            ct.ThrowIfCancellationRequested();
            checkedMap[candidate.Address] =
                await ProbeOneAsync(candidate.Address, port, upstreamHost, sniOverride, withData: true, ct);
        }

        return [.. handshakes.Select(r => checkedMap.GetValueOrDefault(r.Address, r))];
    }

    private static async Task<ProbeResult> ProbeOneAsync(
        IPAddress address,
        int port,
        string upstreamHost,
        string? sniOverride,
        bool withData,
        CancellationToken ct)
    {
        var sni = string.IsNullOrWhiteSpace(sniOverride) ? upstreamHost : sniOverride!;
        var sw = Stopwatch.StartNew();
        var certValid = false;

        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(ProbeTimeout);

            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                await using var cancelRegistration = linked.Token.Register(
                    static state => { try { ((Socket)state!).Dispose(); } catch { } }, socket);

                await socket.ConnectAsync(new IPEndPoint(address, port), linked.Token);

                var network = new NetworkStream(socket, ownsSocket: true);
                await using var ssl = new SslStream(
                    network,
                    leaveInnerStreamOpen: false,
                    (_, _, _, errors) =>
                    {
                        certValid = errors == SslPolicyErrors.None;
                        return true;   // 探测阶段接受一切 Ping，是否有效另行判定
                    });

                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = sni,
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    // 不设置 ApplicationProtocols => 不发送 ALPN，上游会回落 HTTP/1.1
                }, linked.Token);

                // 握手耗时就是排序用的"耗时"，**必须在补测之前停下来**：
                // 补测可能超时，让它覆盖掉 TotalMs 会把各出口的延迟差异抹平，
                // 排序退化成随机 —— 这个坑踩过，见 ProbeResult.DataFlowing。
                sw.Stop();
                var handshakeMs = sw.ElapsedMilliseconds;

                if (!withData)
                    return new ProbeResult(address, true, certValid, handshakeMs, null, false, null);

                var flowing = false;
                int? status = null;
                ResponseSize? size = null;
                string? dataError = null;
                try
                {
                    // 补测用更短的超时：一条健康的出口几百毫秒就回状态行了
                    using var dataCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    dataCts.CancelAfter(DataProbeTimeout);

                    (flowing, status, size) = await MeasureResponseAsync(ssl, upstreamHost, dataCts.Token);
                    if (!flowing)
                        dataError = "响应流立即结束（0 字节）";
                }
                catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
                {
                    dataError = $"{ex.GetType().Name}: {ex.Message}";
                }

                return new ProbeResult(address, true, certValid, handshakeMs, dataError, flowing, status, size);
            }
            finally
            {
                socket.Dispose();
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new ProbeResult(
                address,
                false,
                false,
                long.MaxValue / 4,
                $"{ex.GetType().Name}: {ex.Message}",
                DataFlowing: false,
                StatusCode: null);
        }
    }

    /// <summary>
    /// 发一个最小请求，读出**完整响应头**、并做一次有界正文探测。
    ///
    /// 为什么必须读完整头部、而不是像以前那样"读到换行就收手"：
    /// 只读状态行会漏掉 <c>Content-Length</c>，于是分不清
    /// **`200 OK` + 约 572 KB 真首页** 和 **`200 OK` + 4 字节空壳**。
    /// 旧实现把两者当等价，按耗时挑了更快的那 4 字节空壳，
    /// 用户浏览器里就是"能连上 GitHub、但页面全白"。
    ///
    /// **刻意不发 `Range`**（这里踩过一个大坑）：早先为了"只取一个字节"
    /// 发了 `Range: bytes=0-0`，结果真首页出口 `.166` 回的是
    /// `206 Partial Content` + `content-range: bytes 0-0/*` ——
    /// 总量是通配符 `*`，等于**把唯一可用的体积信号自己毁掉了**，
    /// 探测只能量到十几个字节，反而比空壳的 4 字节只好一点。
    /// 于是排序每次都在两个出口之间随机，用户看到的就是"有时白屏"。
    /// 用不带 Range 的普通 GET，`.166` 会正常回
    /// `200 OK` + `Server: github.com` + `Transfer-Encoding: chunked`。
    ///
    /// 用 GET 而不是 HEAD：个别中间盒会拦 HEAD 却放行 GET，
    /// 用 HEAD 可能把好出口误判成坏出口。
    ///
    /// 正文**只探不读**：优先采信头里的 <c>Content-Length</c>（零成本，
    /// 对 codeload 那种几十兆的包也不下载），没有声明长度时才看实际读到多少字节，
    /// 并记录对端是否已结束响应（见 <see cref="ResponseSize.EndOfResponseReached"/>）。
    /// </summary>
    private static async Task<(bool Flowing, int? Status, ResponseSize? Size)> MeasureResponseAsync(
        Stream ssl, string host, CancellationToken ct)
    {
        var request = Encoding.ASCII.GetBytes(
            $"GET / HTTP/1.1\r\n"
            + $"Host: {host}\r\n"
            + "User-Agent: LocalBoost-probe\r\n"
            + "Accept: */*\r\n"
            + "Connection: close\r\n\r\n");

        await ssl.WriteAsync(request, ct);
        await ssl.FlushAsync(ct);

        // ---------------------------------------------------------------- 第一步：读响应头
        //
        // 用**整个**补测预算把头部读全：这一步的产物（状态码 + Content-Length）
        // 才是全部结论的来源，值得花时间。慢链路上头部本来就可能分几段到达，
        // 只读一次就下结论会把头部字节误当成正文（本项目踩过这个坑）。
        const int HeaderCap = 8 * 1024;
        var buffer = new byte[HeaderCap];
        var total = 0;
        var headerEnd = -1;

        while (total < buffer.Length)
        {
            var read = await ssl.ReadAsync(buffer.AsMemory(total), ct);
            if (read <= 0)
                break;                      // 对端关连接，手上有多少算多少

            total += read;
            headerEnd = FindHeaderEnd(buffer, total);
            if (headerEnd >= 0)
                break;
        }

        if (total == 0)
            return (false, null, null);

        var status = ParseStatusCode(buffer, total);

        // 状态行还没读全就断了，当成拿不到数据 —— 半行状态码会解析成 null，
        // 混进排序里会把"没响应"当成"响应了但没有状态码"。
        if (status is null)
            return (false, null, null);

        // 一：服务器自己声明了正文长度（最可靠，且与当前网络相位无关）
        if (TryParseContentLength(buffer, total, out var declared))
            return (true, status, new ResponseSize(declared, Declared: true));

        // ---------------------------------------------------------------- 第二步：判断正文
        //
        // 头部**读全了**，空行之后的字节就是正文，数得准。
        // 头部没读全（读满上限还没见空行 = 头部超 8 KB，或连接中途断）时，
        // 手上的字节里混着头部本身，**不能拿来当正文大小** ——
        // 宁可留着 Size 为 null（表示"没量到"），也不要编一个数字出来。
        var bodyBytes = headerEnd >= 0 ? Math.Max(0, total - headerEnd) : 0;

        // 头部本身就超 8 KB，说明正文不可能是空的
        if (headerEnd < 0 && total >= buffer.Length)
            bodyBytes = 1;

        // 还没碰到正文就继续读到**能判定**为止。
        //
        // **这一段的读取量是本轮排查的关键**，别缩回去：
        // 实测真首页出口 `.166` 的首字节 0.32~0.49 秒就到，而且首块就是几十 KB；
        // 空壳出口 `.169` 则恒定只给 4 个字节然后干净关闭。
        // 早先这里只读 1 个字节（`AsMemory(0, 1)`）就收手，于是两种情况都只拿到
        // 十几个字节，**根本分不出谁是谁** —— 整个工具因此反复选中空壳出口。
        //
        // **注意别把 `bodyBytes` 重置**：正文的头几个字节经常和响应头
        // 同在一个 TLS 记录里到达，早就落在 `buffer` 里了；
        // 早先的实现在这里从 0 重新计数，于是 `.166` 被量成 `~11字节`
        // （只数到了后续补读的那点），比空壳的 `~4字节` 只好一点 —— 排序因此失效。
        //
        // 另外记录 `EndOfResponseReached`：只有对端**干净结束**这条响应
        // （`Connection: close` 后读到 0 字节）时，手上的字节数才等于真实正文大小。
        // 链路抖动时真首页会传到一半卡住，那种情况必须算"没传完"，不能算空壳。
        //
        // **正文要一直读到 `BodyReadCap`，不能只读到"够阈值就收手"**：
        // 阈值只用来判定"有没有内容"，而体积是用来横向比较谁更可信的，
        // 多读一点信息量就大一点。实测 `.166` 的第一个 TLS 记录只带 1 KB 左右，
        // 收手早了就会把它记成 `~1KB`，看着和空壳没差多少。
        var endOfResponse = false;

        if (headerEnd >= 0 && bodyBytes < BodyReadCap)
        {
            var body = new byte[16 * 1024];
            var spent = TimeSpan.Zero;

            while (bodyBytes < BodyReadCap)
            {
                try
                {
                    using var peek = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    peek.CancelAfter(BodyPeekGrace);
                    var readStart = Stopwatch.GetTimestamp();

                    var read = await ssl.ReadAsync(body, peek.Token);
                    if (read <= 0)
                    {
                        endOfResponse = true;   // 对端干净结束：手上的字节就是全部正文
                        break;
                    }

                    bodyBytes += read;

                    // 每个候选最多花 BodyPeekBudget 等正文：慢出口要给机会，
                    // 但整个探测不能耗到用户等不下去。
                    spent += Stopwatch.GetElapsedTime(readStart);
                    if (spent >= BodyPeekBudget)
                        break;
                }
                catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
                {
                    // 等不到更多正文（超时/被重置）：用手上已有的字节判定，
                    // 但这属于"没传完"，**不能**据此判空壳
                    break;
                }
            }
        }

        return (true, status, bodyBytes > 0
            ? new ResponseSize(bodyBytes, Declared: false, EndOfResponseReached: endOfResponse)
            : null);
    }

    /// <summary>找到头部与正文之间的那个空行，返回正文起始下标（\r\n\r\n 或 \n\n）。</summary>
    private static int FindHeaderEnd(byte[] buffer, int length)
    {
        for (var i = 2; i < length; i++)
        {
            if (buffer[i] == (byte)'\n')
            {
                if (buffer[i - 1] == (byte)'\n')
                    return i + 1;
                if (i >= 3 && buffer[i - 1] == (byte)'\r' && buffer[i - 2] == (byte)'\n' && buffer[i - 3] == (byte)'\r')
                    return i + 1;
            }
        }

        return -1;
    }

    /// <summary>
    /// 从响应头里取 Content-Length。取不到（chunked、或头部不完整）时返回 false。
    ///
    /// 按大小写不敏感匹配：服务器里 Content-Length / content-length 都出现过。
    /// </summary>
    internal static bool TryParseContentLength(byte[] buffer, int length, out long value)
    {
        value = 0;

        var text = Encoding.ASCII.GetString(buffer, 0, length);
        var at = 0;

        while (true)
        {
            var lineEnd = text.IndexOf('\n', at);
            var line = lineEnd < 0 ? text[at..] : text[at..lineEnd];
            line = line.TrimEnd('\r');

            if (line.Length == 0)
                break;      // 头部结束，别把正文里的内容当头部解析

            var colon = line.IndexOf(':');
            if (colon > 0 && line.AsSpan(0, colon).Trim()
                    .Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                var raw = line[(colon + 1)..].Trim();
                if (long.TryParse(raw, out value) && value >= 0)
                    return true;

                break;      // 头里有这一项但值不合法，不猜
            }

            if (lineEnd < 0)
                break;

            at = lineEnd + 1;
        }

        return false;
    }

    /// <summary>从 "HTTP/1.1 200 OK" 里取 200。拿不到就返回 null。</summary>
    internal static int? ParseStatusCode(byte[] buffer, int length)
    {
        var text = Encoding.ASCII.GetString(buffer, 0, length);
        var space = text.IndexOf(' ');
        if (!text.StartsWith("HTTP/", StringComparison.Ordinal) || space < 0)
            return null;

        var code = 0;
        for (var i = space + 1; i < text.Length && char.IsAsciiDigit(text[i]); i++)
            code = (code * 10) + (text[i] - '0');

        return code is >= 100 and <= 599 ? code : null;
    }

    /// <summary>
    /// 出口的"可用度"，**越小越好**（<see cref="Rank"/> 按升序排）。
    ///
    /// 同一台服务器的不同边缘 IP 表现可能不同：实测 github.com 的出口里
    /// 有的返回 200、有的返回 400/403。所以状态码必须参与排序 ——
    /// 否则数据一样"通"，挑中最快的那个坏出口，用户浏览器里就是错误页。
    ///
    /// 空壳取**最大值**（最差），排在 5xx 之后：它比任何显式错误都难用 ——
    /// 4xx/5xx 会让浏览器显示对方的错误页，用户至少知道"这站有问题"；
    /// 空壳是白屏，用户只会以为"网络又不行了 / 这软件没用"，根本无从排查。
    /// （注意这里数值大 = 差，别写成 0。）
    /// </summary>
    private static int HealthRank(ProbeResult r) => r switch
    {
        { Reachable: false } => 5,
        { DataFlowing: false } => 4,
        { LooksEmpty: true } => 3,
        { StatusCode: >= 500 } => 2,
        { StatusCode: >= 400 } => 1,
        _ => 0,     // 2xx / 3xx，以及拿到数据但没解析出状态码的情况
    };
}
