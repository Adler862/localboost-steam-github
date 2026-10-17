using System.Net;

namespace LocalBoost.Tests;

/// <summary>
/// 出口优选排序。
///
/// 这组测试守的是一个真实踩过的坑：github.com 的 7 个边缘 IP，直连时
/// 有的返回 200（真首页）、有的返回 400 / 403 / 404。而优选一开始只看
/// 「握手/数据能不能通」，把它们当成等价的，于是按耗时挑中了最快的那个坏出口，
/// 用户浏览器里就是 GitHub 的 "Bad request" / "Whoa there!" 错误页。
/// 排序里必须让状态码参与，否则"更快的坏出口"永远赢。
/// </summary>
public sealed class ExitRankingTests
{
    private static ProbeResult Make(
        string ip, long ms, bool certValid = true, bool flowing = true, int? status = 200,
        ResponseSize? size = null) =>
        new(IPAddress.Parse(ip), Reachable: true, certValid, ms, null, flowing, status, size);

    /// <summary>补测量到了正文体积。</summary>
    /// <param name="bytes">正文字节数。</param>
    /// <param name="declared">是否来自 Content-Length 声明。</param>
    /// <param name="ended">
    /// 对端是否已结束这条响应。默认 true = "读到的就是全部正文"；
    /// 传 false 表示"链路抖动、传到一半卡住"（体积不可信，不能据此判空壳）。
    /// </param>
    private static ResponseSize Body(long bytes, bool declared = true, bool ended = true) =>
        new(bytes, declared, ended);

    [Fact]
    public void 返回正常状态的出口排在更快的坏出口前面()
    {
        var slowGood = Make("10.0.0.1", ms: 900, status: 200);
        var fastBad = Make("10.0.0.2", ms: 100, status: 403);

        var ranked = IpOptimizer.Rank([fastBad, slowGood]).ToList();

        Assert.Equal("10.0.0.1", ranked[0].Address.ToString());
    }

    [Fact]
    public void 拿不到数据的出口排在最后()
    {
        var good = Make("10.0.0.1", ms: 900, status: 200);
        var noData = Make("10.0.0.3", ms: 50, flowing: false, status: null);

        var ranked = IpOptimizer.Rank([noData, good]).ToList();

        Assert.Equal("10.0.0.1", ranked[0].Address.ToString());
        Assert.Equal("10.0.0.3", ranked[^1].Address.ToString());
    }

    [Fact]
    public void 五开头的状态比四开头更差()
    {
        var client = Make("10.0.0.1", ms: 500, status: 404);
        var server = Make("10.0.0.2", ms: 100, status: 503);

        var ranked = IpOptimizer.Rank([server, client]).ToList();

        Assert.Equal("10.0.0.1", ranked[0].Address.ToString());
    }

    [Fact]
    public void 证书名不匹配的出口仍然排在最后()
    {
        // 证书名不匹配时真实转发会直接失败（除非规则显式改写了 SNI），
        // 所以哪怕它返回 200、还更快，也不能排到前面去
        var certBad = Make("10.0.0.1", ms: 50, certValid: false, status: 200);
        var certGood = Make("10.0.0.2", ms: 900, certValid: true, status: 400);

        var ranked = IpOptimizer.Rank([certBad, certGood]).ToList();

        Assert.Equal("10.0.0.2", ranked[0].Address.ToString());
    }

    [Fact]
    public void 状态都一样时按耗时排()
    {
        var slow = Make("10.0.0.1", ms: 900, status: 200);
        var fast = Make("10.0.0.2", ms: 100, status: 200);

        var ranked = IpOptimizer.Rank([slow, fast]).ToList();

        Assert.Equal("10.0.0.2", ranked[0].Address.ToString());
    }

    [Fact]
    public void 连不上的候选直接不进入排序()
    {
        var unreachable = new ProbeResult(
            IPAddress.Parse("10.0.0.9"), Reachable: false, CertificateValid: false,
            long.MaxValue / 4, "boom", DataFlowing: false, StatusCode: null);
        var ok = Make("10.0.0.1", ms: 100, status: 200);

        var ranked = IpOptimizer.Rank([unreachable, ok]).ToList();

        Assert.Single(ranked);
        Assert.Equal("10.0.0.1", ranked[0].Address.ToString());
    }

    // ---------------------------------------------------------------- 空壳出口

    [Fact]
    public void 未补测的候选不能与已确认有空内容的候选打平()
    {
        // **这条守的是一个非常隐蔽的陷阱**，也是"优选反复选中空壳"的最后一环。
        //
        // 排序第 3 位是 LooksEmpty，而体积只有**补测过**的候选才有。
        // 没补测的候选 Size 为 null → LooksEmpty 恒为 false →
        // 它和真首页出口在"空壳"这一档打平，接着比 HealthRank（都是 0），
        // 最后按握手耗时决胜 —— 空壳 `.169` 通常更快，于是被选中。
        //
        // 这就是实测日志里真实发生的事：真实转发选了 `.169`、返回 502，
        // 而 probe（会补测全部候选）明明推荐 `.166`。
        //
        // 所以"未量到体积"必须排在"量到且确认有内容"之后，
        // 而不是与它并列 —— 拿未测量的东西去和已测量的比，等于没测。
        var unmeasured = Make("20.205.243.169", ms: 100, status: 200, size: null, flowing: false);
        var measured = Make("20.205.243.166", ms: 900, status: 200, size: Body(4096, declared: false, ended: false));

        Assert.False(unmeasured.LooksEmpty);   // 这一条本身没变，不能靠它兜底
        Assert.False(measured.LooksEmpty);

        var ranked = IpOptimizer.Rank([unmeasured, measured]).ToList();

        Assert.Equal("20.205.243.166", ranked[0].Address.ToString());
    }

    [Fact]
    public void 空壳出口排在更慢的真首页后面()
    {
        // 实测复现：169 返回 200 + 4 字节、握手更快；166 返回 200 + 572846 字节、握手更慢。
        // 旧判据认为两者等价，于是按耗时选中空壳，用户浏览器全白。
        var shell = Make("20.205.243.169", ms: 100, status: 200, size: Body(4));
        var real = Make("20.205.243.166", ms: 208, status: 200, size: Body(572846));

        var ranked = IpOptimizer.Rank([shell, real]).ToList();

        Assert.Equal("20.205.243.166", ranked[0].Address.ToString());
        Assert.Equal("20.205.243.169", ranked[^1].Address.ToString());
    }

    [Fact]
    public void 空壳比返回错误状态的出口还差()
    {
        // 400 至少让浏览器显示对方的错误页，用户知道"这站有问题"；
        // 空壳是白屏，只会被误判成"网络又不行了"，最难排查 —— 所以它垫底。
        // 同档内仍按状态码分：4xx 比 5xx 好、5xx 比空壳好。
        var shell = Make("10.0.0.1", ms: 50, status: 200, size: Body(4));
        var badRequest = Make("10.0.0.2", ms: 100, status: 400, size: Body(1440));
        var forbidden = Make("10.0.0.3", ms: 150, status: 403, size: Body(26));
        var serverError = Make("10.0.0.4", ms: 200, status: 503, size: Body(300));

        var ranked = IpOptimizer.Rank([shell, badRequest, forbidden, serverError]).ToList();

        Assert.Equal("10.0.0.2", ranked[0].Address.ToString());   // 400
        Assert.Equal("10.0.0.3", ranked[1].Address.ToString());   // 403
        Assert.Equal("10.0.0.4", ranked[2].Address.ToString());   // 503
        Assert.Equal("10.0.0.1", ranked[^1].Address.ToString());  // 空壳垫底
    }

    [Fact]
    public void 未量到体积的候选不算空壳()
    {
        // 一阶段只做了握手、没进补测的候选，Size 是 null。
        // 关键是**不能因为"没量到"就当成空壳** —— 那样每个未补测的回退候选
        // 都会被贴上空壳标签、被踢到最后，回退路径就没候选可用了。
        var unmeasured = Make("10.0.0.1", ms: 100, status: null, size: null, flowing: false);
        var shell = Make("10.0.0.2", ms: 90, status: 200, size: Body(4));

        Assert.False(unmeasured.LooksEmpty);

        var ranked = IpOptimizer.Rank([unmeasured, shell]).ToList();

        // 未补测的排在补测过的之后，这是既有设计；空壳则垫在补测组里
        Assert.Equal("10.0.0.2", ranked[0].Address.ToString());
        Assert.Equal("10.0.0.1", ranked[1].Address.ToString());
    }

    [Fact]
    public void 未声明长度且响应没结束时无论读到多少都不算空壳()
    {
        // **这条守的是一个比原缺陷更糟的自伤**：
        // chunked 响应没有 Content-Length，"读到了多少字节"只取决于读取时机 ——
        // 一个正常的大页面在慢链路上也可能只读到 64 字节。
        // 若拿实读字节数比阈值，大量正常网站会被误判成空壳、被踢到最后。
        //
        // 实测 github.com 的真首页出口 `.166` 正是这种形态：正文要 7~25 秒，
        // 链路抖动时会在传到 400~500 KB 处停住。它慢，但它不是空壳。
        var slowButReal = Make("10.0.0.1", ms: 50, status: 200, size: Body(64, declared: false, ended: false));
        var alsoReal = Make("10.0.0.2", ms: 50, status: 200, size: Body(1, declared: false, ended: false));

        Assert.False(slowButReal.LooksEmpty);
        Assert.False(alsoReal.LooksEmpty);
    }

    [Fact]
    public void 未声明长度但对端已结束响应且内容极少才算空壳()
    {
        // 未声明长度时唯一确定的情形：对端**干净结束了这条响应**，而总量就是那么点。
        // 实测空壳出口 `.169` 正是这种形态：`200 OK` + 4 字节 + `connection: close`，
        // 读到 4 个字节后就是 EOF —— 那 4 个字节就是全部内容。
        var shell = Make("10.0.0.1", ms: 50, status: 200, size: Body(4, declared: false, ended: true));
        Assert.True(shell.LooksEmpty);

        // 断言"结束"是必要条件：同样的 4 字节，只要响应还没结束，就不能判空壳。
        // 少了这一条，真首页出口 `.166` 会被误杀（它常停在几十~几百 KB 处）。
        var unfinished = Make("10.0.0.2", ms: 50, status: 200, size: Body(4, declared: false, ended: false));
        Assert.False(unfinished.LooksEmpty);

        // 一字节都没读到的情况由 "数据不通" 那一档先拦下，这里只核对不误判
        var nothing = Make("10.0.0.3", ms: 50, status: 200, flowing: false, size: Body(0, declared: false, ended: true));
        Assert.True(nothing.LooksEmpty);
    }

    [Fact]
    public void 阈值边界上不算空壳()
    {
        // 恰好等于阈值视为"有内容"：宁可放过一个可疑的小响应，也不要误杀一个可用出口
        var atThreshold = Make("10.0.0.1", ms: 500, status: 200, size: Body(ProbeResult.EmptyBodyThreshold));
        var justBelow = Make("10.0.0.2", ms: 100, status: 200, size: Body(ProbeResult.EmptyBodyThreshold - 1));

        Assert.False(atThreshold.LooksEmpty);
        Assert.True(justBelow.LooksEmpty);
    }

    [Fact]
    public void 内容少的错误状态不会被当成空壳()
    {
        // 4xx 本来就短（"LocalBoost: 403 Forbidden" 只有 26 字节），
        // 空壳专指"状态好但正文极小"。同样的体积、换个状态码，定性必须不同 ——
        // 否则每个 4xx 都会被贴上"空壳"标签，提示信息就失去意义了。
        var shortForbidden = Make("10.0.0.1", ms: 50, status: 403, size: Body(26));
        var shortOk = Make("10.0.0.2", ms: 50, status: 200, size: Body(26));

        Assert.False(shortForbidden.LooksEmpty);
        Assert.True(shortOk.LooksEmpty);
    }
}
