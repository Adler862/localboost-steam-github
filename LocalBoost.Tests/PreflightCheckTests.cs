using System.Text;

namespace LocalBoost.Tests;

/// <summary>
/// 转发**前**的候选预检判定。
///
/// 这一层被删掉过一次又加回来，两个原因都必须由测试钉住，否则很容易再退回去：
///
///   1. **206 要放行**：唯一可用的 github.com 出口（20.205.243.166）对
///      `Range: bytes=0-0` 回 `206 Partial Content`，正文只有十几字节。
///      早期实现按"正文少于阈值"判空壳，把它连同真空壳一起否掉了 ——
///      结果是整个候选池被否决，比不加预检更糟。
///
///   2. **读得少 ≠ 坏**：首字节出得慢的出口在读窗口里只能攒到几个字节。
///      只要没有确凿证据，就必须返回 Unknown（不否决），而不是 Bad。
/// </summary>
public sealed class PreflightCheckTests
{
    /// <summary>构造一段响应字节，返回 (字节, 长度, 正文起始下标)。</summary>
    private static (byte[] Buffer, int Total, int HeaderEnd) Build(string head, int bodyBytes = 0)
    {
        var headBytes = Encoding.ASCII.GetBytes(head + "\r\n\r\n");
        var total = headBytes.Length + bodyBytes;
        var buffer = new byte[Math.Max(total, 1)];
        headBytes.CopyTo(buffer, 0);

        for (var i = headBytes.Length; i < total; i++)
            buffer[i] = (byte)'x';      // 正文内容无关紧要，判定只看长度

        return (buffer, total, headBytes.Length);
    }

    private static PreflightCheck.Verdict Judge(string head, int bodyBytes = 0)
    {
        var (buffer, total, headerEnd) = Build(head, bodyBytes);
        return PreflightCheck.Judge(buffer, total, headerEnd);
    }

    // ---------------------------------------------------------------- 必须放行

    [Fact]
    public void 声明大体积的二百响应放行()
    {
        // 实测直连 20.205.243.166 拿到 572,394 字节真首页
        Assert.Equal(PreflightCheck.Verdict.Good,
            Judge("HTTP/1.1 200 OK\r\nContent-Length: 572394"));
    }

    [Fact]
    public void 二百零六带内容要放行()
    {
        // **这条是这层被删掉又加回来的核心原因**：
        // 唯一能给出真首页的出口对 Range 请求回 206，正文只有十几字节。
        // 按"正文少于 512 就是空壳"去判，会把它和真空壳一起否掉。
        Assert.Equal(PreflightCheck.Verdict.Good,
            Judge("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/572394", bodyBytes: 11));
    }

    [Fact]
    public void 分块响应攒够字节就放行()
    {
        Assert.Equal(PreflightCheck.Verdict.Good,
            Judge("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked", bodyBytes: 4096));
    }

    [Fact]
    public void 重定向即使正文为空也放行()
    {
        // 实测 raw.githubusercontent.com 根路径回 301 + 0 字节，这是正常的
        Assert.Equal(PreflightCheck.Verdict.Good,
            Judge("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0"));
    }

    [Fact]
    public void 阈值边界上放行()
    {
        Assert.Equal(PreflightCheck.Verdict.Good,
            Judge($"HTTP/1.1 200 OK\r\nContent-Length: {PreflightCheck.MinBodyBytes}"));
    }

    // ---------------------------------------------------------------- 必须否决

    [Fact]
    public void 声明四字节的二百响应要否决()
    {
        // 实测抓到的原始空壳形态：状态 200、Content-Length: 4。
        // 它在连接层完全健康，建连 failover 永远轮不到它，只能在这里拦下。
        Assert.Equal(PreflightCheck.Verdict.Bad,
            Judge("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4"));
    }

    [Fact]
    public void 阈值差一字节就否决()
    {
        Assert.Equal(PreflightCheck.Verdict.Bad,
            Judge($"HTTP/1.1 200 OK\r\nContent-Length: {PreflightCheck.MinBodyBytes - 1}"));
    }

    [Theory]
    [InlineData(400)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(429)]
    [InlineData(500)]
    [InlineData(503)]
    public void 错误状态一律否决(int status)
    {
        // 实测这些出口确实存在：.161 回 400、.167 回 403、.162 回 404，
        // 而且它们握手都最快，只看耗时会全被选中。
        Assert.Equal(PreflightCheck.Verdict.Bad,
            Judge($"HTTP/1.1 {status} Whatever\r\nContent-Length: 1440"));
    }

    // ---------------------------------------------------------------- 必须不否决

    [Fact]
    public void 读得少但无确凿证据时不否决()
    {
        // **这条是另一个必须钉住的教训**：首字节出得慢的出口在读窗口里
        // 只能攒到几个字节。没有确凿证据就否决它，就会把唯一可用的出口误杀。
        // 必须返回 Unknown（不否决），让调用方继续读或交给真实请求。
        Assert.Equal(PreflightCheck.Verdict.Unknown,
            Judge("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked", bodyBytes: 4));
    }

    [Fact]
    public void 二百零六但一字节正文都没有时不放行也不否决()
    {
        // 206 却没正文属于"没看明白"，既不该据此放行，也不该据此否决
        Assert.Equal(PreflightCheck.Verdict.Unknown,
            Judge("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/572394", bodyBytes: 0));
    }

    [Fact]
    public void 状态行都没读全时不否决()
    {
        var shortBuffer = Encoding.ASCII.GetBytes("HTTP/1.1 2");
        Assert.Equal(PreflightCheck.Verdict.Unknown,
            PreflightCheck.Judge(shortBuffer, shortBuffer.Length, -1));
    }

    [Fact]
    public void 不是HTTP响应时不否决()
    {
        var garbage = Encoding.ASCII.GetBytes("something else entirely, not http at all");
        Assert.Equal(PreflightCheck.Verdict.Unknown, PreflightCheck.Judge(garbage, garbage.Length, -1));
        Assert.Equal(PreflightCheck.Verdict.Unknown, PreflightCheck.Judge([], 0, -1));
    }

    [Fact]
    public void 状态码位数不对时不否决()
    {
        var (b1, t1, h1) = Build("HTTP/1.1 99 Weird");
        Assert.Equal(PreflightCheck.Verdict.Unknown, PreflightCheck.Judge(b1, t1, h1));

        var (b2, t2, h2) = Build("HTTP/1.1 9999 Weird");
        Assert.Equal(PreflightCheck.Verdict.Unknown, PreflightCheck.Judge(b2, t2, h2));
    }

    // ---------------------------------------------------------------- 判据一致性

    [Fact]
    public void 预检阈值与探测和转发阶段完全一致()
    {
        // 三处必须用同一个阈值。任何一处走偏，都会出现
        // "探测说它好、预检说它坏、转发又出一半"这种自相矛盾的现象。
        Assert.Equal(ProbeResult.EmptyBodyThreshold, PreflightCheck.MinBodyBytes);
        Assert.Equal(StubDetector.Threshold, PreflightCheck.MinBodyBytes);
    }
}
