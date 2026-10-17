namespace LocalBoost.Tests;

/// <summary>
/// 空壳出口判定。
///
/// 守的是一个实测复现的坑：github.com 的边缘 IP 里有建连成功、TLS 成功、
/// 回 `200 OK`，正文只有 **4 个字节**的。这类出口在"建连 failover"眼里完全健康
/// （TCP 通、TLS 通、状态行也拿到了），于是永远不会被换掉，
/// 用户看到的是"能连上、页面一片白"。
///
/// 判定只依赖两件事：状态码是不是 2xx/3xx，以及**能确定的**正文体积。
/// 体积确定不了时必须判"不是空壳"——宁可漏判，也不要误杀一个可用出口。
/// </summary>
public sealed class StubDetectorTests
{
    private static StubDetector.StubTracker Declared(long length, int status = 200) =>
        new(status) { DeclaredLength = length };

    private static StubDetector.StubTracker Streamed(long bytes, int status = 200)
    {
        var tracker = new StubDetector.StubTracker(status);
        tracker.Add(bytes);
        return tracker;
    }

    [Fact]
    public void 声明四字节的二百响应算空壳()
    {
        // 实测抓到的原样：状态 200，正文 "OK\r\n" 共 4 字节
        Assert.True(Declared(4).LooksLikeStub());
    }

    [Fact]
    public void 声明五十七万字节的真首页不算空壳()
    {
        // 实测直连 20.205.243.166 拿到 572,394 字节真首页
        Assert.False(Declared(572_394).LooksLikeStub());
    }

    [Fact]
    public void 错误状态不归空壳管()
    {
        // 4xx/5xx 有自己的分档，不该被贴上"空壳"标签，
        // 否则日志里每个 403 都会报一次空壳，提示就失去意义
        Assert.False(Declared(4, status: 403).LooksLikeStub());
        Assert.False(Declared(4, status: 502).LooksLikeStub());
        Assert.False(Streamed(0, status: 404).LooksLikeStub());
    }

    [Fact]
    public void 重定向也算正常状态()
    {
        // 301 是合法的重定向（raw.githubusercontent.com 的根路径就回 301）
        Assert.False(Declared(0, status: 301).LooksLikeStub());
        Assert.True(Declared(0, status: 200).LooksLikeStub());
    }

    [Fact]
    public void 没有声明长度时按实际字节数判()
    {
        // chunked 响应没有 Content-Length，只能数转发出去的字节。
        // 实测 github.com 真首页就是 chunked —— 这条路必须能走通。
        Assert.True(Streamed(0).LooksLikeStub());
        Assert.True(Streamed(4).LooksLikeStub());
        Assert.False(Streamed(572_394).LooksLikeStub());
    }

    [Fact]
    public void 阈值边界上不算空壳()
    {
        // 恰好等于阈值视为"有内容"：宁可放过一个可疑的小响应，也不要误杀可用出口
        Assert.False(Declared(StubDetector.Threshold).LooksLikeStub());
        Assert.True(Declared(StubDetector.Threshold - 1).LooksLikeStub());
        Assert.False(Streamed(StubDetector.Threshold).LooksLikeStub());
        Assert.True(Streamed(StubDetector.Threshold - 1).LooksLikeStub());
    }

    [Fact]
    public void 判定阈值与探测阶段保持一致()
    {
        // 两处阈值必须相同，否则会出现"探测说它好、转发又说它坏"的自相矛盾
        Assert.Equal(ProbeResult.EmptyBodyThreshold, StubDetector.Threshold);
    }

    [Fact]
    public void 累积计数到上限后不再增长()
    {
        // 超过上限就不再累加，避免为已经很明确的大响应白费开销
        var tracker = new StubDetector.StubTracker(200);
        tracker.Add(StubDetector.CountCeiling);
        var first = tracker.Bytes;

        tracker.Add(1000);
        Assert.Equal(first, tracker.Bytes);
    }

    [Fact]
    public void 负数与非正数量不会污染计数()
    {
        var tracker = new StubDetector.StubTracker(200);
        tracker.Add(-100);
        tracker.Add(0);
        Assert.Equal(0, tracker.Bytes);
    }

    [Fact]
    public void 转发开始时的状态码被固定下来()
    {
        // 转发过程中状态码可能已被改写，判定要用开始时记下的那个
        var tracker = new StubDetector.StubTracker(200);
        Assert.Equal(200, tracker.StatusCode);
        Assert.True(tracker.LooksLikeStub());
    }
}
