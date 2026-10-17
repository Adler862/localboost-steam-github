using System.Text;

namespace LocalBoost.Tests;

/// <summary>
/// 响应头里的 Content-Length 解析。
///
/// 这一项是"空壳出口"的唯一可靠判据：实测 github.com 的
/// 20.205.243.166 返回 200 + 572,846 字节真首页，
/// 而 20.205.243.169 返回 **200 + 4 字节空体**。
/// 只看状态行分不出这两者，用户浏览器里就是"能连上、页面全白"。
///
/// 解析出错只会静默返回 false（退回"看实际读到多少字节"），不会崩，
/// 所以值得钉住。
/// </summary>
public sealed class ResponseHeaderTests
{
    private static bool TryParse(string text, out long value) =>
        IpOptimizer.TryParseContentLength(Encoding.ASCII.GetBytes(text), Encoding.ASCII.GetByteCount(text), out value);

    private static long Parse(string text) => TryParse(text, out var v) ? v : -1;

    [Fact]
    public void 取出声明长度()
    {
        Assert.Equal(572846, Parse("HTTP/1.1 200 OK\r\nContent-Length: 572846\r\n\r\n"));
    }

    [Fact]
    public void 取出空壳的极小长度()
    {
        // 真实抓到的那一类：状态 200，正文只有 "OK\r\n" 四个字节
        Assert.Equal(4, Parse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n"));
    }

    [Theory]
    [InlineData("content-length: 1234\r\n\r\n")]
    [InlineData("CONTENT-LENGTH: 1234\r\n\r\n")]
    [InlineData("Content-Length:1234\r\n\r\n")]      // 冒号后没空格
    [InlineData("Content-Length:   1234   \r\n\r\n")] // 多余空白
    [InlineData("X-Other: 1\r\nContent-Length: 1234\r\n\r\n")]   // 前面还有别的头
    public void 大小写与空白都不影响解析(string header)
    {
        Assert.Equal(1234, Parse("HTTP/1.1 200 OK\r\n" + header));
    }

    [Fact]
    public void 值为零也要解析出来()
    {
        // 204 / 304 这类响应合法地声明 0 字节，不能当成"没声明"
        Assert.True(TryParse("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", out var v));
        Assert.Equal(0, v);
    }

    [Fact]
    public void 没有这一项时返回false()
    {
        // chunked 编码不声明长度，这时只能退回"看实际读到多少字节"
        Assert.False(TryParse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", out _));
    }

    [Fact]
    public void 头部还没读完时返回false()
    {
        // 只读到半个头，不能猜
        Assert.False(TryParse("HTTP/1.1 200 OK\r\nContent-Len", out _));
    }

    [Fact]
    public void 值不合法时不猜一个数字出来()
    {
        Assert.False(TryParse("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n", out _));
        Assert.False(TryParse("HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n", out _));
    }

    [Fact]
    public void 正文里的内容不会被当成头部()
    {
        // 头部已经结束（空行），后面正文里就算出现 "Content-Length:" 也不能采信
        Assert.False(TryParse("HTTP/1.1 200 OK\r\nServer: x\r\n\r\nContent-Length: 999999\r\n", out _));
    }

    [Fact]
    public void 状态行自己不能被误认成头部()
    {
        // 状态行里没有冒号，即便有也不能当成 Content-Length
        Assert.False(TryParse("HTTP/1.1 200 OK\r\n\r\n", out _));
    }
}
