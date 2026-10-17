using System.Text;

namespace LocalBoost.Tests;

/// <summary>
/// HTTP 状态行解析。
///
/// 这段决定"这个出口好不好用"的判断依据：同一台服务器的不同边缘 IP 表现可能不一样
/// （实测 github.com 有返回 200 的、也有返回 400/403 的），状态码解析错一次，
/// 优选就会挑中坏出口。属于出错也只会静默返回 null 的那类代码，值得钉住。
/// </summary>
public sealed class StatusLineTests
{
    private static int? Parse(string text) =>
        IpOptimizer.ParseStatusCode(Encoding.ASCII.GetBytes(text), Encoding.ASCII.GetByteCount(text));

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\n", 200)]
    [InlineData("HTTP/1.1 400 Bad Request\r\n", 400)]
    [InlineData("HTTP/1.1 403 Forbidden\r\n", 403)]
    [InlineData("HTTP/1.1 404 Site not found\r\n", 404)]
    [InlineData("HTTP/1.1 500 Internal Server Error\r\n", 500)]
    [InlineData("HTTP/1.0 301 Moved Permanently\r\n", 301)]
    [InlineData("HTTP/1.1 200 OK\r\nServer: Kestrel\r\n", 200)]
    public void 取出状态码(string line, int expected)
    {
        Assert.Equal(expected, Parse(line));
    }

    [Fact]
    public void 只有状态行没有后续内容也能解析()
    {
        Assert.Equal(204, Parse("HTTP/1.1 204"));
    }

    [Fact]
    public void 不是HTTP响应时返回null()
    {
        // TLS 握手成功但对方直接回二进制/乱码时，不能瞎猜一个状态码出来
        Assert.Null(Parse("something else entirely\r\n"));
        Assert.Null(Parse("\0\0\0\0"));
        Assert.Null(Parse(""));
    }

    [Fact]
    public void 状态码超出合理范围时返回null()
    {
        // 位数不足、或明显不是状态码的数字都当解析失败处理
        Assert.Null(Parse("HTTP/1.1 9 OK\r\n"));
        Assert.Null(Parse("HTTP/1.1 99999 OK\r\n"));
    }

    [Fact]
    public void 状态行被截断成半个数字时仍是null()
    {
        // 只读到 "HTTP/1.1 4" 的情况：4 不在 100~599 内，应当当作没拿到
        Assert.Null(Parse("HTTP/1.1 4"));
    }
}
