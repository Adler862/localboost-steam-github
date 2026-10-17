namespace LocalBoost.Tests;

/// <summary>
/// PAC 生成。这是纯字符串输出，也恰好是最容易被改坏又难察觉的地方：
/// 语法错一点浏览器就整份 PAC 失效，而它只影响"部分域名"，很容易被当成别的问题。
/// </summary>
public sealed class PacScriptTests
{
    private const int Port = 18080;

    [Fact]
    public void 精确域名用严格相等匹配()
    {
        var pac = PacScript.Build(TestData.WithHosts("github.com"), Port);

        Assert.Contains("if (host === \"github.com\") return proxy;", pac);
    }

    [Fact]
    public void 通配域名用带前导点的_dnsDomainIs()
    {
        var pac = PacScript.Build(TestData.WithHosts("*.github.io"), Port);

        // 前导点是关键：没有它就退化成"只比后缀"，和审查报告 P1-2 是同一类错误
        Assert.Contains("if (dnsDomainIs(host, \".github.io\")) return proxy;", pac);
    }

    [Fact]
    public void 通配域名不会被写成严格相等()
    {
        var pac = PacScript.Build(TestData.WithHosts("*.github.io"), Port);

        Assert.DoesNotContain("host === \"*.github.io\"", pac);
        Assert.DoesNotContain("=== \".github.io\"", pac);
    }

    [Fact]
    public void 端口写进代理指令()
    {
        var pac = PacScript.Build(TestData.WithHosts("github.com"), 12345);

        Assert.Contains("var proxy = \"PROXY 127.0.0.1:12345\";", pac);
    }

    [Fact]
    public void 没有规则时非规则域名直连()
    {
        var pac = PacScript.Build(TestData.Empty(), Port);

        Assert.Contains("return \"DIRECT\";", pac);
    }

    [Fact]
    public void 兜底指令可替换为原有代理()
    {
        // 用户本来配着手工代理时，PAC 兜底必须沿用那个代理，
        // 否则没被接管的流量会从"走代理"悄悄变成"直连"
        var pac = PacScript.Build(TestData.WithHosts("github.com"), Port, "PROXY 10.0.0.1:8080");

        Assert.Contains("return \"PROXY 10.0.0.1:8080\";", pac);
        Assert.DoesNotContain("return \"DIRECT\";", pac);
    }

    [Fact]
    public void 输出只含_ASCII()
    {
        // PAC 由 WinINET 的脚本引擎解析，非 ASCII 字节的读法取决于系统代码页。
        // 注释里混进中文就有可能被误解，所以生成物一律保持纯 ASCII。
        var pac = PacScript.Build(TestData.WithHosts("github.com", "*.github.io"), Port);

        Assert.All(pac, c => Assert.True(c <= 0x7F, $"发现了非 ASCII 字符：U+{(int)c:X4}"));
    }

    [Fact]
    public void 结构完整且以右花括号收尾()
    {
        var pac = PacScript.Build(TestData.WithHosts("github.com"), Port);

        Assert.Contains("function FindProxyForURL(url, host) {", pac);
        Assert.Contains("host = host.toLowerCase();", pac);
        Assert.Contains("return \"DIRECT\";", pac);
        Assert.EndsWith($"}}{Environment.NewLine}", pac);
    }

    [Fact]
    public void 域名按字典序输出_结果可重现()
    {
        var first = PacScript.Build(TestData.WithHosts("store.steampowered.com", "github.com", "api.github.com"), Port);
        var second = PacScript.Build(TestData.WithHosts("api.github.com", "github.com", "store.steampowered.com"), Port);

        Assert.Equal(first, second);
    }

    [Fact]
    public void 精确域名排在通配域名之前()
    {
        var pac = PacScript.Build(TestData.WithHosts("*.github.io", "github.com"), Port);

        var exactAt = pac.IndexOf("host === \"github.com\"", StringComparison.Ordinal);
        var suffixAt = pac.IndexOf("dnsDomainIs", StringComparison.Ordinal);

        Assert.True(exactAt >= 0 && suffixAt >= 0 && exactAt < suffixAt);
    }
}
