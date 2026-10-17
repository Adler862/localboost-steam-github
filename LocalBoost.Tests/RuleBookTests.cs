namespace LocalBoost.Tests;

/// <summary>
/// 规则表的匹配与字段校验。
///
/// 这里面「通配后缀不误命中形近域名」是审查报告 P1-2 的回归测试：
/// 当时写成 host.EndsWith(suffix)，导致 evilgithub.io 也会命中 *.github.io
/// 并被当成规则域名接管。
/// </summary>
public sealed class RuleBookTests
{
    // ------------------------------------------------------------ 匹配

    [Fact]
    public void 精确域名命中规则()
    {
        var rules = TestData.WithHosts("github.com");

        Assert.True(rules.TryGet("github.com", out var rule));
        Assert.Equal("T", rule.Tag);
    }

    [Fact]
    public void 域名匹配不区分大小写()
    {
        var rules = TestData.WithHosts("github.com");

        Assert.True(rules.TryGet("GitHub.COM", out _));
    }

    [Fact]
    public void 尾部点会被规范化后匹配()
    {
        var rules = TestData.WithHosts("github.com");

        // DNS 里 "github.com." 与 "github.com" 等价，根域名写法不该漏掉
        Assert.True(rules.TryGet("github.com.", out _));
    }

    [Fact]
    public void 通配后缀命中子域()
    {
        var rules = TestData.WithHosts("*.github.io");

        Assert.True(rules.TryGet("foo.github.io", out _));
        Assert.True(rules.TryGet("a.b.github.io", out _));
    }

    [Fact]
    public void 通配后缀不误命中形近域名()
    {
        var rules = TestData.WithHosts("*.github.io");

        // 关键回归点：缺少分隔点边界时这两个会命中，进而被本地反代接管
        Assert.False(rules.TryGet("evilgithub.io", out _));
        Assert.False(rules.TryGet("notgithub.io", out _));
    }

    [Fact]
    public void 通配后缀不匹配裸域()
    {
        var rules = TestData.WithHosts("*.github.io");

        // "*.github.io" 的语义是"子域"，不含裸域本身
        Assert.False(rules.TryGet("github.io", out _));
    }

    [Fact]
    public void 不在表内的域名不命中()
    {
        var rules = TestData.WithHosts("github.com", "*.github.io");

        Assert.False(rules.TryGet("example.com", out _));
        Assert.False(rules.TryGet("github.com.evil.example", out _));
    }

    [Fact]
    public void 停用的规则不参与匹配()
    {
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "enabled": false } ] }
            """);

        Assert.False(rules.TryGet("github.com", out _));
    }

    // ------------------------------------------------------------ 字段校验

    [Fact]
    public void 非法域名被丢弃并产生告警()
    {
        var rules = TestData.WithHosts("bad_host!", "github.com");

        Assert.True(rules.TryGet("github.com", out _));
        Assert.Contains(rules.Warnings, w => w.Contains("bad_host!"));
    }

    [Fact]
    public void 整条规则域名全非法时被跳过()
    {
        var rules = TestData.WithHosts("bad_host!", "has space");

        Assert.Empty(rules.Rules);
        Assert.Contains(rules.Warnings, w => w.Contains("整条规则已跳过"));
    }

    [Fact]
    public void 合法域名不带告警()
    {
        var rules = TestData.WithHosts("github.com", "*.github.io");

        Assert.Empty(rules.Warnings);
    }

    [Fact]
    public void 非法_serverName_被忽略并告警()
    {
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "serverName": "bad name!" } ] }
            """);

        Assert.Null(rules.Rules.Single().ServerName);
        Assert.Contains(rules.Warnings, w => w.Contains("serverName"));
    }

    [Fact]
    public void 启用_serverName_时必须产生安全告警()
    {
        // serverName 是唯一会削弱上游证书校验的字段，静默生效是不可接受的
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "serverName": "mirror.example.com" } ] }
            """);

        Assert.Equal("mirror.example.com", rules.Rules.Single().ServerName);
        Assert.Contains(rules.Warnings, w => w.Contains("SNI 改写"));
    }

    [Fact]
    public void 非法_staticIps_被丢弃()
    {
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "staticIps": ["1.2.3.4", "not-an-ip"] } ] }
            """);

        var ips = rules.Rules.Single().StaticIps;
        Assert.NotNull(ips);
        Assert.Equal(["1.2.3.4"], ips);
        Assert.Contains(rules.Warnings, w => w.Contains("staticIps"));
    }

    [Fact]
    public void 非法端口回退到_443()
    {
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "port": 99999 } ] }
            """);

        Assert.Equal(443, rules.Rules.Single().Port);
        Assert.Contains(rules.Warnings, w => w.Contains("端口"));
    }

    [Fact]
    public void 非法_upstream_被忽略并告警()
    {
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "upstream": "http://evil" } ] }
            """);

        Assert.Null(rules.Rules.Single().Upstream);
        Assert.Contains(rules.Warnings, w => w.Contains("upstream"));
    }

    // ------------------------------------------------------------ 上游解析

    [Fact]
    public void upstream_留空时上游就是请求的主机名()
    {
        var rules = TestData.WithHosts("github.com");
        var rule = rules.Rules.Single();

        Assert.Equal("github.com", RuleBook.UpstreamHostOf(rule, "github.com"));
    }

    [Fact]
    public void upstream_填写时按填写的走()
    {
        var rules = TestData.FromJson("""
            { "rules": [ { "tag": "T", "hosts": ["github.com"], "upstream": "mirror.example.com" } ] }
            """);

        Assert.Equal("mirror.example.com", RuleBook.UpstreamHostOf(rules.Rules.Single(), "github.com"));
    }

    // ------------------------------------------------------------ hosts 条目生成

    [Fact]
    public void 启用域名去重且不区分大小写()
    {
        var rules = TestData.WithHosts("github.com", "GitHub.com", "api.github.com");

        Assert.Equal(2, rules.EnabledHosts().Count());
    }
}
