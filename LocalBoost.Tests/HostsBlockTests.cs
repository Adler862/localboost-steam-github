namespace LocalBoost.Tests;

/// <summary>
/// hosts 托管区块的剥离逻辑。
///
/// 这是全项目唯一会改动用户已有文件的代码，写错的后果是用户的 hosts 被吃掉，
/// 所以值得用测试把边界情形钉住。
/// </summary>
public sealed class HostsBlockTests
{
    [Fact]
    public void 移除托管区块并保留用户原有条目()
    {
        var lines = new List<string>
        {
            "127.0.0.1 localhost",
            Cli.MarkBegin,
            "127.0.0.1 github.com",
            "127.0.0.1 steamcommunity.com",
            Cli.MarkEnd,
            "192.168.1.10 nas",
        };

        var result = Cli.StripManagedBlock(lines);

        Assert.Equal(["127.0.0.1 localhost", "192.168.1.10 nas"], result);
    }

    [Fact]
    public void 没有标记时内容一点不变()
    {
        var lines = new List<string> { "127.0.0.1 localhost", "192.168.1.10 nas" };

        var result = Cli.StripManagedBlock(lines);

        Assert.Equal(["127.0.0.1 localhost", "192.168.1.10 nas"], result);
    }

    [Fact]
    public void 多个托管区块全部移除()
    {
        // 手动删过一半、或旧版本留下过重复区块时会出现这种文件
        var lines = new List<string>
        {
            "a",
            Cli.MarkBegin, "x", Cli.MarkEnd,
            "b",
            Cli.MarkBegin, "y", Cli.MarkEnd,
            "c",
        };

        var result = Cli.StripManagedBlock(lines);

        Assert.Equal(["a", "b", "c"], result);
    }

    [Fact]
    public void 区块未闭合时把标记之后的内容一并去掉()
    {
        // 文件被截断（写入中途断电）时只剩下开始标记。
        // 刻意选择"多删"这个方向：宁可丢掉半截托管内容，
        // 也不要留着它让下次写入变成重复条目。
        var lines = new List<string> { "keep", Cli.MarkBegin, "127.0.0.1 github.com" };

        var result = Cli.StripManagedBlock(lines);

        Assert.Equal(["keep"], result);
    }

    [Fact]
    public void 标记带首尾空白也能识别()
    {
        var lines = new List<string>
        {
            "keep",
            "  " + Cli.MarkBegin + "  ",
            "127.0.0.1 github.com",
            "\t" + Cli.MarkEnd,
        };

        var result = Cli.StripManagedBlock(lines);

        Assert.Equal(["keep"], result);
    }

    [Fact]
    public void 只有标记没有内容时也清干净()
    {
        var lines = new List<string> { "keep", Cli.MarkBegin, Cli.MarkEnd };

        var result = Cli.StripManagedBlock(lines);

        Assert.Equal(["keep"], result);
    }

    [Fact]
    public void 标记是注释行且首尾不同()
    {
        // 标记必须是注释（不能影响 hosts 解析），且起止不同（否则无法界定区块）
        Assert.StartsWith("#", Cli.MarkBegin);
        Assert.StartsWith("#", Cli.MarkEnd);
        Assert.NotEqual(Cli.MarkBegin, Cli.MarkEnd);
    }
}
