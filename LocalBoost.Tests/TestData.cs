namespace LocalBoost.Tests;

/// <summary>
/// 构造规则表的公共入口。
///
/// <see cref="RuleBook.Load"/> 只接受文件路径，所以这里落一个临时文件再读，
/// 顺便让测试走的就是真实的加载路径（含字段校验与告警），而不是绕过它的捷径。
/// </summary>
internal static class TestData
{
    public static RuleBook WithHosts(params string[] hosts) =>
        FromJson($$"""
            { "rules": [ { "tag": "T", "hosts": [{{Quote(hosts)}}] } ] }
            """);

    public static RuleBook Empty() => FromJson("""{ "rules": [] }""");

    public static RuleBook FromJson(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"localboost-rules-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);

        try
        {
            return RuleBook.Load(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Quote(IEnumerable<string> values) =>
        string.Join(", ", values.Select(v => $"\"{v}\""));
}
