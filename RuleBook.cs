using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalBoost;

/// <summary>
/// 一条加速规则。字段设计参考了同类本地加速工具的通行做法：
/// 一条规则描述「要接管哪些域名」以及「出口该怎么走」。
/// </summary>
public sealed class AccelRule
{
    public string Tag { get; set; } = "";

    /// <summary>要拦截的域名，支持 "*.example.com" 形式的后缀通配。</summary>
    public string[] Hosts { get; set; } = [];

    /// <summary>
    /// 真实要去的域名。留空表示与请求的主机名相同。
    /// 想让某个域名实际落到另一个入口时填这里（例如某个可用镜像）。
    /// </summary>
    public string? Upstream { get; set; }

    /// <summary>
    /// 手工指定的候选 IP。留空则由 IP 优选引擎自行解析 + 测速。
    /// 一旦填写，引擎只在这批 IP 里优选，不再做 DNS。
    /// </summary>
    public string[]? StaticIps { get; set; }

    /// <summary>
    /// 追加到候选池的 IP：**和 DNS 采集结果一起参与优选**，不是替换。
    ///
    /// 与 <see cref="StaticIps"/> 的区别是语义，不是技术：
    ///   - <c>staticIps</c>：IP 已确定，不再优选的固定上游（如 Steam 的 Akamai 边缘，
    ///     必须配合 <see cref="ServerName"/> 才有效，换一个没意义）；
    ///   - <c>extraIps</c>：**额外加几个值得一试的候选**，交给优选去测速与判活。
    ///
    /// 典型用途：正常解析出来的出口全被墙/被拉黑时，某个已知可用的中转 IP
    /// 值得混进池子里一起比较。它时通时断，所以不能当固定上游（那样它一断就全断），
    /// 而放进候选池后优选会在它可用时选中它、不可用时自然跳过。
    /// </summary>
    public string[]? ExtraIps { get; set; }

    /// <summary>
    /// SNI 改写值。留空表示保留原始主机名作为 SNI。
    /// 存在少数场景需要把它改写成别的值（纯 .NET BCL 无法删除 SNI，只能改写）。
    /// </summary>
    public string? ServerName { get; set; }

    public int Port { get; set; } = 443;

    public bool Enabled { get; set; } = true;

    [JsonIgnore]
    public bool IsEnabled => Enabled && Hosts.Length > 0;
}

public sealed class RuleBook
{
    private readonly Dictionary<string, AccelRule> _exact = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Suffix, AccelRule Rule)> _suffixes = [];

    public IReadOnlyCollection<AccelRule> Rules { get; private set; } = [];

    /// <summary>加载期发现的问题（非法域名、被丢弃的字段、被启用的 SNI 改写等）。</summary>
    public IReadOnlyList<string> Warnings { get; private set; } = [];

    public static RuleBook Load(string path)
    {
        var json = File.ReadAllText(path);
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };
        var root = JsonSerializer.Deserialize<RuleFile>(json, options)
                   ?? throw new InvalidDataException("rules.json 解析结果为空");

        var warnings = new List<string>();
        var rules = Sanitize(root.Rules ?? [], warnings);
        return new RuleBook(rules, warnings);
    }

    /// <summary>用一批已经调好 Enabled 的规则重新建表。界面改勾选后走这里。</summary>
    public static RuleBook Create(IReadOnlyCollection<AccelRule> rules, IReadOnlyList<string>? warnings = null) =>
        new(rules, warnings ?? []);

    private RuleBook(IReadOnlyCollection<AccelRule> rules, IReadOnlyList<string> warnings)
    {
        Rules = rules;
        Warnings = warnings;

        foreach (var rule in rules.Where(r => r.IsEnabled))
        {
            foreach (var host in rule.Hosts)
            {
                if (host.StartsWith("*.", StringComparison.Ordinal))
                    _suffixes.Add((host[2..], rule));
                else
                    _exact[host] = rule;
            }
        }
    }

    /// <summary>
    /// 逐字段校验规则表。
    ///
    /// rules.json 是明文、位于安装目录，且 <see cref="AccelRule.ServerName"/> 会放宽上游证书校验，
    /// 所以这里必须把非法值挡在外面，并把所有会影响安全性的字段显式报出来，
    /// 不能让一份被改过的配置悄悄生效。
    /// </summary>
    private static List<AccelRule> Sanitize(List<AccelRule> rules, List<string> warnings)
    {
        var kept = new List<AccelRule>();

        foreach (var rule in rules)
        {
            var tag = string.IsNullOrWhiteSpace(rule.Tag) ? "(未命名规则)" : rule.Tag;

            var hosts = (rule.Hosts ?? [])
                .Select(h => h?.Trim().ToLowerInvariant() ?? "")
                .Where(h => h.Length > 0)
                .Where(h =>
                {
                    var bare = h.StartsWith("*.", StringComparison.Ordinal) ? h[2..] : h;
                    if (IsValidHostName(bare))
                        return true;

                    warnings.Add($"{tag}：忽略非法域名「{h}」");
                    return false;
                })
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (hosts.Length == 0)
            {
                warnings.Add($"{tag}：没有合法域名，整条规则已跳过");
                continue;
            }

            rule.Hosts = hosts;

            if (!string.IsNullOrWhiteSpace(rule.Upstream))
            {
                if (IsValidHostName(rule.Upstream))
                {
                    rule.Upstream = rule.Upstream.Trim().ToLowerInvariant();
                }
                else
                {
                    warnings.Add($"{tag}：upstream「{rule.Upstream}」不是合法域名，已忽略");
                    rule.Upstream = null;
                }
            }

            if (rule.StaticIps is { Length: > 0 })
            {
                var valid = rule.StaticIps
                    .Where(ip => System.Net.IPAddress.TryParse(ip, out _))
                    .ToArray();

                if (valid.Length != rule.StaticIps.Length)
                    warnings.Add($"{tag}：staticIps 里有 {rule.StaticIps.Length - valid.Length} 个非法 IP，已丢弃");

                rule.StaticIps = valid.Length > 0 ? valid : null;
            }

            if (rule.ExtraIps is { Length: > 0 })
            {
                var valid = rule.ExtraIps
                    .Where(ip => System.Net.IPAddress.TryParse(ip, out _))
                    .ToArray();

                if (valid.Length != rule.ExtraIps.Length)
                    warnings.Add($"{tag}：extraIps 里有 {rule.ExtraIps.Length - valid.Length} 个非法 IP，已丢弃");

                rule.ExtraIps = valid.Length > 0 ? valid : null;
            }

            if (!string.IsNullOrWhiteSpace(rule.ServerName))
            {
                if (IsValidHostName(rule.ServerName))
                {
                    rule.ServerName = rule.ServerName.Trim().ToLowerInvariant();

                    // 这是唯一一个会削弱上游证书校验的字段，必须显式告知
                    warnings.Add($"{tag}：启用了 SNI 改写（serverName={rule.ServerName}）。"
                              + "该规则的上游证书不再校验名称，只校验链与签名。");
                }
                else
                {
                    warnings.Add($"{tag}：serverName「{rule.ServerName}」不是合法域名，已忽略");
                    rule.ServerName = null;
                }
            }

            if (rule.Port is <= 0 or > 65535)
            {
                warnings.Add($"{tag}：端口 {rule.Port} 非法，已回退到 443");
                rule.Port = 443;
            }

            kept.Add(rule);
        }

        return kept;
    }

    /// <summary>RFC 1123 主机名粗校验：只允许字母数字与连字符，且首尾不能是连字符。</summary>
    private static bool IsValidHostName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var host = value.Trim().TrimEnd('.');
        if (host.Length is 0 or > 253)
            return false;

        foreach (var label in host.Split('.'))
        {
            if (label.Length is 0 or > 63)
                return false;

            if (label[0] == '-' || label[^1] == '-')
                return false;

            foreach (var c in label)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '-')
                    return false;
            }
        }

        return true;
    }

    public bool TryGet(string host, out AccelRule rule)
    {
        host = host.TrimEnd('.');
        if (_exact.TryGetValue(host, out var hit))
        {
            rule = hit;
            return true;
        }

        foreach (var (suffix, candidate) in _suffixes)
        {
            // 必须带上分隔点再比：只比后缀的话 "evilgithub.io" 也会命中 "*.github.io"，
            // 于是不在白名单里的域名会被当成规则域名接管、走本地反代。
            if (host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)
                && host.Length > suffix.Length + 1)
            {
                rule = candidate;
                return true;
            }
        }

        rule = null!;
        return false;
    }

    /// <summary>全部启用规划的主机名，用于生成 hosts 条目。</summary>
    public IEnumerable<string> EnabledHosts() =>
        Rules.Where(r => r.IsEnabled).SelectMany(r => r.Hosts).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>给定主机名，返回真正要连的上游域名。</summary>
    public static string UpstreamHostOf(AccelRule rule, string requestHost) =>
        string.IsNullOrWhiteSpace(rule.Upstream) ? requestHost : rule.Upstream!;

    private sealed class RuleFile
    {
        public List<AccelRule>? Rules { get; set; }
    }
}
