using System.Net;
using System.Text;

namespace LocalBoost.Tests;

/// <summary>
/// DNS 应答解析。
///
/// 这段是手写的二进制解析，出错的表现是**静默返回空列表**（看起来像"这个域名没有候选"），
/// 排查成本很高，所以把边界情形都钉住。
/// </summary>
public sealed class SystemDnsQueryTests
{
    [Fact]
    public void 取出单条A记录()
    {
        var message = BuildResponse("example.com", [(TypeA, "1.2.3.4")]);

        Assert.Equal(["1.2.3.4"], SystemDnsQuery.ParseAnswers(message).Select(ip => ip.ToString()));
    }

    [Fact]
    public void 取出多条A记录()
    {
        var message = BuildResponse("example.com", [(TypeA, "1.2.3.4"), (TypeA, "5.6.7.8")]);

        Assert.Equal(
            ["1.2.3.4", "5.6.7.8"],
            SystemDnsQuery.ParseAnswers(message).Select(ip => ip.ToString()));
    }

    [Fact]
    public void 跳过非A记录且不因此错位()
    {
        // CNAME 在前、A 在后是常见形态（解析器会把整条链一起返回）。
        // 如果长度字段没被正确跳过，后面那条 A 就会被读成垃圾。
        var message = BuildResponse("example.com", [(TypeCname, "cname.example.net"), (TypeA, "9.9.9.9")]);

        Assert.Equal(["9.9.9.9"], SystemDnsQuery.ParseAnswers(message).Select(ip => ip.ToString()));
    }

    [Fact]
    public void 名字用压缩指针也能正确跳过()
    {
        // 应答里的名字通常是 0xC00C 这样的压缩指针（指向问题段），只占 2 字节。
        // 答案段从「问题段名字 + QTYPE + QCLASS」之后开始。
        var message = BuildResponse("example.com", [(TypeA, "10.0.0.1")]);

        const int answerOffset = QuestionOffset + QuestionNameLength + 4;
        Assert.Equal(0xC0, message[answerOffset]);

        Assert.Equal(["10.0.0.1"], SystemDnsQuery.ParseAnswers(message).Select(ip => ip.ToString()));
    }

    [Fact]
    public void 报文被截断时不抛异常只返回已解析的部分()
    {
        var full = BuildResponse("example.com", [(TypeA, "1.2.3.4"), (TypeA, "5.6.7.8")]);

        // 砍掉最后一条记录的一半
        var cut = full[..^8];

        var parsed = SystemDnsQuery.ParseAnswers(cut);
        Assert.Equal(["1.2.3.4"], parsed.Select(ip => ip.ToString()));
    }

    [Fact]
    public void 空报文与畸形报文返回空列表()
    {
        Assert.Empty(SystemDnsQuery.ParseAnswers([]));
        Assert.Empty(SystemDnsQuery.ParseAnswers(new byte[8]));
        Assert.Empty(SystemDnsQuery.ParseAnswers([0xFF, 0xFF, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0]));
    }

    [Fact]
    public void 解析出的地址是IPv4()
    {
        var message = BuildResponse("example.com", [(TypeA, "203.0.113.7")]);

        var ip = Assert.Single(SystemDnsQuery.ParseAnswers(message));
        Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, ip.AddressFamily);
        Assert.Equal("203.0.113.7", ip.ToString());
    }

    // ------------------------------------------------------------ 构造测试报文

    private const int TypeA = 1;
    private const int TypeCname = 5;

    private const int QuestionOffset = 12;

    /// <summary>"example.com" 在报文里编码后的长度：11 个字符 + 2 个长度字节 + 结尾 0。</summary>
    private const int QuestionNameLength = 13;

    /// <summary>
    /// 造一个应答报文。名字一律用压缩指针指向问题段（真实解析器的常见做法），
    /// 顺带把"指针要当成 2 字节跳过"这条路径覆盖上。
    /// </summary>
    private static byte[] BuildResponse(string question, (int Type, string Value)[] answers)
    {
        var bytes = new List<byte>();

        void U16(int value)
        {
            bytes.Add((byte)(value >> 8));
            bytes.Add((byte)value);
        }

        void Name(string name)
        {
            foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                var text = Encoding.ASCII.GetBytes(label);
                bytes.Add((byte)text.Length);
                bytes.AddRange(text);
            }

            bytes.Add(0);
        }

        U16(0x1234);            // ID
        U16(0x8180);            // 标志位：标准应答 + RD/RA
        U16(1);                 // QDCOUNT
        U16(answers.Length);    // ANCOUNT
        U16(0);                 // NSCOUNT
        U16(0);                 // ARCOUNT

        Name(question);
        U16(1);                 // QTYPE = A
        U16(1);                 // QCLASS = IN

        foreach (var (type, value) in answers)
        {
            U16(0xC00C);        // 压缩指针 → 问题段的名字
            U16(type);
            U16(1);             // CLASS = IN
            bytes.AddRange([0, 0, 0, 60]);   // TTL

            var rdata = type == TypeA
                ? IPAddress.Parse(value).GetAddressBytes()
                : BuildRdataForName(value);

            U16(rdata.Length);
            bytes.AddRange(rdata);
        }

        return [.. bytes];
    }

    /// <summary>CNAME 的 RDATA 也是一个域名，这里用固定长度、不压缩的形式，避免测试自身出错。</summary>
    private static byte[] BuildRdataForName(string name)
    {
        var bytes = new List<byte>();

        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var text = Encoding.ASCII.GetBytes(label);
            bytes.Add((byte)text.Length);
            bytes.AddRange(text);
        }

        bytes.Add(0);
        return [.. bytes];
    }
}
