using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace LocalBoost;

/// <summary>
/// 直接向本机配置的 DNS 服务器查 A 记录。
///
/// **为什么不能直接用 <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>**：
/// 它遵循 hosts 文件。而本程序在 hosts 模式下**恰好**把规则域名写进了 hosts 指向
/// 127.0.0.1，于是"系统 DNS"这个候选来源拿到的一律是环回地址（过滤后 0 条），
/// 整个来源等于失效；兜底回退路径也被它挡住 —— 这正是 README 里那条
/// 「hosts 模式下回退必然失败」的成因。
///
/// 而这个来源不能丢。实测 store.steampowered.com：
///   本机解析器 → 104.115.236.165，HTTP 200、951 KB、首字节 1.19s  ✅
///   四家 DoH   → 23.44.210.x / 23.77.15.x，全部连接超时             ❌
/// 原因是 Akamai 这类 CDN 的答案取决于**解析器所处的网络位置** ——
/// 本机解析器看到的是"从这条线路出去该走哪个节点"，这一点任何 DoH 都替代不了。
/// </summary>
internal static class SystemDnsQuery
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private const int TypeA = 1;

    /// <summary>解析 A 记录。按顺序尝试各个 DNS 服务器，任一成功即返回。</summary>
    public static async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct)
    {
        foreach (var server in Servers())
        {
            try
            {
                var addresses = await QueryAsync(server, host, ct);
                if (addresses.Count > 0)
                    return addresses;
            }
            catch (Exception ex) when (ex is IOException or SocketException
                                          or OperationCanceledException or InvalidOperationException)
            {
                // 这个服务器不通（或被防火墙丢包）就换下一个
            }
        }

        return [];
    }

    /// <summary>本机配置的 DNS 服务器。只取 IPv4 —— 优选引擎目前只做 IPv4。</summary>
    private static List<IPAddress> Servers()
    {
        var result = new List<IPAddress>();

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up)
                    continue;

                foreach (var dns in adapter.GetIPProperties().DnsAddresses)
                {
                    if (dns.AddressFamily == AddressFamily.InterNetwork && !result.Contains(dns))
                        result.Add(dns);
                }
            }
        }
        catch (NetworkInformationException)
        {
            // 拿不到网卡信息就只能放弃这个来源，调用方会走别的来源
        }

        return result;
    }

    private static async Task<List<IPAddress>> QueryAsync(IPAddress server, string host, CancellationToken ct)
    {
        var query = BuildQuery(host, out var id);

        using var udp = new UdpClient(server.AddressFamily);
        udp.Connect(server, 53);

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(Timeout);

        await udp.SendAsync(query, budget.Token);

        while (true)
        {
            var response = await udp.ReceiveAsync(budget.Token);

            // 同一个 socket 上理论上只会有我们自己的应答，但 ID 对不上就重收，
            // 免得把别的东西解析成 IP。
            if (response.Buffer.Length >= 12 && ReadUInt16(response.Buffer, 0) == id)
                return ParseAnswers(response.Buffer);
        }
    }

    private static byte[] BuildQuery(string host, out ushort id)
    {
        id = (ushort)Random.Shared.Next(1, ushort.MaxValue);

        var buffer = new List<byte>(32);

        void U16(ushort value)
        {
            buffer.Add((byte)(value >> 8));
            buffer.Add((byte)value);
        }

        U16(id);
        U16(0x0100);   // 标志位：RD，要求递归解析
        U16(1);        // QDCOUNT
        U16(0);        // ANCOUNT
        U16(0);        // NSCOUNT
        U16(0);        // ARCOUNT

        foreach (var label in host.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
                throw new InvalidOperationException($"域名段长度非法：{label}");

            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }

        buffer.Add(0);   // 名字结束
        U16(TypeA);
        U16(1);          // IN

        return [.. buffer];
    }

    /// <summary>
    /// 从应答里取出 A 记录。
    ///
    /// CNAME 之类的记录直接跳过：解析器通常会把整条链和它在同一次应答里一起返回，
    /// 我们只要最后的 A 记录。
    /// </summary>
    internal static List<IPAddress> ParseAnswers(byte[] message)
    {
        var result = new List<IPAddress>();

        if (message.Length < 12)
            return result;

        var answers = ReadUInt16(message, 6);
        var offset = 12;

        // 跳过问题段（名字 + QTYPE + QCLASS）
        if (!SkipName(message, ref offset) || offset + 4 > message.Length)
            return result;

        offset += 4;

        for (var i = 0; i < answers; i++)
        {
            if (!SkipName(message, ref offset) || offset + 10 > message.Length)
                break;

            var type = ReadUInt16(message, offset);
            var length = ReadUInt16(message, offset + 8);
            offset += 10;

            if (offset + length > message.Length)
                break;

            if (type == TypeA && length == 4)
                result.Add(new IPAddress(message.AsSpan(offset, 4)));

            offset += length;
        }

        return result;
    }

    /// <summary>
    /// 按 DNS 名字格式推进读取位置。压缩指针（高两位为 11）只占两个字节 ——
    /// 这里只需要正确跳过，不需要真的解出名字。
    /// </summary>
    private static bool SkipName(byte[] message, ref int offset)
    {
        while (offset < message.Length)
        {
            var length = message[offset];

            if (length == 0)
            {
                offset++;
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                offset += 2;
                return offset <= message.Length;
            }

            offset += 1 + length;
        }

        return false;
    }

    private static ushort ReadUInt16(byte[] buffer, int offset) =>
        (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
}
