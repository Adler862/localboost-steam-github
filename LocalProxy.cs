using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LocalBoost;

/// <summary>
/// 本地 HTTP 代理（只监听 127.0.0.1）。
///
/// 与 hosts + MITM 反代是**互补**的两条路：
///
///   - CONNECT 走「盲隧道」：接受 CONNECT 后按优选 IP 建一条到上游的裸 TCP，
///     然后把两个方向的字节对传。客户端自己做 TLS，我们只搬运密文。
///     → 代理模式**完全不需要安装根证书**，也就没有 MITM 那一整套风险面；
///     → hosts 写不进去的通配域名（*.github.io、*.steamstatic.com）代理模式能覆盖。
///     代价：端到端加密拿不到明文，所以这里**做不了 SNI 改写**。
///
///   - 明文 HTTP 走绝对 URI 转发：把 "GET http://host/x" 的请求行改写成 "GET /x" 再转发。
///
/// 安全边界：只监听环回、且只接管规则表内的域名 —— 不能变成局域网可用的开放代理。
/// </summary>
public sealed class LocalProxy : IDisposable
{
    private const int MaxHeaderBytes = 32 * 1024;

    private readonly RuleBook _rules;
    private readonly UpstreamConnector _connector;
    private readonly CancellationTokenSource _cts = new();
    private readonly TcpListener _listener;
    private Task? _acceptLoop;

    public LocalProxy(RuleBook rules, UpstreamConnector connector, int preferredPort)
    {
        _rules = rules;
        _connector = connector;

        _listener = new TcpListener(IPAddress.Loopback, preferredPort);
        try
        {
            _listener.Start();
        }
        catch (SocketException)
        {
            // 偏好端口被占了就退到系统分配的临时端口。
            // 系统代理是自动配置的，用户不需要知道端口号，所以这点是安全的。
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
        }

        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    /// <summary>实际监听的端口。偏好端口被占用时会和传入的值不同。</summary>
    public int Port { get; }

    public event Action<string>? Log;

    public void Start() => _acceptLoop = Task.Run(AcceptLoopAsync);

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { continue; }

            // 一条慢连接不能拖住整个接受循环，所以每个连接单独起任务、不 await
            _ = HandleClientAsync(client);
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using (client)
        {
            client.NoDelay = true;
            var ct = _cts.Token;

            try
            {
                using var stream = client.GetStream();

                var head = await ReadHeadAsync(stream, ct);
                if (head is null)
                    return;

                if (!TryParseRequestLine(head, out var method, out var target, out var version))
                {
                    await WriteStatusAsync(stream, "400 Bad Request", ct);
                    return;
                }

                if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                    await TunnelAsync(stream, target, ct);
                else
                    await ForwardPlainAsync(stream, head, method, target, version, ct);
            }
            catch (OperationCanceledException)
            {
                // 服务停止，正常收尾
            }
            catch (Exception ex)
            {
                Log?.Invoke($"[代理] 连接处理失败：{ex.Message}");
            }
        }
    }

    // ------------------------------------------------------------ CONNECT 盲隧道

    private async Task TunnelAsync(Stream client, string target, CancellationToken ct)
    {
        if (!TrySplitHostPort(target, 443, out var host, out var port))
        {
            await WriteStatusAsync(client, "400 Bad Request", ct);
            return;
        }

        if (!_rules.TryGet(host, out var rule))
        {
            // 只接管白名单域名：本机代理不能变成任意目标的跳板
            Log?.Invoke($"[代理] 拒绝 CONNECT {host}:{port} —— 不在规则表内");
            await WriteStatusAsync(client, "403 Forbidden", ct);
            return;
        }

        Stream upstream;
        try
        {
            // tls: false —— 这就是"盲"的含义：只搬密文，不终止 TLS，
            // 因此不需要根证书，客户端仍按真实证书链严格校验
            upstream = await _connector.ConnectAsync(host, port, tls: false, ct);
        }
        catch (Exception ex)
        {
            Log?.Invoke($"[代理] {host}:{port} 建连失败：{ex.Message}");
            await WriteStatusAsync(client, "502 Bad Gateway", ct);
            return;
        }

        await using (upstream)
        {
            await client.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct);
            await client.FlushAsync(ct);

            await PumpAsync(client, upstream, ct);
            Log?.Invoke($"[代理] {rule.Tag} {host}:{port} → {_connector.LastExit ?? "未知出口"}");
        }
    }

    // ------------------------------------------------------------ 明文 HTTP 转发

    private async Task ForwardPlainAsync(
        Stream client, byte[] head, string method, string target, string version, CancellationToken ct)
    {
        // 代理请求的请求行是绝对 URI 形式（"GET http://github.com/x HTTP/1.1"）。
        // https 不会走这里 —— 浏览器对 https 一律先发 CONNECT。
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp)
        {
            await WriteStatusAsync(client, "501 Not Implemented", ct);
            return;
        }

        var host = uri.Host;
        var port = uri.IsDefaultPort ? 80 : uri.Port;

        if (!_rules.TryGet(host, out var rule))
        {
            Log?.Invoke($"[代理] 拒绝 {method} {host} —— 不在规则表内");
            await WriteStatusAsync(client, "403 Forbidden", ct);
            return;
        }

        var headerEnd = IndexOfHeaderEnd(head, head.Length);
        if (headerEnd < 0)
        {
            await WriteStatusAsync(client, "400 Bad Request", ct);
            return;
        }

        var rewritten = RewriteRequestLine(head, headerEnd, $"{method} {uri.PathAndQuery} {version}");

        Stream upstream;
        try
        {
            upstream = await _connector.ConnectAsync(host, port, tls: false, ct);
        }
        catch (Exception ex)
        {
            Log?.Invoke($"[代理] {host}:{port} 建连失败：{ex.Message}");
            await WriteStatusAsync(client, "502 Bad Gateway", ct);
            return;
        }

        await using (upstream)
        {
            await upstream.WriteAsync(rewritten, ct);
            await upstream.FlushAsync(ct);

            await PumpAsync(client, upstream, ct);
            Log?.Invoke($"[代理] {rule.Tag} {method} {host}{uri.PathAndQuery} → "
                      + $"{_connector.LastExit ?? "未知出口"}");
        }
    }

    /// <summary>
    /// 把请求行从绝对 URI 改写成 origin-form，并去掉只对代理有意义的头。
    /// 头部之后的字节（可能已经读到一部分正文）原样保留。
    /// </summary>
    private static byte[] RewriteRequestLine(byte[] head, int headerEnd, string newRequestLine)
    {
        var headerLength = headerEnd + 4;   // 含结尾的 CRLFCRLF
        var headerText = Encoding.ASCII.GetString(head, 0, headerLength);

        var firstBreak = headerText.IndexOf('\n');
        if (firstBreak < 0)
            return head;

        var rest = headerText[(firstBreak + 1)..];

        // Proxy-Connection 是给代理看的跳逐跳头，转给上游会让上游行为异常
        rest = string.Join("\r\n", rest
            .Split("\r\n", StringSplitOptions.None)
            .Where(line => !line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase)));

        var rebuilt = Encoding.ASCII.GetBytes($"{newRequestLine}\r\n{rest}");

        var bodyLength = head.Length - headerLength;
        var result = new byte[rebuilt.Length + bodyLength];
        rebuilt.CopyTo(result, 0);
        Array.Copy(head, headerLength, result, rebuilt.Length, bodyLength);
        return result;
    }

    // ------------------------------------------------------------ 字节搬运

    /// <summary>
    /// 双向对传，两个方向都自然结束才算这条连接结束。
    /// 用 WhenAll 而不是 WhenAny：下载场景下上游先发完 FIN，客户端还在读，
    /// WhenAny 会在数据还没读完时就拆掉连接。
    /// </summary>
    private static async Task PumpAsync(Stream a, Stream b, CancellationToken ct)
    {
        var forward = CopyAsync(a, b, ct);
        var backward = CopyAsync(b, a, ct);
        await Task.WhenAll(forward, backward);
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            while (true)
            {
                var read = await from.ReadAsync(buffer, ct);
                if (read == 0)
                    break;

                // NetworkStream 不缓冲，写完即走，不需要每块 Flush
                await to.WriteAsync(buffer.AsMemory(0, read), ct);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // 对端关闭、被取消、socket 被回收都算正常结束
        }
    }

    // ------------------------------------------------------------ 报文解析

    /// <summary>读到头部结束（CRLFCRLF）为止。<paramref name="head"/> 里可能带上正文的前若干字节，原样保留。</summary>
    private static async Task<byte[]?> ReadHeadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[8192];
        using var collected = new MemoryStream();

        while (collected.Length < MaxHeaderBytes)
        {
            int read;
            try
            {
                read = await stream.ReadAsync(buffer, ct);
            }
            catch (IOException)
            {
                return null;
            }

            if (read == 0)
                return null;

            collected.Write(buffer, 0, read);

            if (IndexOfHeaderEnd(collected.GetBuffer(), (int)collected.Length) >= 0)
                return collected.ToArray();
        }

        return null;
    }

    private static int IndexOfHeaderEnd(byte[] data, int length)
    {
        for (var i = 3; i < length; i++)
        {
            if (data[i] == (byte)'\n' && data[i - 1] == (byte)'\r'
                && data[i - 2] == (byte)'\n' && data[i - 3] == (byte)'\r')
            {
                return i - 3;
            }
        }

        return -1;
    }

    private static bool TryParseRequestLine(byte[] head, out string method, out string target, out string version)
    {
        method = target = "";
        version = "HTTP/1.1";

        var lineEnd = Array.IndexOf(head, (byte)'\n');
        if (lineEnd < 0)
            return false;

        var parts = Encoding.ASCII.GetString(head, 0, lineEnd)
            .Trim()
            .Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length < 2)
            return false;

        method = parts[0];
        target = parts[1];
        if (parts.Length > 2)
            version = parts[2];

        return true;
    }

    /// <summary>拆 "host:port"；支持 [::1]:443 这种 IPv6 字面量写法。</summary>
    private static bool TrySplitHostPort(string target, int defaultPort, out string host, out int port)
    {
        host = "";
        port = defaultPort;

        if (target.StartsWith('['))
        {
            var close = target.IndexOf(']');
            if (close < 0)
                return false;

            host = target[1..close];
            var rest = target[(close + 1)..];
            return rest.Length == 0 || (rest[0] == ':' && int.TryParse(rest[1..], out port));
        }

        var colon = target.LastIndexOf(':');
        if (colon < 0)
        {
            host = target;
            return host.Length > 0;
        }

        host = target[..colon];
        return host.Length > 0 && int.TryParse(target[(colon + 1)..], out port);
    }

    private static async Task WriteStatusAsync(Stream stream, string status, CancellationToken ct)
    {
        var body = Encoding.UTF8.GetBytes($"LocalBoost: {status}\n");
        var head = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status}\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n"
            + $"Content-Length: {body.Length}\r\n"
            + "Connection: close\r\n\r\n");

        await stream.WriteAsync(head, ct);
        await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();

        try
        {
            _acceptLoop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // 收尾阶段的异常不影响最终状态
        }

        _cts.Dispose();
    }
}
