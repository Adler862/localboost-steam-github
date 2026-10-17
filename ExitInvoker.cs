using System.Net;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;

namespace LocalBoost;

/// <summary>
/// 出口 HttpMessageInvoker。用一个共享实例就够了，
/// 因为 ConnectCallback 本身能读到目标主机名，再按规则去查优选 IP。
///
/// 真正的连接逻辑（候选筛选、failover、SNI 改写）在 <see cref="UpstreamConnector"/>，
/// 与 CONNECT 盲隧道共用同一份实现。
/// 注意：返回已经完成 TLS 的 Stream 时，SocketsHttpHandler 不会再做一次加密。
/// </summary>
public sealed class ExitInvoker : IDisposable
{
    private readonly UpstreamConnector _connector;
    private readonly HttpMessageInvoker _invoker;

    public ExitInvoker(UpstreamConnector connector)
    {
        _connector = connector;

        _invoker = new HttpMessageInvoker(new SocketsHttpHandler
        {
            UseProxy = false,          // 必须直连，否则 IP 优选没有意义
            UseCookies = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            EnableMultipleHttp2Connections = false,
            // 这个预算要覆盖「首次 IP 探测 + 失败重试」，给短了会直接报连接超时。
            // 平时的请求走缓存，不会真的用满。
            ConnectTimeout = TimeSpan.FromSeconds(20),
            ConnectCallback = ConnectAsync,
        });
    }

    /// <summary>最近一次出口目标，仅用于日志展示。并发下是尽力而为的近似值。</summary>
    public string? LastExit => _connector.LastExit;

    /// <summary>出口层的告警（证书校验被放宽等）。</summary>
    public event Action<string>? Log
    {
        add => _connector.Log += value;
        remove => _connector.Log -= value;
    }

    public HttpMessageInvoker Instance => _invoker;

    private ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct) =>
        new(_connector.ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, tls: true, ct));

    public void Dispose() => _invoker.Dispose();
}

/// <summary>转发时保留客户端看到的原始 Host，让上游以为是直接访问它。</summary>
public sealed class PreserveHostTransformer : HttpTransformer
{
    public static readonly PreserveHostTransformer Instance = new();

    public override async ValueTask TransformRequestAsync(
        HttpContext httpContext,
        HttpRequestMessage proxyRequest,
        string destinationPrefix,
        CancellationToken cancellationToken)
    {
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

        // 只带主机名，不要代理监听端口。
        // 上游是标准 443，收到 "github.com:8443" 这种 Host 会做规范化重定向，页面就是打不开。
        proxyRequest.Headers.Host = httpContext.Request.Host.Host;
    }
}
