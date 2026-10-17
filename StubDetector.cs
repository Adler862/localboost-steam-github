using System.IO.Pipelines;
using Microsoft.AspNetCore.Http.Features;

namespace LocalBoost;

/// <summary>
/// 检测"空壳出口"，并把肇事 IP 标进冷却队列。
///
/// **为什么单靠建连 failover 不够**：实测 github.com 的某些边缘 IP 会
/// 建连成功、TLS 成功、返回 `200 OK`，然后正文只有 **4 个字节**。
/// 这类出口在 <see cref="UpstreamConnector"/> 眼里是完全健康的 ——
/// TCP 通了、TLS 通了、状态行也拿到了，于是 failover 永远不会触发，
/// 用户看到的是"能连上、页面一片白"。这是本项目最隐蔽的一类故障。
///
/// **为什么不能只看响应头**：实测 github.com 真首页用的是
/// `Transfer-Encoding: chunked` 且**没有 `Content-Length`**
/// （直连 20.205.243.166 拿到 572,394 字节）。所以有相当一部分情况
/// 只能靠**数实际转发出去的字节数**来判断。
///
/// 判定出来之后**不改写当前响应**（那时字节已经发给浏览器了），
/// 而是把这个 IP 报为失败 —— 这样**下一次请求会自动换出口**。
/// 用户表现：第一次白屏，刷新即可。
/// </summary>
internal static class StubDetector
{
    /// <summary>
    /// 正文小于这个字节数、状态码却是 2xx/3xx，就按空壳处理。
    /// 与 <see cref="ProbeResult.EmptyBodyThreshold"/> 保持一致：
    /// 探测阶段和转发阶段必须用同一个判据，否则会出现
    /// "探测说它好、转发又说它坏"的自相矛盾。
    /// </summary>
    internal const int Threshold = ProbeResult.EmptyBodyThreshold;

    /// <summary>数够这么多字节就认定"有真实内容"，停止计数，避免影响大响应的吞吐。</summary>
    internal const int CountCeiling = 64 * 1024;

    /// <summary>
    /// 按响应头决定要不要数字节。
    ///
    /// 只在**没有声明长度**（chunked）时才包装写入路径：声明了长度的直接看数字，
    /// 不必干扰数据流。这是为了不牺牲正常大响应的吞吐 —— 包装会让 YARP
    /// 走不到 Kestrel 的 sendfile 快路径，对 codeload 那种几十兆的包是实打实的损失。
    /// </summary>
    public static StubTracker Attach(HttpContext context)
    {
        var status = context.Response.StatusCode;

        // 已经声明长度的：不碰数据流，转发结束后直接看数字
        if (context.Response.ContentLength is { } declared)
            return new StubTracker(status) { DeclaredLength = declared };

        // 没有声明长度（chunked / 连接关闭界定）：数实际字节
        var feature = context.Features.Get<IHttpResponseBodyFeature>();
        if (feature is null)
            return new StubTracker(status);

        var tracker = new StubTracker(status);
        context.Features.Set<IHttpResponseBodyFeature>(new CountingBodyFeature(feature, tracker));
        return tracker;
    }

    /// <summary>一次转发过程中累积的字节数，用来在转发结束后判定是否空壳。</summary>
    internal sealed class StubTracker(int status)
    {
        private long _bytes;
        private int _finalStatus;

        /// <summary>
        /// 转发**结束后**的状态码。
        ///
        /// **必须用最终状态码判空壳，不能用转发开始前的值**：那时响应还没被上游填充，
        /// `context.Response.StatusCode` 是默认的 200。拿它判定会把**所有**响应
        /// 都当成 2xx —— 实测 `api.steampowered.com` 的根路径本来就合法地回
        /// `404` + 146 字节，却被判成「空壳（状态 200）」，于是可用出口被标黑、
        /// 退到未加速的直连。判据里的 `StatusCode is < 200 or >= 300` 那一段
        /// 因此从未生效过。
        ///
        /// 转发成功时用 <see cref="Seal"/> 记下真实状态；没走到那一步就退回初始值。
        /// </summary>
        public int StatusCode => _finalStatus != 0 ? _finalStatus : status;

        /// <summary>转发结束后由调用方记下真实状态码。</summary>
        public void Seal(int finalStatus) => _finalStatus = finalStatus;

        /// <summary>服务器自己声明的长度（有值时不需要计数）。</summary>
        public long? DeclaredLength { get; init; }

        /// <summary>被包装的原始特性，转发结束后要还原回去。</summary>
        public IHttpResponseBodyFeature? Original { get; set; }

        public long Bytes => Interlocked.Read(ref _bytes);

        public void Add(long count)
        {
            if (count <= 0)
                return;

            // 超过上限就不再累加：反正已经远超阈值，再数只是白费
            if (Interlocked.Read(ref _bytes) >= CountCeiling)
                return;

            Interlocked.Add(ref _bytes, count);
        }

        /// <summary>
        /// 转发结束后判定：这个出口是不是空壳？
        ///
        /// 只在**状态是 2xx**、且能确定体积的情况下才敢下结论：
        ///   - **3xx 不算** —— 重定向正文为空是完全正常的
        ///     （实测 raw.githubusercontent.com 的根路径就回 301 且正文 0 字节）；
        ///   - 4xx/5xx 不算 —— 它们有自己的分档，混进来会让日志里每条 403 都被报成空壳；
        ///   - 体积确定不了时返回 false（"不敢说它坏"），宁可漏判也不误杀可用出口。
        /// </summary>
        public bool LooksLikeStub()
        {
            if (StatusCode is < 200 or >= 300)
                return false;

            if (DeclaredLength is { } declared)
                return declared < Threshold;

            // 没收到任何字节：连接在正文之前就没了，属于空壳
            return Bytes < Threshold;
        }

        /// <summary>把响应体特性还原，避免影响后续请求。</summary>
        public void Detach(HttpContext context)
        {
            if (Original is not null)
                context.Features.Set(Original);
        }
    }

    /// <summary>
    /// 数着流过去的字节数的响应体包装。
    ///
    /// 刻意只做计数，不缓冲、不改写 —— 缓冲整个正文会让大文件下载先卡在内存里，
    /// 那是比空壳严重得多的问题。
    ///
    /// **必须包 <see cref="Stream"/> 并据此重建 feature**：框架里
    /// <c>IHttpResponseBodyFeature.Writer</c> 是预先构造好的，
    /// 只把 <c>Writer</c> 换成一个包装类并不能保证写入路径经过它 ——
    /// 实测 YARP 走的是 <c>Writer</c>，于是计数永远是 0，
    /// 结果把**健康出口也判成空壳并标记掉**（本项目踩过这个坑）。
    /// 用 <see cref="StreamResponseBodyFeature"/> 从我们自己的 Stream 重建，
    /// 才能让 <c>Stream</c> 与 <c>Writer</c> 两条路径都落到计数上。
    /// </summary>
    private sealed class CountingBodyFeature : IHttpResponseBodyFeature
    {
        private readonly IHttpResponseBodyFeature _inner;
        private readonly StreamResponseBodyFeature _rebuilt;
        private readonly StubTracker _tracker;

        public CountingBodyFeature(IHttpResponseBodyFeature inner, StubTracker tracker)
        {
            _inner = inner;
            _tracker = tracker;
            _rebuilt = new StreamResponseBodyFeature(new CountingStream(inner.Stream, tracker), inner);
        }

        public Stream Stream => _rebuilt.Stream;

        public PipeWriter Writer => _rebuilt.Writer;

        public Task StartAsync(CancellationToken cancellationToken = default) =>
            _inner.StartAsync(cancellationToken);

        public Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken = default)
        {
            // 走 sendfile 说明是个实体文件，不可能是空壳；顺手把字节数记上
            _tracker.Add(count ?? 0);
            return _inner.SendFileAsync(path, offset, count, cancellationToken);
        }

        public Task CompleteAsync() => _inner.CompleteAsync();

        public void DisableBuffering() => _inner.DisableBuffering();
    }

    /// <summary>只统计读过多少字节的 Stream 包装。不缓冲、不改写内容。</summary>
    private sealed class CountingStream(Stream inner, StubTracker tracker) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            inner.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = inner.Read(buffer, offset, count);
            tracker.Add(read);
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var read = inner.Read(buffer);
            tracker.Add(read);
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken);
            tracker.Add(read);
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);

        public override void SetLength(long value) => inner.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count)
        {
            tracker.Add(count);
            inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            tracker.Add(buffer.Length);
            inner.Write(buffer);
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            tracker.Add(buffer.Length);
            await inner.WriteAsync(buffer, cancellationToken);
        }

        public override Task WriteAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            tracker.Add(count);
            return inner.WriteAsync(buffer, offset, count, cancellationToken);
        }
    }
}
