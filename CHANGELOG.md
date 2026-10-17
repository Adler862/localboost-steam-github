# 更新日志

本文件格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

## [1.0.0] - 2026-10-14

首次开源发布。只做 Steam 与 GitHub 的域名解析优选，两种加速模式可独立使用。

### 新增

- **两种加速模式**：
  - 模式一 `hosts + 本地反代`：把白名单域名指向 `127.0.0.1`，按 SNI 动态签发叶证书做 MITM。
  - 模式二 `本地代理 + PAC`：环回上的 HTTP 代理，`CONNECT` 走**盲隧道**（只搬运密文，
    TLS 由客户端端到端完成），因此**不需要安装根证书**，并且能覆盖 hosts 表达不了的通配域名。
- **命令行**：`run` / `cert install|remove|path` / `hosts install|remove|list` /
  `proxy install|remove|status` / `rules` / `probe <host>`。
- **IP 优选引擎**：多源 DoH 候选采集（阿里 / 360 / Google / dns.sb + 系统 DNS 累加）、
  TCP+TLS 握手测速（只测 TCP 会被伪造 SYN-ACK 欺骗）、证书有效性参与排序、
  候选不足时向同网段扩展、15 分钟缓存、失败 IP 冷却、启动后台预热。
- **规则表字段校验**：非法域名 / IP / 端口会被丢弃并给出告警；
  启用 `serverName`（SNI 改写）时必定产生安全告警。
- **图形界面**：WinForms 自绘 Win11 风格界面，跟随系统深浅色与强调色，高位深缩放（PerMonitorV2）适配。
- **单元测试项目**（xunit）。覆盖规则表匹配与校验、PAC 生成、hosts 托管区块剥离 ——
  这几处改错了只会静默失效，最值得钉住。
- **工程化**：`.editorconfig`、`global.json`、`Directory.Build.props`、`Directory.Packages.props`、
  CI（编译零警告 + 格式与风格校验 + 测试 + 验证单文件发布链路）。

### 安全

- 根证书私钥的落盘加固：**随机口令**（废弃早先的硬编码口令）、
  PKCS12 主体与口令均经 **DPAPI 按当前 Windows 账户加密**、密钥目录 **ACL 断开继承**
  只保留当前用户 / Administrators / SYSTEM。旧格式文件会自动迁移，且保持同一把密钥。
- 上游证书校验：修正 SNI 改写的判定（原用引用比较，会无缘由放宽校验）；
  放宽时**只容忍「名称不匹配」**，链、签名、有效期仍按严格标准校验，且每次放宽都写日志。
- 证书签发只对规则表内的域名生效，避免本机任意进程带任意 SNI 触发白签。
- 根证书安装判定由比对 Subject 改为**比对指纹**，修掉 CA 重建后全站证书失效且无法自愈的问题。
- 本地代理只监听环回、只接管规则表内的域名，不充当开放代理。
- 回退路径补上私有网段过滤（原先只过滤环回）。

### 修复

- **`store.steampowered.com` 等 Steam 域名持续 502**。根因是候选 IP 的来源不完整：
  DoH 那四家返回的 Akamai IP 对本机网络**全部不可用**，而唯一可用的 IP
  （`104.115.236.165`，实测 HTTP 200 / 951 KB / 首字节 1.19s）只有**本机解析器**知道 ——
  但 hosts 模式下系统 DNS 这条路被我们自己的 hosts 记录（指向 127.0.0.1）挡住了。
  新增 `SystemDnsQuery`：直接向本机 DNS 服务器查 A 记录，绕开 hosts，
  让"本机解析器"这个来源重新生效（兜底回退路径同理）。
  实测 `store.steampowered.com` 从**每轮 502** 变为 **200 / 200 / 200**。
- 转发失败时不再打印 YARP 的整段异常堆栈（我们自己那行简明日志已经含 ForwarderError 代码），
  避免把界面日志区刷满。
- **最小化后最大化会闪退**。Windows 事件日志给出的异常码是 `0xC00000FD`，
  即栈溢出：为适配高 DPI 而新增的 `ApplyDpiScale()` 会改窗口尺寸，而 WinForms 在
  隐藏窗口 / 最小化 / 最大化过程中**也会**触发 `DpiChanged`，于是形成
  「改尺寸 → 触发 Resize/DpiChanged → 再改尺寸」的递归，最大化那条路径会一直递归
  到栈耗尽。现在只在「可见且处于正常状态」时才动尺寸，并加了重入闸。
- **最小化改为正常最小化**（不再缩到托盘）。原先的「一最小化就缩到托盘」与 README
  描述的「关窗口才缩托盘」不符，而且缩到托盘后任务栏没有按钮，"最小化后最大化"
  无从操作。现在只有关闭窗口才缩到托盘。
- **浏览器报 `ERR_CERT_INVALID` 导致 github.com / store.steampowered.com 整站打不开
  —— 真正的根因是叶证书的 `Authority Key Identifier` 扩展编码不规范。**
  RFC 5280 的模块声明是 `DEFINITIONS IMPLICIT TAGS`，`[0]` 是 **IMPLICIT**，
  编码必须是 `30 16 80 14 <keyid>`（0x80 = context 0 + primitive）；
  而原来的实现按 EXPLICIT 拼成了 `30 18 A0 16 04 14 <keyid>`。
  **宽容的解析器全都照收**（Windows 链引擎 Build=True、openssl 显示正常、curl 能连上），
  只有浏览器自带的严格解析器失败：Chromium 在 netlog 里明确记着
  `Failed parsing authority key identifier`，随后判定整张证书无效
  （`net_error: -207`、`cert_status: 128`，Edge 与 Steam 客户端完全一致）。
  项目里这个现象被反复误判成「HSTS 拦截」「根证书没装好」「吊销检查失败」——
  实际原因一直是这一处编码。现改用 BCL 的
  `X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier` 生成，
  删掉手拼 DER 的代码，并加了 5 个单元测试把字节钉住
  （这类错误只有严格解析器能发现，测试是唯一的防线）。
  顺带把叶证书的 `Key Usage`（critical，Digital Signature + Key Encipherment）补上，
  根证书也改成标准 CA 形状（`keyCertSign + cRLSign`，不再带 EKU）——
  这两条是标准做法，但不是本次故障的原因。
  **已装过根证书的用户不需要重装**。
- 同一个 SNI 的「拒绝签发」提示不再逐条刷屏。实测有些域名会被解析到 `127.0.0.1`
  （例如 `doh.dns.sb` —— dns.sb 故意把自己的域名黑洞化以提示 DNS 被污染），
  本机程序每几秒就来敲一次 443，原来的逐条日志会把日志区刷满、看起来像程序出故障。
- README 修正「兜底回退」的描述：它在 hosts 模式下**必然失败**（系统 DNS 的结果就是本程序
  写进去的 127.0.0.1，会被当作自环拒绝），此时表现为 502，并不会退化成直连。
- `hosts list` 与不带参数的 `hosts` 不再**删除** hosts 条目（原先会清空）。
- `.gitattributes` 补上 `eol=lf`。只写 `text` 的话检出时的行尾由 `core.autocrlf` 决定，
  Windows 上默认会把工作区变成 CRLF，与 `.editorconfig` 的 `end_of_line = lf` 打架，
  `dotnet format --verify-no-changes` 会把整个文件报成 ENDOFLINE 错误。
- 通配域名补上分隔点边界，`evilgithub.io` 不再命中 `*.github.io`。
- 高 DPI（125% / 150%）下界面错位与文字重叠；布局常量改为按 `DeviceDpi` 换算。
- 圆角嵌套（"圆角外面套方框"）与标题栏下方越悬停越明显的白线。
- 系统关机 / 注销不再被"缩到托盘"挡住。
- 启动失败时正确释放 `WebApplication` 与 `HttpMessageInvoker`；托盘图标替换时释放旧 `Icon`。
- 停止加速时自动还原系统代理，避免把整个系统指向一个已无人监听的 PAC。

### 已知限制

- SNI 只能改写、无法删除（纯 BCL 不构造无 SNI 的 ClientHello）；代理模式下无法改写。
- 覆盖不到 Steam 的 SteamPipe 下载（UDP / TCP 27030-27100）。
- 只做 IPv4。
- HSTS 站点需要手动清理（仅模式一）。

[未发布]: https://github.com/Adler862/LocalBoost/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Adler862/LocalBoost/releases/tag/v1.0.0
