# 参与开发

感谢愿意帮忙。这个项目不大（十几个源文件、几千行），但有几处**安全红线**、
以及一批**踩过坑的实现约定**，动代码前请先看第 1、2 节。

---

## 1. 红线（触及即拒）

这是一个会在用户机器上安装根证书的工具，所以下面几条不接受商量：

1. **不得放宽证书校验。** 上游 TLS 的放宽只允许出现在一处：
   `UpstreamConnector.ConnectViaAsync` 里、仅当规则显式配置了 `serverName` 时，
   且**只容忍「证书名称不匹配」**。任何形式的 `(_, _, _, _) => true`、跳过链校验、
   跳过有效期校验，一律拒绝。
2. **不得新增第三方加密 / 网络库。** 证书签发、TLS、代理全部用 BCL 实现是刻意选择：
   少一个依赖就少一条供应链攻击路径。新增依赖需要在这个 PR 里论证清楚为什么 BCL 做不到。
3. **不得把代理暴露到环回之外。** `LocalProxy` 只监听 `127.0.0.1`，
   且只接管规则表内的域名。任何让它变成开放代理的改动都会被拒。
4. **不得在用户没有主动操作时改动系统设置。** hosts、证书库、注册表的写入
   必须由用户显式触发（点按钮或执行命令），并且必须可完整回滚。
5. **不得加入任何遥测、回传、"检查更新"之类的对外请求。**
   本工具的网络行为只应该是：DoH 解析、优选测速、以及用户请求的转发。
6. **不得把根证书私钥的落盘方式改弱。** 随机口令 + DPAPI 加密 + 目录 ACL 收紧这三条都要在。

拿不准就先开一个 Issue 讨论，比写完再被拒好。

---

## 2. 踩过的坑（改代码前必读）

这些都是真实踩出来的，注释里也大多写着，重复踩会很难查：

1. **`X509KeyStorageFlags` 分两类，别搞混。**
   叶证书必须 `PersistKeySet` —— Schannel 作为 TLS 服务端需要密钥容器句柄，
   用 `EphemeralKeySet` 会握手失败，而且**服务端日志里一点异常都没有**，
   只在客户端看到 `no peer certificate available`。根证书只做签名，用 `EphemeralKeySet` 不留痕迹。
2. **SNI 改写判定必须比字符串**，不能用 `ReferenceEquals` —— 那样 `serverName` 与主机名同值时
   也会被判成"已改写"，从而无缘无故放宽校验。
3. **圆角只能有一层来源。** 窗口 + 卡片 + 按钮各自圆角 = 视觉上"圆角外面套一圈方框"。
   现在是 `Pad = 0`、卡片与按钮全直角，圆角只由窗口（DWM）提供。
4. **不要给卡片和标题栏描边。** 那条 1px 半透明线会被反复合成到未清空的缓冲区上，
   鼠标每进出一次叠一层，最后变成一条越来越明显的白线。
5. **布局常量全部是"设计稿像素"，必须经 `S()` 换算。** 字体按点值渲染会自动跟着 DPI 放大，
   坐标不跟着放大就会文字重叠。新增布局代码时别再写裸像素。
6. **`out _` 在 lambda 里不是弃元。** `(_, host) => rules.TryGet(host, out _)` 会把 `_`
   解析成那个 lambda 参数，编译错误信息很有误导性。把参数改名即可。
7. **绝不用 `TransparencyKey`。** 它会把窗口变成 layered window，DWM 材质与圆角一起失效。
8. **两台 HttpClient 的代理策略不同**：DoH 解析客户端 `UseProxy = true`（受限网络要靠它出站），
   出口转发 `UseProxy = false`（做 IP 优选必须直连）。
9. **每个候选 IP 要有独立超时预算**（`PerAttemptTimeout`）。只靠外层 `ConnectTimeout` 的话，
   第一个 IP 若是 SYN 无响应的黑洞会耗满整个预算，failover 等于没有。
10. **`FormClosing` 里必须放行关机/注销**（`CloseReason.WindowsShutDown`），否则用户会看到
    "LocalBoost 阻止关机"。
11. **发布输出目录必须在 csproj 里排除**（`Content Remove` / `Compile Remove`），
    否则 `-o publish` 会让产物自我嵌套。

---

## 3. 环境与命令

需要 **Windows** 与 **.NET 9 SDK**（版本由 `global.json` 锁定）。

```bash
dotnet restore LocalBoost.Tests/LocalBoost.Tests.csproj   # 只还原这一个，主程序会被连带还原
dotnet build   LocalBoost.Tests/LocalBoost.Tests.csproj -c Release -warnaserror
dotnet test    LocalBoost.Tests/LocalBoost.Tests.csproj -c Release

dotnet format whitespace LocalBoost.csproj --verify-no-changes   # 空白与换行
dotnet format style      LocalBoost.csproj --verify-no-changes --severity warn
```

要改格式就直接跑（**不要用聚合的 `dotnet format`**）：

```bash
dotnet format whitespace LocalBoost.csproj
```

> 为什么不用聚合命令：它在应用修复时可能因为命名规则去修改编译选项，
> 进而抛 `NotSupportedException` 崩掉。所以 `.editorconfig` 里刻意不写 `dotnet_naming_rule`，
> 命名靠 review 保证。

想跑界面直接 `dotnet bin/Release/net9.0-windows/LocalBoost.dll`（不带参数进图形界面）。
注意**不要**在已有实例运行时跑 `dotnet publish -o publish`，产物文件被占用会直接失败。

---

## 4. 代码约定

- **注释与提交信息用中文**，并且解释**为什么**这么做，而不是复述代码在做什么。
  这个项目里绝大多数注释都是"当年踩了什么坑"，这是它最有价值的部分。
- 私有字段 `_camelCase`，类型与公开成员 `PascalCase`，常量 `PascalCase`。
- 布局相关的数字一律加注释说明是按 100% 缩放的设计值。
- 新增对外可见的东西（环境变量、命令行参数、配置文件字段）要同步更新 README —— 开源之后它们就是公开 API。
- 网络层的 `catch` 允许偏宽（任何失败都不该把进程带崩），但**必须**把原因写进日志或让调用方看到。

---

## 5. 测试

`LocalBoost.Tests` 目前覆盖纯函数：规则表匹配与校验、PAC 生成、hosts 托管区块剥离。
这几处的共同点是**改错了不会立刻炸，只会静默失效**，所以最值得钉住。

- 新增纯逻辑（解析、生成、校验、匹配）请一并加测试。
- 涉及真实证书库 / 注册表 / hosts 文件的行为暂时没有自动化测试，
  这些地方的改动请在 PR 描述里写清**手动验证步骤**与**回滚方式**。
- 报告 P1-2 那类回归（通配域名边界）的测试写在一个地方就好，别散落。

---

## 6. PR 要求

- 一个 PR 做一件事。混着格式化重排与逻辑改动会让人没法 review。
- 描述里写清：**改了什么、为什么、怎么验证的、怎么回滚**。
  - 改了 hosts / 证书 / 系统代理逻辑 → 必须写回滚路径。
  - 改了证书校验相关 → 说明放宽范围有没有变化。
- 如果改动会提高 `rules.json` 或其它外部输入的可信度要求，请在描述里点出来。
- 提交前请确认 CI 会过的四项：编译零警告、whitespace 校验、style(warn+) 校验、单元测试。

---

## 7. 不建议的方向

- **不要往"多功能工具箱"扩。** 本项目的定位是"轻量、只做两件事"，
  功能一多就会和成熟项目正面重叠，也失去存在理由。
- **不要为了让某个特定网络环境能用而放宽安全设置。** 这类问题应该通过配置项
  （并且默认安全）解决，而不是改默认行为。
- 不要顺手改动 README 里那些看起来"啰嗦"的安全说明 —— 它们是给使用者做判断用的。

---

## 8. 行为准则

参与本项目即表示同意 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
