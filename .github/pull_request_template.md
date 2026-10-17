<!--
提交前请先过一遍 CONTRIBUTING.md 的第 1 节「红线」与第 2 节「踩过的坑」。
-->

## 改了什么

<!-- 一句话说清这个 PR 做什么 -->

## 为什么

<!-- 解决什么问题？关联的 Issue 编号？ -->

## 怎么验证的

<!--
  列出你实际做过的验证，不要只写"应该没问题"。
  涉及界面改动的请附截图（这个项目改 UI 一律靠截图迭代）。
  涉及网络行为的请写清用的什么命令、看到了什么结果。
-->

- [ ] `dotnet build LocalBoost.Tests/LocalBoost.Tests.csproj -c Release -warnaserror` 零警告
- [ ] `dotnet format whitespace LocalBoost.csproj --verify-no-changes`
- [ ] `dotnet format style LocalBoost.csproj --verify-no-changes --severity warn`
- [ ] `dotnet test LocalBoost.Tests/LocalBoost.Tests.csproj -c Release` 全绿

## 怎么回滚

<!--
  改了 hosts / 证书库 / 系统代理 / 规则表语义的必须写。
  写清用户怎么把机器恢复到改动前的状态。
-->

## 是否触碰安全敏感面

<!-- 下面每一条都请如实勾选，"不涉及"也要勾 -->

- [ ] 没有放宽任何证书校验（或者：放宽范围**没有**变化，说明见下）
- [ ] 没有新增第三方依赖（或者：新增依赖的理由与 BCL 无法实现的原因见下）
- [ ] 没有让代理监听超出环回、也没有让它接管规则表外的域名
- [ ] 没有在用户未主动操作时改动系统设置
- [ ] 没有新增对外网络请求
- [ ] 根证书私钥的落盘强度没有变化

## 其它

<!-- 需要 reviewer 特别注意的地方、或者你拿不准的取舍 -->
