using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace LocalBoost;

/// <summary>
/// 本地根 CA + 动态叶证书签发。
///
/// 本地反代 HTTPS 必须 MITM：浏览器以为自己在连 github.com，
/// 实际上连的是 127.0.0.1，所以本机得拿出一张 github.com 的证书，
/// 而且这张证书必须被系统信任，否则浏览器一直报警。
///
/// 全部用 BCL 自带能力实现，不依赖 OpenSSL / BouncyCastle。
///
/// 根证书必须装到 **LocalMachine\Root（计算机级）**：Chromium 系浏览器
/// （Chrome / Edge）的网络进程跑在沙箱里，读不到 CurrentUser 用户证书库，
/// 只装用户库时浏览器找不到签发者，链是"部分链"，直接报 ERR_CERT_INVALID。
///
/// 私钥保护（本文件的安全核心）：
/// 私钥一旦泄露就等于"可以为任意网站签发被本机信任的证书"，因此落盘做了三层：
///   1. 随机口令：每次生成 32 字节随机口令，不再使用硬编码口令；
///   2. DPAPI：口令与 PKCS12 主体都经 <see cref="ProtectedData"/> 按当前用户加密，
///      拷到别的机器或别的用户上下文下都无法解密；
///   3. 目录 ACL：存储目录断开继承，只留当前用户 / Administrators / SYSTEM。
/// </summary>
public sealed class LocalCertAuthority : IDisposable
{
    private const string RootSubject = "CN=LocalBoost Local Root CA";

    /// <summary>旧版本用的硬编码口令。只在迁移历史文件时读取，不再用于写入。</summary>
    private const string LegacyPassword = "localboost";

    private const string PfxFileName = "root-ca.dpapi";
    private const string SecretFileName = "root-ca.key.dpapi";
    private const string LegacyPfxFileName = "root-ca.pfx";

    /// <summary>
    /// 叶证书必须落到密钥容器里：Schannel 作为 TLS 服务端时要能拿到密钥容器句柄，
    /// 用 EphemeralKeySet 会直接握手失败（现象是 openssl 报 no peer certificate available，
    /// 而服务端日志里看不到任何异常 —— 排查时别被这一点带偏）。
    ///
    /// 但**不加** Exportable：服务端只用它签名，不需要导出能力，少一项能力就少一条泄露路径。
    /// </summary>
    private const X509KeyStorageFlags LeafKeyFlags = X509KeyStorageFlags.PersistKeySet;

    /// <summary>
    /// 根证书只在内存里做签名（不经 Schannel），所以可以用临时密钥集，
    /// 不在用户密钥库里留下任何痕迹，也不需要导出能力。
    /// </summary>
    private const X509KeyStorageFlags RootKeyFlags = X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>迁移旧文件时要重新导出一次，必须带 Exportable。</summary>
    private const X509KeyStorageFlags LegacyKeyFlags =
        X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;

    /// <summary>DPAPI 的附加熵，让本程序加密的密文不能与其它程序互相解。</summary>
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("LocalBoost.RootCA.v1");

    private readonly string _dir;
    private readonly ConcurrentDictionary<string, Lazy<X509Certificate2>> _issued =
        new(StringComparer.OrdinalIgnoreCase);

    private X509Certificate2 _root = null!;
    private RSA _rootKey = null!;
    private byte[] _password = [];

    public LocalCertAuthority(string? storeDir = null)
    {
        _dir = storeDir ?? DefaultStoreDir;
        Directory.CreateDirectory(_dir);
        SecureDirectory();

        if (!LoadOrCreate())
            throw new InvalidOperationException($"无法准备根证书，存储目录：{_dir}");
    }

    public static string DefaultStoreDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LocalBoost");

    /// <summary>密钥材料所在目录（内含 DPAPI 加密的 PKCS12 与口令）。</summary>
    public string StoragePath => _dir;

    public X509Certificate2 Root => _root;

    /// <summary>
    /// 根证书是否已装进「计算机 → 受信任的根证书颁发机构」。
    ///
    /// 判定只看 LocalMachine：Chromium 系浏览器（Chrome / Edge）的网络进程是沙箱化的
    /// 低完整性进程，读不到 CurrentUser 用户证书库。只装用户库时浏览器拿不到签发者，
    /// 链被判为"部分链"，表现为 ERR_CERT_INVALID（不是常见的 ERR_CERT_AUTHORITY_INVALID）。
    /// </summary>
    public bool IsRootInstalled() => IsInStore(StoreLocation.LocalMachine);

    /// <summary>指定证书库里是否存在**当前这把**根证书（按指纹比对，不看 Subject）。</summary>
    private bool IsInStore(StoreLocation location)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadOnly);

            // 比指纹而不是比 Subject：根证书可能因为文件损坏或临近过期被重建，
            // 换过密钥之后只比名字会误判成"已安装"，于是叶证书由新密钥签发、
            // 系统信任的还是旧根，全站 ERR_CERT_INVALID，而且重装一次也修不好。
            return store.Certificates
                .Any(c => string.Equals(c.Thumbprint, _root.Thumbprint, StringComparison.OrdinalIgnoreCase));
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public void InstallRoot()
    {
        AddToStore(StoreLocation.LocalMachine);
        TryCleanStore(StoreLocation.CurrentUser);
    }

    /// <summary>
    /// 确保根证书装到计算机信任库。返回「此前就已经装好」。
    ///
    /// 同时尽力清掉旧版本留在「当前用户」证书库里的副本：浏览器不读用户库，
    /// 那份副本没有用处，留着只会让人误以为"已经装过了"。
    ///
    /// 清理结果**不对外报告**：实测 Windows 有时会拒绝删除（.NET 只抛一个
    /// CryptographicException，而 certutil -delstore 却能删掉），而且 .NET 的枚举
    /// 结果与注册表实际存储还会互相矛盾。基于不可靠的枚举去生成提示，
    /// 只会给出误导性结论，所以这里只做事、不下结论。
    /// </summary>
    public bool EnsureInstalled()
    {
        // 顺序不能反：必须先确认计算机库可用，再清用户库。
        // 否则在权限不足时会先删掉用户库那份、又装不上计算机库，最后两边都没有。
        var alreadyInstalled = IsRootInstalled();
        if (!alreadyInstalled)
            AddToStore(StoreLocation.LocalMachine);

        TryCleanStore(StoreLocation.CurrentUser);
        return alreadyInstalled;
    }

    /// <summary>
    /// 卸载根证书。返回计算机信任库是否已经清干净。
    /// 计算机库的判定基于指纹比对，是可靠的；用户库那侧尽力而为。
    /// </summary>
    public bool UninstallRoot()
    {
        var machineCleared = TryCleanStore(StoreLocation.LocalMachine);
        TryCleanStore(StoreLocation.CurrentUser);
        return machineCleared;
    }

    private void AddToStore(StoreLocation location)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadWrite);

            // 先删同名的旧根：根证书重建（换密钥）时不能把两张都留着
            foreach (var stale in store.Certificates.Cast<X509Certificate2>()
                         .Where(c => string.Equals(c.Subject, RootSubject, StringComparison.OrdinalIgnoreCase))
                         .ToList())
            {
                store.Remove(stale);
            }

            store.Add(_root);
        }
        catch (CryptographicException ex)
        {
            var scope = location == StoreLocation.LocalMachine ? "计算机" : "当前用户";
            throw new InvalidOperationException(
                $"写入{scope}信任库失败，多半是权限不足——请以管理员身份运行 LocalBoost 后重试。", ex);
        }
    }

    /// <summary>
    /// 尝试清掉指定证书库里的本程序根证书，返回是否真的清干净了。
    ///
    /// 这里有个 Windows 的坑值得记下来：把根证书装进 LocalMachine\Root 之后，
    /// **.NET 的 <c>X509Store(CurrentUser, Root)</c> 枚举会把计算机级的根一起列出来**，
    /// 而 <c>HKCU\Software\Microsoft\SystemCertificates\Root\Certificates</c> 和
    /// <c>certutil -user -store Root</c> 都看不到它。此时对这条"影子条目"调 Remove
    /// 会返回"拒绝访问"（它本来就不在用户库里，没得删）。
    ///
    /// 所以：删除失败不代表用户库真的有残留，**必须回读实际存储来判断**，
    /// 更不能在删除失败时告诉用户"已清理"——旧实现就是吞掉异常照样报成功。
    /// </summary>
    private bool TryCleanStore(StoreLocation location)
    {
        if (CountOurRootIn(location) == 0)
            return true;

        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadWrite);

            // 先物化成列表再删：直接遍历 store.Certificates 会在删除时踩到集合被修改
            var doomed = store.Certificates.Cast<X509Certificate2>()
                .Where(c => string.Equals(c.Subject, RootSubject, StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var existing in doomed)
                store.Remove(existing);
        }
        catch (CryptographicException)
        {
            // 权限被拒等，交给下面的复查给出真实结论
        }

        return CountOurRootIn(location) == 0;
    }

    /// <summary>数一数指定证书库里有几张本程序的根证书（按 Subject，用于清理）。</summary>
    private static int CountOurRootIn(StoreLocation location)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Cast<X509Certificate2>()
                .Count(c => string.Equals(c.Subject, RootSubject, StringComparison.OrdinalIgnoreCase));
        }
        catch (CryptographicException)
        {
            return 0;
        }
    }

    public X509Certificate2 GetOrIssue(string host) =>
        // 用 Lazy 包一层：GetOrAdd 的工厂在多线程下可能被调用多次，
        // 只有一个结果会被存入，直接返回 X509Certificate2 的话其余实例会被丢掉且不释放。
        _issued.GetOrAdd(
            host,
            h => new Lazy<X509Certificate2>(() => Issue(h), LazyThreadSafetyMode.ExecutionAndPublication)).Value;

    private X509Certificate2 Issue(string host)
    {
        using var leafKey = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={host}", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, 0, critical: true));

        // Key Usage 必须显式写上，这一条是修 ERR_CERT_INVALID 的关键。
        //
        // 缺了它，Windows 的链引擎在**只建链**时不会报错（X509Chain 返回成功、零标志），
        // 但一旦跑 SSL 用途策略检查（CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)，
        // 浏览器就是这么验的）就会被判「不得用于该用途」；Chromium 把它映射成
        // net::ERR_CERT_INVALID(-207)，而 HSTS 域名又不给「继续访问」按钮，
        // 表现就是整站打不开 —— 而且极易被误判成"根证书没装好"。
        //
        // 实测对照（同一台机器、同一个根证书形状，只差这一项）：
        //   叶证书无 Key Usage  → Edge 报 ERR_CERT_INVALID
        //   叶证书有 Key Usage  → Edge 正常加载
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));   // serverAuth
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var rootSki = _root.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
        if (rootSki?.SubjectKeyIdentifier is { Length: > 0 } ski)
        {
            request.CertificateExtensions.Add(BuildAuthorityKeyIdentifier(ski));
        }

        // RFC 5280 要求序列号是非负整数。最高位为 1 时会被解析成负数，
        // 部分中间盒和 Windows CryptoAPI 会直接拒收，所以清掉最高位。
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        using var signed = request.Create(
            _root.SubjectName,
            X509SignatureGenerator.CreateForRSA(_rootKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90),
            serial);

        using var withKey = signed.CopyWithPrivateKey(leafKey);
        return X509CertificateLoader.LoadPkcs12(
            withKey.Export(X509ContentType.Pfx, Password),
            Password,
            LeafKeyFlags);
    }

    /// <summary>加载已有根证书；没有或不可用则新建。返回是否成功持有根证书。</summary>
    private bool LoadOrCreate()
    {
        var existing = LoadModern() ?? LoadLegacy();
        if (existing is not null)
        {
            if (existing.NotAfter.ToUniversalTime() > DateTimeOffset.UtcNow.AddDays(30))
            {
                Adopt(existing);
                return true;
            }

            // 临近过期就重建。旧的那张同名根证书会在下次 InstallRoot 时被 RemoveSameSubject 清掉。
            existing.Dispose();
        }

        CreateRoot();
        return true;
    }

    private X509Certificate2? LoadModern()
    {
        var pfxFile = Path.Combine(_dir, PfxFileName);
        var secretFile = Path.Combine(_dir, SecretFileName);
        if (!File.Exists(pfxFile) || !File.Exists(secretFile))
            return null;

        byte[]? password = null;
        try
        {
            _password = Unprotect(File.ReadAllBytes(secretFile));
            password = (byte[])_password.Clone();
            var pfx = Unprotect(File.ReadAllBytes(pfxFile));

            var loaded = X509CertificateLoader.LoadPkcs12(pfx, Encoding.UTF8.GetString(password), RootKeyFlags);
            CryptographicOperations.ZeroMemory(pfx);

            if (!loaded.HasPrivateKey)
            {
                loaded.Dispose();
                return null;
            }

            return loaded;
        }
        catch
        {
            // 文件损坏或换了 Windows 账户（DPAPI 解不开）都走这里，直接重建
            return null;
        }
        finally
        {
            if (password is not null)
                CryptographicOperations.ZeroMemory(password);
        }
    }

    /// <summary>
    /// 迁移旧版本的文件：明文 PKCS12 + 硬编码口令 "localboost"。
    /// 必须保住密钥本身，否则已装进信任库的旧根证书会与新叶证书不匹配，
    /// 用户的浏览器会立刻全站报 ERR_CERT_INVALID。
    /// </summary>
    private X509Certificate2? LoadLegacy()
    {
        var legacy = Path.Combine(_dir, LegacyPfxFileName);
        if (!File.Exists(legacy))
            return null;

        try
        {
            var loaded = X509CertificateLoader.LoadPkcs12(
                File.ReadAllBytes(legacy), LegacyPassword, LegacyKeyFlags);
            if (!loaded.HasPrivateKey)
            {
                loaded.Dispose();
                return null;
            }

            _password = RandomNumberGenerator.GetBytes(32);
            Persist(loaded.Export(X509ContentType.Pkcs12, Password));
            File.Delete(legacy);
            return loaded;
        }
        catch
        {
            return null;
        }
    }

    private void Adopt(X509Certificate2 cert)
    {
        _root = cert;
        _rootKey = cert.GetRSAPrivateKey() ?? throw new InvalidDataException("根证书缺少 RSA 私钥");
    }

    private void CreateRoot()
    {
        _rootKey?.Dispose();
        _rootKey = RSA.Create(2048);
        _password = RandomNumberGenerator.GetBytes(32);

        var request = new CertificateRequest(
            RootSubject, _rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, 12, critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        // 根证书是 CA，Key Usage 里必须有 keyCertSign —— 这是标准做法，也是各类检查器
        // 最容易挑的地方。这里**刻意不再加 EKU**：在根证书上放 extendedKeyUsage 会把
        // 整条链限制在那些用途上（RFC 5280），属于非标准配置，也白白缩窄了将来可能
        // 需要的用途。实测根证书不带 EKU、带 keyCertSign 时，Windows 链引擎与浏览器都正常。
        //
        // 注意：这只影响**新建**的根证书。用户机器上已有的根不会被改动 ——
        // 现有根配上面补了 Key Usage 的叶证书已经验证可用，不必让人重装证书。
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));

        using var selfSigned = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        // 先把明文 PKCS12 拿到手再落盘：加载回来的实例不再带导出能力，
        // 之后就没法再导出一次了。
        var pfx = selfSigned.Export(X509ContentType.Pkcs12, Password);
        Persist(pfx);
        Adopt(X509CertificateLoader.LoadPkcs12(pfx, Password, RootKeyFlags));
    }

    /// <summary>把 PKCS12 与随机口令分别 DPAPI 加密后落盘。</summary>
    private void Persist(byte[] pfx)
    {
        File.WriteAllBytes(Path.Combine(_dir, PfxFileName), Protect(pfx));
        File.WriteAllBytes(Path.Combine(_dir, SecretFileName), Protect(_password));
    }

    private string Password => Encoding.UTF8.GetString(_password);

    /// <summary>
    /// 断开继承，只留当前用户、Administrators 与 SYSTEM。
    /// 默认继承来的 ACL 会带上 Users，而本目录里放着能签发任意网站证书的私钥。
    /// </summary>
    private void SecureDirectory()
    {
        try
        {
            var info = new DirectoryInfo(_dir);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            AddFullControl(security, WindowsIdentity.GetCurrent().User, inherit);
            AddFullControl(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), inherit);
            AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), inherit);

            info.SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException
                                       or PlatformNotSupportedException or InvalidOperationException
                                       or IOException)
        {
            // 改不动 ACL 不是致命问题（例如目录在只读介质上），DPAPI 那层保护仍在
        }
    }

    private static void AddFullControl(FileSystemSecurity security, IdentityReference? identity, InheritanceFlags inherit)
    {
        if (identity is null)
            return;

        security.AddAccessRule(new FileSystemAccessRule(
            identity, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
    }

    private static byte[] Protect(byte[] plain) =>
        ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);

    private static byte[] Unprotect(byte[] cipher) =>
        ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);

    /// <summary>
    /// 手工拼 AKI 扩展的 DER：SEQUENCE { [0] KeyIdentifier :: OCTET STRING }
    /// SKI 是 20 字节 SHA-1，长度都远小于 128，短格式长度字节够用。
    /// </summary>
    /// <summary>
    /// 构造叶证书用的 Authority Key Identifier 扩展。
    ///
    /// 用 BCL 生成，不要手拼 DER。以前这里是自己拼字节的，而且拼错了：
    /// RFC 5280 的模块声明是 `DEFINITIONS IMPLICIT TAGS`，所以 [0] 是 **IMPLICIT**、
    /// 编码应为 `80 14 &lt;keyid&gt;`（0x80 = context 0，primitive）；
    /// 而原来的实现当成 EXPLICIT 写成了 `A0 16 04 14 &lt;keyid&gt;`。
    ///
    /// 这种错误最难查的地方在于**宽容的解析器全都照收**：Windows CryptoAPI 建链正常、
    /// openssl 显示正常、curl 也能连上；只有浏览器自带的严格解析器会失败，
    /// 报 "Failed parsing authority key identifier"，然后判定整张证书无效 ——
    /// 表现就是 ERR_CERT_INVALID，而 HSTS 域名还不给"继续访问"按钮。
    /// 项目里这个现象被反复误判成"HSTS 拦的""根证书没装好""吊销检查失败"，
    /// 实际原因一直是这一处编码。
    /// </summary>
    internal static X509AuthorityKeyIdentifierExtension BuildAuthorityKeyIdentifier(string subjectKeyIdentifierHex)
    {
        var keyId = Convert.FromHexString(subjectKeyIdentifierHex);
        return X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(keyId);
    }

    public void Dispose()
    {
        foreach (var lazy in _issued.Values)
        {
            if (lazy.IsValueCreated)
                lazy.Value.Dispose();
        }

        _issued.Clear();
        _root?.Dispose();
        _rootKey?.Dispose();

        if (_password.Length > 0)
            CryptographicOperations.ZeroMemory(_password);
    }
}
