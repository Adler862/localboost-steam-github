using System.Security.Cryptography.X509Certificates;

namespace LocalBoost.Tests;

/// <summary>
/// 叶证书扩展的编码。
///
/// 这一组测试存在的唯一理由是：**ASN.1 编码错了以后，宽容的解析器全都看不出来**。
/// 本项目就踩过一次 —— 叶证书的 Authority Key Identifier 被写成 EXPLICIT 标签，
/// Windows 的链引擎、openssl、curl 全部正常，只有浏览器拒绝（ERR_CERT_INVALID），
/// 结果这个现象被反复误判成"HSTS 拦截""根证书没装好""吊销检查失败"，拖了很久。
/// 所以这里直接把字节钉住，任何重新手拼 DER 的尝试都会在这里失败。
/// </summary>
public sealed class LeafExtensionTests
{
    private const string RootKeyId = "10B8D91989FF9DDDECF4E567490BD92B41FEE30B";

    [Fact]
    public void AKI里的0号标签必须是IMPLICIT的primitive()
    {
        var aki = LocalCertAuthority.BuildAuthorityKeyIdentifier(RootKeyId);
        var raw = aki.RawData;

        // 规范编码：SEQUENCE { [0] IMPLICIT keyIdentifier }
        //  30 16 80 14 <20 字节 keyid>
        //            ↑ 0x80 = context 0 + primitive（IMPLICIT）
        // 写成 0xA0（context 0 + constructed，EXPLICIT）就是错的 ——
        // RFC 5280 的模块是 DEFINITIONS IMPLICIT TAGS。
        Assert.Equal(0x30, raw[0]);
        Assert.Equal(0x80, raw[2]);
        Assert.NotEqual(0xA0, raw[2]);
    }

    [Fact]
    public void AKI的总长度与keyid长度对得上()
    {
        var aki = LocalCertAuthority.BuildAuthorityKeyIdentifier(RootKeyId);
        var raw = aki.RawData;

        // 期望 30 16 | 80 14 | 20 字节
        Assert.True(raw.Length == 24 && raw[1] == 22 && raw[3] == 20,
            $"实际字节：{Convert.ToHexString(raw)}（共 {raw.Length} 字节）");

        Assert.Equal(20, raw[3]);
    }

    [Fact]
    public void AKI里带的确实是根证书的keyid()
    {
        var aki = LocalCertAuthority.BuildAuthorityKeyIdentifier(RootKeyId);
        var raw = aki.RawData;

        var keyId = Convert.ToHexString(raw[4..]);
        Assert.Equal(RootKeyId, keyId);
    }

    [Fact]
    public void AKI的OID是_2_5_29_35()
    {
        var aki = LocalCertAuthority.BuildAuthorityKeyIdentifier(RootKeyId);

        Assert.NotNull(aki.Oid);
        Assert.Equal("2.5.29.35", aki.Oid!.Value);
    }

    [Fact]
    public void AKI不是关键扩展()
    {
        // RFC 5280 允许它 critical，但实际部署中都是非关键，保持一致
        var aki = LocalCertAuthority.BuildAuthorityKeyIdentifier(RootKeyId);

        Assert.False(aki.Critical);
    }
}
