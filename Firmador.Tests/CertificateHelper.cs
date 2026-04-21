using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FirmadorCR.Tests;

/// <summary>
/// Generates a temporary self-signed RSA certificate for use in tests.
/// The certificate is written to a temp .p12 file and cleaned up after use.
/// </summary>
internal sealed class TempCertificate : IDisposable
{
    public string PfxPath { get; }
    public string Pin { get; } = "test-pin-1234";

    public TempCertificate()
    {
        using RSA rsa = RSA.Create(2048);

        var request = new CertificateRequest(
            "CN=FirmadorCR Test, O=Test Org, C=CR",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.Now.AddMinutes(-1),
            DateTimeOffset.Now.AddYears(1));

        PfxPath = Path.GetTempFileName() + ".p12";
        File.WriteAllBytes(PfxPath, cert.Export(X509ContentType.Pfx, Pin));
    }

    public void Dispose()
    {
        if (File.Exists(PfxPath))
            File.Delete(PfxPath);
    }
}
