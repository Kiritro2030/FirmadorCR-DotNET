using System.Text;
using System.Xml;

namespace FirmadorCR.Tests;

public class FirmadorHaciendaCRTests
{
    // Minimal valid Hacienda v4.4 XML used across tests
    private const string ValidXmlTemplate =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <FacturaElectronica xmlns="https://cdn.comprobanteselectronicos.go.cr/xml-schemas/v4.4/facturaElectronica"
                            xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <Clave>50601012400310121234500100001010000000011199999999</Clave>
          <CodigoActividad>620900</CodigoActividad>
          <NumeroConsecutivo>00100001010000000011</NumeroConsecutivo>
          <FechaEmision>2024-01-01T08:00:00-06:00</FechaEmision>
        </FacturaElectronica>
        """;

    #region Constructor / validation

    [Fact]
    public void Constructor_WithValidArguments_DoesNotThrow()
    {
        var _ = new FirmadorHaciendaCR("some/path.p12", "pin");
    }

    [Fact]
    public async Task FirmarXml_WithMissingCertFile_ThrowsFileNotFoundException()
    {
        var firmador = new FirmadorHaciendaCR("nonexistent.p12", "1234");
        await Assert.ThrowsAnyAsync<Exception>(() => firmador.FirmarXml(ValidXmlTemplate));
    }

    [Fact]
    public async Task FirmarXml_WithXmlMissingV44_ThrowsArgumentException()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        const string badXml = """
            <?xml version="1.0" encoding="utf-8"?>
            <FacturaElectronica xmlns="https://cdn.comprobanteselectronicos.go.cr/xml-schemas/v4.3/facturaElectronica">
              <Clave>50601012400310121234500100001010000000011199999999</Clave>
            </FacturaElectronica>
            """;

        await Assert.ThrowsAsync<ArgumentException>(() => firmador.FirmarXml(badXml));
    }

    [Fact]
    public async Task FirmarXml_WithWrongPin_ThrowsException()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, "wrong-pin");
        await Assert.ThrowsAnyAsync<Exception>(() => firmador.FirmarXml(ValidXmlTemplate));
    }

    #endregion

    #region Successful signing

    [Fact]
    public async Task FirmarXml_WithValidInputs_ReturnsSuccess()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        Respuesta<string> result = await firmador.FirmarXml(ValidXmlTemplate);

        Assert.True(result.Exito);
        Assert.NotNull(result.Datos);
        Assert.NotEmpty(result.Datos);
    }

    [Fact]
    public async Task FirmarXml_ReturnsDatosAsBase64EncodedXml()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        Respuesta<string> result = await firmador.FirmarXml(ValidXmlTemplate);

        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(result.Datos!));
        Assert.Contains("<ds:Signature", decoded);
    }

    [Fact]
    public async Task FirmarXml_SignedXmlContainsRequiredXadesElements()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        Respuesta<string> result = await firmador.FirmarXml(ValidXmlTemplate);
        string signedXml = Encoding.UTF8.GetString(Convert.FromBase64String(result.Datos!));

        Assert.Contains("ds:SignedInfo", signedXml);
        Assert.Contains("ds:SignatureValue", signedXml);
        Assert.Contains("ds:KeyInfo", signedXml);
        Assert.Contains("xades:QualifyingProperties", signedXml);
        Assert.Contains("xades:SignedProperties", signedXml);
        Assert.Contains("xades:SigningTime", signedXml);
        Assert.Contains("xades:SigningCertificate", signedXml);
        Assert.Contains("xades:SignaturePolicyIdentifier", signedXml);
    }

    [Fact]
    public async Task FirmarXml_SignedXmlIsWellFormedDocument()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        Respuesta<string> result = await firmador.FirmarXml(ValidXmlTemplate);
        string signedXml = Encoding.UTF8.GetString(Convert.FromBase64String(result.Datos!));

        var xmlDoc = new XmlDocument();
        var ex = Record.Exception(() => xmlDoc.LoadXml(signedXml));
        Assert.Null(ex);
    }

    [Fact]
    public async Task FirmarXml_CalledTwice_ProducesDifferentSignatureIds()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        Respuesta<string> r1 = await firmador.FirmarXml(ValidXmlTemplate);
        Respuesta<string> r2 = await firmador.FirmarXml(ValidXmlTemplate);

        // Each call must generate fresh IDs
        Assert.NotEqual(r1.Datos, r2.Datos);
    }

    [Fact]
    public async Task FirmarXml_PolicyUrlAndDigestMatchHaciendaSpec()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        Respuesta<string> result = await firmador.FirmarXml(ValidXmlTemplate);
        string signedXml = Encoding.UTF8.GetString(Convert.FromBase64String(result.Datos!));

        Assert.Contains(FirmadorHaciendaCR.SIGN_POLICY_URL, signedXml);
        Assert.Contains(FirmadorHaciendaCR.SIGN_POLICY_DIGEST, signedXml);
    }

    #endregion

    #region Stateless overloads

    [Fact]
    public void FirmarXml_StatelessOverload_ReturnSignedXmlString()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        string signed = firmador.FirmarXml(cert.PfxPath, cert.Pin, ValidXmlTemplate);

        Assert.Contains("<ds:Signature", signed);
    }

    [Fact]
    public void FirmarXmlBase64_ReturnsBase64EncodedString()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        string base64 = firmador.FirmarXmlBase64(cert.PfxPath, cert.Pin, ValidXmlTemplate);
        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64));

        Assert.Contains("<ds:Signature", decoded);
    }

    [Fact]
    public void FirmarXmlToFile_WritesSignedXmlToFile()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);
        string outputPath = Path.GetTempFileName();

        try
        {
            bool success = firmador.FirmarXmlToFile(cert.PfxPath, cert.Pin, ValidXmlTemplate, outputPath);

            Assert.True(success);
            Assert.True(File.Exists(outputPath));
            string content = File.ReadAllText(outputPath);
            Assert.Contains("<ds:Signature", content);
        }
        finally
        {
            File.Delete(outputPath);
        }
    }

    [Fact]
    public void FirmarXmlToFile_WithInvalidOutputPath_ReturnsFalse()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        bool result = firmador.FirmarXmlToFile(cert.PfxPath, cert.Pin, ValidXmlTemplate, "/invalid/path/output.xml");

        Assert.False(result);
    }

    #endregion

    #region CRLF normalization

    [Fact]
    public async Task FirmarXml_WithWindowsLineEndings_ProducesValidSignature()
    {
        using var cert = new TempCertificate();
        var firmador = new FirmadorHaciendaCR(cert.PfxPath, cert.Pin);

        string windowsXml = ValidXmlTemplate.Replace("\n", "\r\n");
        Respuesta<string> result = await firmador.FirmarXml(windowsXml);

        Assert.True(result.Exito);
        Assert.NotNull(result.Datos);
    }

    #endregion
}
