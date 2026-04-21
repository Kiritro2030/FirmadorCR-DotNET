using System.Text;
using FirmadorCR;

// ---------------------------------------------------------------------------
// FirmadorCR — Usage example
// ---------------------------------------------------------------------------
// Prerequisites:
//   1. A valid P12/PFX digital certificate issued by Hacienda CR (SINPE / BCCR).
//   2. An unsigned XML invoice that conforms to the Hacienda CR v4.4 schema.
//
// To run:
//   dotnet run --project Firmador.Example -- <path-to-cert.p12> <pin> <path-to-invoice.xml>
// ---------------------------------------------------------------------------

if (args.Length < 3)
{
    Console.Error.WriteLine("Usage: Firmador.Example <cert.p12> <pin> <invoice.xml>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("  cert.p12     Path to your Hacienda CR P12/PFX certificate");
    Console.Error.WriteLine("  pin          Certificate PIN");
    Console.Error.WriteLine("  invoice.xml  Path to the unsigned XML invoice (v4.4 schema)");
    return 1;
}

string pfxPath    = args[0];
string pin        = args[1];
string xmlPath    = args[2];
string outputPath = Path.ChangeExtension(xmlPath, ".signed.xml");

if (!File.Exists(pfxPath))
{
    Console.Error.WriteLine($"Certificate not found: {pfxPath}");
    return 1;
}

if (!File.Exists(xmlPath))
{
    Console.Error.WriteLine($"XML invoice not found: {xmlPath}");
    return 1;
}

Console.WriteLine($"Certificate : {pfxPath}");
Console.WriteLine($"Invoice     : {xmlPath}");
Console.WriteLine();

try
{
    string xmlContent = File.ReadAllText(xmlPath, Encoding.UTF8);

    // --- Option A: instance-based (recommended for DI / repeated use) --------
    var firmador = new FirmadorHaciendaCR(pfxPath, pin);
    Respuesta<string> result = await firmador.FirmarXml(xmlContent);

    if (!result.Exito)
    {
        Console.Error.WriteLine($"Signing failed: {result.Mensaje}");
        return 1;
    }

    // result.Datos is the signed XML encoded in Base64
    string signedXml = Encoding.UTF8.GetString(Convert.FromBase64String(result.Datos!));
    File.WriteAllText(outputPath, signedXml, Encoding.UTF8);

    Console.WriteLine($"Signed XML  : {outputPath}");
    string datos = result.Datos!;
    Console.WriteLine($"Base64 (first 80 chars): {datos[..Math.Min(80, datos.Length)]}...");
    Console.WriteLine();

    // --- Option B: stateless overload ----------------------------------------
    // string signedXmlB = firmador.FirmarXml(pfxPath, pin, xmlContent);

    // --- Option C: write directly to file ------------------------------------
    // bool ok = firmador.FirmarXmlToFile(pfxPath, pin, xmlContent, outputPath);

    Console.WriteLine("Done. Send result.Datos (Base64) to Hacienda's API.");
    return 0;
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Invalid XML: {ex.Message}");
    return 1;
}
catch (InvalidOperationException ex)
{
    Console.Error.WriteLine($"Certificate error: {ex.Message}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Unexpected error: {ex.Message}");
    return 1;
}
