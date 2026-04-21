# FirmadorCR .NET

[![Build & Test](https://github.com/josuegame2030/FirmadorCR-DotNET/actions/workflows/ci.yml/badge.svg)](https://github.com/josuegame2030/FirmadorCR-DotNET/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**English** | [Español](#español)

---

A .NET library for digitally signing electronic XML invoices (*comprobantes electrónicos*) for Costa Rica's **Ministerio de Hacienda** tax authority.

Implements the **XAdES-EPES** signature format as specified in [Hacienda CR v4.4](https://www.hacienda.go.cr/contenido/14716-comprobantes-electronicos).

## Features

- XAdES-EPES digital signatures compliant with Hacienda CR v4.4
- RSA-SHA256 cryptography with XML Canonicalization (C14N)
- Loads P12/PFX certificates with PIN-based authentication
- Returns signed XML as a Base64 string ready for Hacienda's API
- Helper overloads: sign to string, sign to Base64, sign to file
- Zero third-party NuGet dependencies — uses only BCL cryptography APIs

## Requirements

- [.NET 10+](https://dotnet.microsoft.com/download)
- A valid **Hacienda CR P12/PFX digital certificate**
- An unsigned XML invoice conforming to the **v4.4** schema

## Installation

```bash
dotnet add package FirmadorCR
```

## Quick Start

```csharp
using FirmadorCR;

// 1. Read the unsigned XML invoice
string xmlContent = File.ReadAllText("factura.xml");

// 2. Create the signer with your certificate
var firmador = new FirmadorHaciendaCR("mi_certificado.p12", "mi_pin");

// 3. Sign — returns a Respuesta<string> where Datos is Base64-encoded signed XML
Respuesta<string> result = await firmador.FirmarXml(xmlContent);

if (result.Exito)
{
    // Send result.Datos directly to Hacienda's reception API
    Console.WriteLine(result.Datos);
}
```

## API Reference

### `FirmadorHaciendaCR(string pfxPath, string pin)`

Creates a signer instance bound to the given certificate.

### `Task<Respuesta<string>> FirmarXml(string xmlSinFirmar)`

Signs the XML and returns the result wrapped in a `Respuesta<string>`.

| Property | Type | Description |
|---|---|---|
| `Exito` | `bool` | `true` on success |
| `Mensaje` | `string` | Human-readable status message |
| `Datos` | `string` | Signed XML encoded in **Base64** |

### Additional overloads

```csharp
// Sign with explicit credentials (stateless)
string signedXml = firmador.FirmarXml(pfxPath, pin, xmlContent);

// Sign and return Base64 directly
string base64 = firmador.FirmarXmlBase64(pfxPath, pin, xmlContent);

// Sign and write to file
bool ok = firmador.FirmarXmlToFile(pfxPath, pin, xmlContent, "output.xml");
```

## How it works

```
┌───────────────────────────────────────────────────────────────┐
│  Input: unsigned XML (v4.4)  +  P12 certificate               │
└──────────────────────────┬────────────────────────────────────┘
                           │
           ┌───────────────▼───────────────┐
           │  1. Normalize line endings     │
           │     (CRLF → LF for C14N)      │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │  2. Build XAdES-EPES structure │
           │     • SignedInfo               │
           │     • KeyInfo (X.509 cert)     │
           │     • QualifyingProperties     │
           │       – SigningTime (UTC-6)    │
           │       – SigningCertificate     │
           │       – SignaturePolicyId      │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │  3. Compute SHA-256 digests    │
           │     using C14N transforms      │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │  4. Sign SignedInfo with       │
           │     RSA-SHA256 (PKCS#1)        │
           └───────────────┬───────────────┘
                           │
┌──────────────────────────▼────────────────────────────────────┐
│  Output: signed XML encoded in Base64                          │
└───────────────────────────────────────────────────────────────┘
```

The signature policy points to the official Hacienda CR resolution document and uses the SHA-256 digest hardcoded in the specification.

## Running the example

```bash
dotnet run --project Firmador.Example -- cert.p12 my-pin invoice.xml
```

## Running tests

```bash
dotnet test
```

Tests use a dynamically-generated self-signed certificate — no real Hacienda certificate is required.

## Security notes

- **Never commit real P12/PFX certificates to version control.** The `.gitignore` already excludes `*.p12` and `*.pfx`.
- Certificate PINs should be read from environment variables or a secrets manager, not hardcoded.
- The library uses `X509KeyStorageFlags.EphemeralKeySet` to avoid writing private keys to disk.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Run tests: `dotnet test`
4. Open a pull request

## License

[MIT](LICENSE) © Josué Navarro

---

## Español

Librería .NET para firmar digitalmente los **comprobantes electrónicos XML** del Ministerio de Hacienda de Costa Rica.

Implementa el formato de firma **XAdES-EPES** según la especificación de Hacienda CR v4.4.

### Instalación

```bash
dotnet add package FirmadorCR
```

### Uso rápido

```csharp
using FirmadorCR;

string xmlContent = File.ReadAllText("factura.xml");
var firmador = new FirmadorHaciendaCR("mi_certificado.p12", "mi_pin");

Respuesta<string> resultado = await firmador.FirmarXml(xmlContent);

if (resultado.Exito)
{
    // resultado.Datos contiene el XML firmado en Base64
    // Enviar directamente a la API de recepción de Hacienda
    Console.WriteLine(resultado.Datos);
}
```

### Requisitos

- .NET 10+
- Certificado digital P12/PFX emitido por Hacienda
- XML de comprobante electrónico en formato v4.4

### Ejecutar los tests

```bash
dotnet test
```

Los tests generan un certificado autofirmado en tiempo de ejecución. No se requiere un certificado real de Hacienda.

### Notas de seguridad

- **Nunca suba certificados P12/PFX reales a control de versiones.** El `.gitignore` ya excluye `*.p12` y `*.pfx`.
- El PIN del certificado debe leerse desde variables de entorno o un gestor de secretos.
