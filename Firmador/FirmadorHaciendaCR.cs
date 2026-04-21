using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace FirmadorCR
{
    /// <summary>
    /// Signs electronic XML documents for Costa Rica's Hacienda tax authority.
    /// Implements XAdES-EPES format according to Hacienda CR v4.4 specifications.
    /// </summary>
    public class FirmadorHaciendaCR(string pfxPath, string pin) : IFirmador
    {
        #region Constants

        public const string XMLDSIGNS = "http://www.w3.org/2000/09/xmldsig#";
        public const string XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
        public const string XML_SCHEMA_INSTANCE = "http://www.w3.org/2001/XMLSchema-instance";
        public const string XADES = "http://uri.etsi.org/01903/v1.3.2#";
        public const string SHA256_URI = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string RSA_SHA256_URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public const string C14N_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        public const string ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

        // Hacienda CR v4.4 signature policy (URL-encoded per specification)
        public const string SIGN_POLICY_URL = "https://cdn.comprobanteselectronicos.go.cr/xml-schemas/Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf";
        public const string SIGN_POLICY_DIGEST = "DWxin1xWOeI8OuWQXazh4VjLWAaCLAA954em7DMh0h8=";

        #endregion

        #region Per-signature unique IDs

        private string _signatureId = string.Empty;
        private string _signatureValueId = string.Empty;
        private string _xadesObjectId = string.Empty;
        private string _keyInfoId = string.Empty;
        private string _reference0Id = string.Empty;
        private string _reference1Id = string.Empty;
        private string _signedPropertiesId = string.Empty;
        private string _qualifyingPropertiesId = string.Empty;

        #endregion

        #region Certificate state

        private X509Certificate2? _certificate;
        private RSA? _privateKey;
        private string _publicKeyBase64 = string.Empty;
        private string _modulusBase64 = string.Empty;
        private string _exponentBase64 = string.Empty;

        // Namespaces from the original document, needed for correct C14N digest
        private string _xmlns = string.Empty;
        private string _xmlnsXsd = string.Empty;
        private string _xmlnsXsi = string.Empty;

        #endregion

        #region Public API

        /// <summary>
        /// Signs an XML document using the certificate provided at construction time.
        /// </summary>
        /// <param name="xmlSinFirmar">Unsigned XML string (Hacienda CR v4.4 format).</param>
        /// <returns>
        /// A <see cref="Respuesta{T}"/> where <c>Datos</c> is the signed XML encoded in Base64,
        /// ready to be sent to Hacienda's API.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the certificate cannot be loaded or is expired.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when the XML does not comply with the required v4.4 format.
        /// </exception>
        public Task<Respuesta<string>> FirmarXml(string xmlSinFirmar)
        {
            GenerateIds();
            LoadAndValidateCertificate(pfxPath, pin);
            ValidateXmlVersion(xmlSinFirmar);

            string signedXml = SignXmlInternal(xmlSinFirmar);

            return Task.FromResult(new Respuesta<string>
            {
                Exito = true,
                Mensaje = "XML firmado correctamente.",
                Datos = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedXml))
            });
        }

        /// <summary>
        /// Signs an XML document using explicit certificate credentials (stateless overload).
        /// </summary>
        /// <param name="pfxPath">Path to the .p12 / .pfx file.</param>
        /// <param name="pin">Certificate PIN.</param>
        /// <param name="xmlContent">Unsigned XML string.</param>
        /// <returns>Signed XML string.</returns>
        public string FirmarXml(string pfxPath, string pin, string xmlContent)
        {
            GenerateIds();
            LoadAndValidateCertificate(pfxPath, pin);
            ValidateXmlVersion(xmlContent);
            return SignXmlInternal(xmlContent);
        }

        /// <summary>
        /// Signs an XML document and returns the result Base64-encoded.
        /// </summary>
        public string FirmarXmlBase64(string pfxPath, string pin, string xmlContent)
            => Convert.ToBase64String(Encoding.UTF8.GetBytes(FirmarXml(pfxPath, pin, xmlContent)));

        /// <summary>
        /// Signs an XML document and writes the result to <paramref name="outputPath"/>.
        /// </summary>
        /// <returns><c>true</c> on success; <c>false</c> if an error occurred.</returns>
        public bool FirmarXmlToFile(string pfxPath, string pin, string xmlContent, string outputPath)
        {
            try
            {
                File.WriteAllText(outputPath, FirmarXml(pfxPath, pin, xmlContent), Encoding.UTF8);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Certificate loading

        private void LoadAndValidateCertificate(string certPath, string certPin)
        {
            byte[] pfxBytes = File.ReadAllBytes(certPath);

            _certificate = X509CertificateLoader.LoadPkcs12(pfxBytes, certPin,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

            _privateKey = _certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("No se pudo obtener la clave privada RSA del certificado.");

            if (_certificate.NotAfter <= DateTime.Now)
                throw new InvalidOperationException("El certificado está expirado. Por favor use un certificado válido.");

            _publicKeyBase64 = Convert.ToBase64String(_certificate.RawData);

            RSAParameters rsaParams = _privateKey.ExportParameters(false);
            _modulusBase64 = Convert.ToBase64String(rsaParams.Modulus!);
            _exponentBase64 = Convert.ToBase64String(rsaParams.Exponent!);
        }

        #endregion

        #region Core signing logic

        private string SignXmlInternal(string xmlContent)
        {
            // C14N in .NET converts \r to &#xD; which alters the digest — normalize first.
            xmlContent = xmlContent.Replace("\r\n", "\n").Replace("\r", "\n");

            XmlDocument xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(xmlContent);

            _xmlns = xmlDoc.DocumentElement!.GetAttribute("xmlns");
            _xmlnsXsd = xmlDoc.DocumentElement.GetAttribute("xmlns:xsd");
            _xmlnsXsi = xmlDoc.DocumentElement.GetAttribute("xmlns:xsi");

            XmlElement signatureElement = CreateCompleteSignature(xmlDoc);
            xmlDoc.DocumentElement.AppendChild(signatureElement);

            return xmlDoc.OuterXml;
        }

        private XmlElement CreateCompleteSignature(XmlDocument xmlDoc)
        {
            XmlElement signatureNode = CreateDsElement(xmlDoc, "Signature");
            signatureNode.SetAttribute("Id", _signatureId);

            XmlElement signedInfoNode = CreateDsElement(xmlDoc, "SignedInfo");
            signatureNode.AppendChild(signedInfoNode);

            XmlElement canonMethod = CreateDsElement(xmlDoc, "CanonicalizationMethod");
            canonMethod.SetAttribute("Algorithm", C14N_URI);
            signedInfoNode.AppendChild(canonMethod);

            XmlElement sigMethod = CreateDsElement(xmlDoc, "SignatureMethod");
            sigMethod.SetAttribute("Algorithm", RSA_SHA256_URI);
            signedInfoNode.AppendChild(sigMethod);

            XmlElement keyInfoNode = CreateKeyInfo(xmlDoc);
            XmlElement objectNode = CreateXadesObject(xmlDoc);
            XmlElement signedPropertiesNode = GetSignedPropertiesFromObject(objectNode)!;

            string docDigest = CalculateDocumentDigest(xmlDoc);
            signedInfoNode.AppendChild(CreateReference(xmlDoc, "", _reference0Id, docDigest, includeTransforms: true));

            string keyInfoDigest = CalculateNodeDigest(keyInfoNode, includeXadesNamespace: false);
            signedInfoNode.AppendChild(CreateReference(xmlDoc, $"#{_keyInfoId}", _reference1Id, keyInfoDigest, includeTransforms: false));

            string xadesDigest = CalculateNodeDigest(signedPropertiesNode, includeXadesNamespace: true);
            signedInfoNode.AppendChild(CreateReference(xmlDoc, $"#{_signedPropertiesId}", null, xadesDigest, includeTransforms: false, type: "http://uri.etsi.org/01903#SignedProperties"));

            XmlElement signatureValueNode = CreateDsElement(xmlDoc, "SignatureValue");
            signatureValueNode.SetAttribute("Id", _signatureValueId);
            signatureNode.AppendChild(signatureValueNode);

            signatureNode.AppendChild(keyInfoNode);
            signatureNode.AppendChild(objectNode);

            signatureValueNode.InnerText = CalculateSignature(signedInfoNode);

            return signatureNode;
        }

        private static XmlElement? GetSignedPropertiesFromObject(XmlElement objectNode)
        {
            XmlNodeList nodes = objectNode.GetElementsByTagName("SignedProperties", XADES);
            return nodes.Count > 0 ? (XmlElement)nodes[0]! : null;
        }

        private static XmlElement CreateReference(XmlDocument xmlDoc, string uri, string? id, string digestValue, bool includeTransforms, string? type = null)
        {
            XmlElement reference = CreateDsElement(xmlDoc, "Reference");

            if (!string.IsNullOrEmpty(id))
                reference.SetAttribute("Id", id);

            if (!string.IsNullOrEmpty(type))
                reference.SetAttribute("Type", type);

            reference.SetAttribute("URI", uri);

            if (includeTransforms)
            {
                XmlElement transforms = CreateDsElement(xmlDoc, "Transforms");
                XmlElement transform = CreateDsElement(xmlDoc, "Transform");
                transform.SetAttribute("Algorithm", ENVELOPED_SIGNATURE);
                transforms.AppendChild(transform);
                reference.AppendChild(transforms);
            }

            XmlElement digestMethod = CreateDsElement(xmlDoc, "DigestMethod");
            digestMethod.SetAttribute("Algorithm", SHA256_URI);
            reference.AppendChild(digestMethod);

            XmlElement digestValueNode = CreateDsElement(xmlDoc, "DigestValue");
            digestValueNode.InnerText = digestValue;
            reference.AppendChild(digestValueNode);

            return reference;
        }

        private XmlElement CreateKeyInfo(XmlDocument xmlDoc)
        {
            XmlElement keyInfo = CreateDsElement(xmlDoc, "KeyInfo");
            keyInfo.SetAttribute("Id", _keyInfoId);

            XmlElement x509Data = CreateDsElement(xmlDoc, "X509Data");
            XmlElement x509Cert = CreateDsElement(xmlDoc, "X509Certificate");
            x509Cert.InnerText = _publicKeyBase64;
            x509Data.AppendChild(x509Cert);
            keyInfo.AppendChild(x509Data);

            XmlElement keyValue = CreateDsElement(xmlDoc, "KeyValue");
            XmlElement rsaKeyValue = CreateDsElement(xmlDoc, "RSAKeyValue");

            XmlElement modulus = CreateDsElement(xmlDoc, "Modulus");
            modulus.InnerText = _modulusBase64;
            rsaKeyValue.AppendChild(modulus);

            XmlElement exponent = CreateDsElement(xmlDoc, "Exponent");
            exponent.InnerText = _exponentBase64;
            rsaKeyValue.AppendChild(exponent);

            keyValue.AppendChild(rsaKeyValue);
            keyInfo.AppendChild(keyValue);

            return keyInfo;
        }

        private XmlElement CreateXadesObject(XmlDocument xmlDoc)
        {
            XmlElement objectNode = CreateDsElement(xmlDoc, "Object");
            objectNode.SetAttribute("Id", _xadesObjectId);

            XmlElement qualifyingProperties = xmlDoc.CreateElement("xades", "QualifyingProperties", XADES);
            qualifyingProperties.SetAttribute("Id", _qualifyingPropertiesId);
            qualifyingProperties.SetAttribute("Target", $"#{_signatureId}");
            objectNode.AppendChild(qualifyingProperties);

            XmlElement signedProperties = xmlDoc.CreateElement("xades", "SignedProperties", XADES);
            signedProperties.SetAttribute("Id", _signedPropertiesId);
            qualifyingProperties.AppendChild(signedProperties);

            XmlElement signedSigProps = xmlDoc.CreateElement("xades", "SignedSignatureProperties", XADES);
            signedProperties.AppendChild(signedSigProps);

            // Hacienda CR uses UTC-6 (no DST)
            XmlElement signingTime = xmlDoc.CreateElement("xades", "SigningTime", XADES);
            signingTime.InnerText = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss-06:00");
            signedSigProps.AppendChild(signingTime);

            AppendSigningCertificate(xmlDoc, signedSigProps);
            AppendSignaturePolicyIdentifier(xmlDoc, signedSigProps);
            AppendSignerRole(xmlDoc, signedSigProps);

            XmlElement signedDataObjProps = xmlDoc.CreateElement("xades", "SignedDataObjectProperties", XADES);
            signedProperties.AppendChild(signedDataObjProps);

            XmlElement dataObjFormat = xmlDoc.CreateElement("xades", "DataObjectFormat", XADES);
            dataObjFormat.SetAttribute("ObjectReference", $"#{_reference0Id}");
            signedDataObjProps.AppendChild(dataObjFormat);

            XmlElement mimeType = xmlDoc.CreateElement("xades", "MimeType", XADES);
            mimeType.InnerText = "text/xml";
            dataObjFormat.AppendChild(mimeType);

            XmlElement encoding = xmlDoc.CreateElement("xades", "Encoding", XADES);
            encoding.InnerText = "UTF-8";
            dataObjFormat.AppendChild(encoding);

            return objectNode;
        }

        private void AppendSigningCertificate(XmlDocument xmlDoc, XmlElement parent)
        {
            XmlElement signingCert = xmlDoc.CreateElement("xades", "SigningCertificate", XADES);
            parent.AppendChild(signingCert);

            XmlElement cert = xmlDoc.CreateElement("xades", "Cert", XADES);
            signingCert.AppendChild(cert);

            XmlElement certDigest = xmlDoc.CreateElement("xades", "CertDigest", XADES);
            cert.AppendChild(certDigest);

            XmlElement certDigestMethod = CreateDsElement(xmlDoc, "DigestMethod");
            certDigestMethod.SetAttribute("Algorithm", SHA256_URI);
            certDigest.AppendChild(certDigestMethod);

            XmlElement certDigestValue = CreateDsElement(xmlDoc, "DigestValue");
            certDigestValue.InnerText = Convert.ToBase64String(SHA256.HashData(_certificate!.RawData));
            certDigest.AppendChild(certDigestValue);

            XmlElement issuerSerial = xmlDoc.CreateElement("xades", "IssuerSerial", XADES);
            cert.AppendChild(issuerSerial);

            XmlElement issuerName = CreateDsElement(xmlDoc, "X509IssuerName");
            issuerName.InnerText = _certificate.Issuer;
            issuerSerial.AppendChild(issuerName);

            XmlElement serialNumber = CreateDsElement(xmlDoc, "X509SerialNumber");
            serialNumber.InnerText = GetSerialNumberDecimal();
            issuerSerial.AppendChild(serialNumber);
        }

        private static void AppendSignaturePolicyIdentifier(XmlDocument xmlDoc, XmlElement parent)
        {
            XmlElement sigPolicyId = xmlDoc.CreateElement("xades", "SignaturePolicyIdentifier", XADES);
            parent.AppendChild(sigPolicyId);

            XmlElement sigPolicyIdInner = xmlDoc.CreateElement("xades", "SignaturePolicyId", XADES);
            sigPolicyId.AppendChild(sigPolicyIdInner);

            XmlElement policyId = xmlDoc.CreateElement("xades", "SigPolicyId", XADES);
            sigPolicyIdInner.AppendChild(policyId);

            XmlElement identifier = xmlDoc.CreateElement("xades", "Identifier", XADES);
            identifier.InnerText = SIGN_POLICY_URL;
            policyId.AppendChild(identifier);

            policyId.AppendChild(xmlDoc.CreateElement("xades", "Description", XADES));

            XmlElement sigPolicyHash = xmlDoc.CreateElement("xades", "SigPolicyHash", XADES);
            sigPolicyIdInner.AppendChild(sigPolicyHash);

            XmlElement policyDigestMethod = CreateDsElement(xmlDoc, "DigestMethod");
            policyDigestMethod.SetAttribute("Algorithm", SHA256_URI);
            sigPolicyHash.AppendChild(policyDigestMethod);

            XmlElement policyDigestValue = CreateDsElement(xmlDoc, "DigestValue");
            policyDigestValue.InnerText = SIGN_POLICY_DIGEST;
            sigPolicyHash.AppendChild(policyDigestValue);
        }

        private static void AppendSignerRole(XmlDocument xmlDoc, XmlElement parent)
        {
            XmlElement signerRole = xmlDoc.CreateElement("xades", "SignerRole", XADES);
            parent.AppendChild(signerRole);

            XmlElement claimedRoles = xmlDoc.CreateElement("xades", "ClaimedRoles", XADES);
            signerRole.AppendChild(claimedRoles);

            XmlElement claimedRole = xmlDoc.CreateElement("xades", "ClaimedRole", XADES);
            claimedRole.InnerText = "Emisor";
            claimedRoles.AppendChild(claimedRole);
        }

        #endregion

        #region Digest and signature calculation

        private string CalculateDocumentDigest(XmlDocument xmlDoc)
        {
            XmlDsigC14NTransform transform = new XmlDsigC14NTransform(false);
            transform.LoadInput(xmlDoc);

            using MemoryStream ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream));
            return Convert.ToBase64String(SHA256.HashData(ms.ToArray()));
        }

        private string CalculateNodeDigest(XmlElement node, bool includeXadesNamespace)
        {
            XmlDocument tempDoc = new XmlDocument { PreserveWhitespace = true };
            XmlElement tempNode = (XmlElement)tempDoc.ImportNode(node, true);

            if (!string.IsNullOrEmpty(_xmlns))
                tempNode.SetAttribute("xmlns", _xmlns);

            tempNode.SetAttribute("xmlns:ds", XMLDSIGNS);

            if (!string.IsNullOrEmpty(_xmlnsXsd))
                tempNode.SetAttribute("xmlns:xsd", XML_SCHEMA);

            if (!string.IsNullOrEmpty(_xmlnsXsi))
                tempNode.SetAttribute("xmlns:xsi", XML_SCHEMA_INSTANCE);

            if (includeXadesNamespace)
                tempNode.SetAttribute("xmlns:xades", XADES);

            tempDoc.AppendChild(tempNode);

            XmlDsigC14NTransform transform = new XmlDsigC14NTransform(false);
            transform.LoadInput(tempDoc);

            using MemoryStream ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream));
            return Convert.ToBase64String(SHA256.HashData(ms.ToArray()));
        }

        private string CalculateSignature(XmlElement signedInfoNode)
        {
            XmlDocument tempDoc = new XmlDocument { PreserveWhitespace = true };
            XmlElement tempNode = (XmlElement)tempDoc.ImportNode(signedInfoNode, true);

            if (!string.IsNullOrEmpty(_xmlns))
                tempNode.SetAttribute("xmlns", _xmlns);

            tempNode.SetAttribute("xmlns:ds", XMLDSIGNS);

            if (!string.IsNullOrEmpty(_xmlnsXsd))
                tempNode.SetAttribute("xmlns:xsd", XML_SCHEMA);

            if (!string.IsNullOrEmpty(_xmlnsXsi))
                tempNode.SetAttribute("xmlns:xsi", XML_SCHEMA_INSTANCE);

            tempDoc.AppendChild(tempNode);

            XmlDsigC14NTransform transform = new XmlDsigC14NTransform(false);
            transform.LoadInput(tempDoc);

            using MemoryStream ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream));
            return Convert.ToBase64String(
                _privateKey!.SignData(ms.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        #endregion

        #region Helpers

        private void GenerateIds()
        {
            _signatureId = MakeId("Signature-");
            _signatureValueId = MakeId("SignatureValue-");
            _xadesObjectId = MakeId("XadesObjectId-");
            _keyInfoId = $"KeyInfoId-{_signatureId}";
            _reference0Id = MakeId("Reference-");
            _reference1Id = "ReferenceKeyInfo";
            _signedPropertiesId = $"SignedProperties-{_signatureId}";
            _qualifyingPropertiesId = MakeId("QualifyingProperties-");
        }

        private static string MakeId(string prefix)
        {
            string uuid = Guid.NewGuid().ToString("N");
            return $"{prefix}{uuid[..8]}-{uuid[8..12]}-{uuid[12..16]}-{uuid[16..20]}-{uuid[20..]}";
        }

        private string GetSerialNumberDecimal()
        {
            // .NET exposes serial number as hex; Hacienda expects decimal.
            string serialHex = _certificate!.SerialNumber;
            var bigInt = System.Numerics.BigInteger.Parse(serialHex, System.Globalization.NumberStyles.HexNumber);
            if (bigInt < 0)
                bigInt += System.Numerics.BigInteger.Pow(2, serialHex.Length * 4);
            return bigInt.ToString();
        }

        private static void ValidateXmlVersion(string xmlContent)
        {
            if (!xmlContent.Contains("v4.4"))
                throw new ArgumentException("El XML no cumple con el formato requerido. Se requiere versión v4.4.", nameof(xmlContent));
        }

        private static XmlElement CreateDsElement(XmlDocument xmlDoc, string localName)
            => xmlDoc.CreateElement("ds", localName, XMLDSIGNS);

        #endregion
    }
}
