namespace FirmadorCR
{
    /// <summary>
    /// Contract for signing electronic XML documents for Costa Rica's Hacienda system.
    /// </summary>
    public interface IFirmador
    {
        /// <summary>
        /// Signs an XML document using the configured P12/PFX certificate.
        /// </summary>
        /// <param name="xmlSinFirmar">Unsigned XML content (must comply with Hacienda CR v4.4).</param>
        /// <returns>
        /// A <see cref="Respuesta{T}"/> where <c>Datos</c> is the signed XML encoded in Base64.
        /// </returns>
        Task<Respuesta<string>> FirmarXml(string xmlSinFirmar);
    }
}
