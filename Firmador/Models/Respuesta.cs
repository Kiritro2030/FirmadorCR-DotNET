namespace FirmadorCR
{
    /// <summary>
    /// Represents the result of a signing operation.
    /// </summary>
    /// <typeparam name="T">The type of the returned data.</typeparam>
    public class Respuesta<T>
    {
        /// <summary>Whether the operation succeeded.</summary>
        public bool Exito { get; set; }

        /// <summary>Human-readable message describing the result.</summary>
        public string Mensaje { get; set; } = string.Empty;

        /// <summary>The data returned by the operation, or default on failure.</summary>
        public T? Datos { get; set; }
    }
}
