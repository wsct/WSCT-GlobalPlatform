namespace WSCT.GlobalPlatform.Security
{
    /// <summary>
    /// Key derivation algorithm interface.
    /// </summary>
    public interface IKeyDerivationAlgorithm
    {
        /// <summary>
        /// Generate the session keys.
        /// </summary>
        /// <param name="baseKeyDiversificationData">Base key diversification data.</param>
        /// <param name="masterKey">Master key.</param>
        /// <returns>Session keys generated.</returns>
        Keys Generate(byte[] baseKeyDiversificationData, byte[] masterKey);
    }
}
