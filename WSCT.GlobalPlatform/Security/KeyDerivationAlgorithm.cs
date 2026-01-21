namespace WSCT.GlobalPlatform.Security
{
    #region >> KeyDerivationAlgorithm *

    /// <summary>
    /// A factory class used to create key derivation algorithms.
    /// </summary>
    public class KeyDerivationAlgorithm
    {
        /// <summary>
        /// Creates a key derivation algorithm.
        /// </summary>
        /// <param name="identifier">The identifier of the key derivation algorithm.</param>
        /// <returns>An instance of the key derivation algorithm.</returns>
        public static IKeyDerivationAlgorithm Create(KeyDerivationAlgorithmIdentifier identifier)
        {
            return identifier switch
            {
                KeyDerivationAlgorithmIdentifier.Visa2 => new Visa2KeyDerivationAlgorithm(),
                KeyDerivationAlgorithmIdentifier.EmvCps11 => throw new NotImplementedException(identifier.ToString()),
                _ => throw new ArgumentOutOfRangeException(identifier.ToString())
            };
        }
    }

    #endregion
}
