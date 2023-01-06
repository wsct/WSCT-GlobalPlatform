namespace WSCT.GlobalPlatform.Security
{
    #region >> KeyDerivationAlgorithm *

    public class KeyDerivationAlgorithm
    {
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
