namespace WSCT.GlobalPlatform.Security
{
    public interface IKeyDerivationAlgorithm
    {
        Keys Generate(byte[] baseKeyDiversificationData, byte[] masterKey);
    }
}
