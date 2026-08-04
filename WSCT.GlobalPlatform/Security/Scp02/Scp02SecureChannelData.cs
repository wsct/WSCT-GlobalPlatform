using WSCT.Helpers;

namespace WSCT.GlobalPlatform.Security;

/// <summary>
/// The data used to manage a secure channel.
/// </summary>
public class Scp02SecureChannelData : SecureChannelData
{
    private const int expectedInitializeUpdateResponseLength = 28;

    public Scp02SecureChannelData(SecureChannelProtocolDetails scp, byte keyVersion, byte keyIdentifier, Span<byte> hostChallenge) : base(scp, keyVersion, keyIdentifier, hostChallenge)
    {
    }   

    public override SecureChannelData ParseInitializeUpdateResponse(Span<byte> udr)
    {
        if (udr.Length != expectedInitializeUpdateResponseLength)
        {
            throw new GlobalPlatformException($"Something went wrong during the Initialize Update: Invalid UDR length (expected {expectedInitializeUpdateResponseLength} bytes, got {udr.Length})");
        }

        KeyDiversificationData = udr[..10].ToArray();
        KeyInformation = udr[10..12].ToArray();
        CardChallenge = udr[12..20].ToArray();
        CardCryptogram = udr[20..28].ToArray();

        return this;
    }
}
