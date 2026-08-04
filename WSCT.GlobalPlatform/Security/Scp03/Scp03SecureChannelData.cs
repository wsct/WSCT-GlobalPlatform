using System;
using WSCT.Helpers;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace WSCT.GlobalPlatform.Security;

/// <summary>
/// The data used to manage a secure channel.
/// </summary>
public class Scp03SecureChannelData : SecureChannelData
{
    private const int keyDiversificationDataLength = 10;
    private const int keyInformationLength = 3;
    private readonly int sMode_ChallengeLength = 8; // Ou 16
    private readonly int pseudorandom_counterLength = 3;
    private readonly int initializeUpdateResponseLength;

    public byte[]? PseudoRandomCounter { get; protected set; }
    public byte[] context()
    {
        return [.. HostChallenge, .. CardChallenge!];
    }
    public Scp03SecureChannelData(SecureChannelProtocolDetails scp, byte keyVersion, byte keyIdentifier, Span<byte> hostChallenge) : base(scp, keyVersion, keyIdentifier, hostChallenge)
    {
        initializeUpdateResponseLength = 
            keyDiversificationDataLength + keyInformationLength 
            + 2 * sMode_ChallengeLength + pseudorandom_counterLength;
    }

    private static byte[] Take(ReadOnlySpan<byte> data, ref int offset, int length = -1)
    {
        if (length == -1) length = data.Length - offset;
        byte[] result = data[offset..(offset + length)].ToArray();
        offset += length;
        return result;
    }

    public override SecureChannelData ParseInitializeUpdateResponse(Span<byte> udr)
    {
        if (udr.Length != initializeUpdateResponseLength)
        {
            throw new GlobalPlatformException($"Something went wrong during the Initialize Update: Invalid UDR length (expected {initializeUpdateResponseLength} bytes, got {udr.Length})");
        }
        int offset = 0;

        KeyDiversificationData = Take(udr, ref offset, 10);
        KeyInformation = Take(udr, ref offset, 3);
        CardChallenge = Take(udr, ref offset, sMode_ChallengeLength);
        CardCryptogram = Take(udr, ref offset, sMode_ChallengeLength);
        PseudoRandomCounter = Take(udr, ref offset);
        return this;
    }
}
