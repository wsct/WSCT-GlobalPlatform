namespace WSCT.GlobalPlatform.Security.Scp02;

public class Scp03Specifics(byte subIdentifier)
{
    public byte[] LastCMac { get; set; } = [.. Constants.ICV];

    public Scp03SubIdentifier SubIdentifier { get; set; } = new Scp03SubIdentifier(subIdentifier);
}
