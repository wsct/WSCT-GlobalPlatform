using WSCT.GlobalPlatform;
using WSCT.GlobalPlatform.Security;
using WSCT.Stack;

namespace WSCT.Layers.GlobalPlatform;

public class GlobalPlatformController
{
    public static bool IsLayerActive { get; set; } = true;

    public static AID SecurityDomainAid { get; set; } = new([]);

    public static byte KeyIdentifier { get; set; } = 0x00;

    public static byte KeyVersion { get; set; } = 0x01;

    public static Keys CardKeys { get; set; } = new(
        new byte[16],
        new byte[16],
        new byte[16]
    );

    public static GlobalPlatformCard? GpCard { get; set; }

    public static ICardChannelLayer? NextChannelLayer { get; set; }
}
