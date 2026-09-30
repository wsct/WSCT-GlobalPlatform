using WSCT.GlobalPlatform;
using WSCT.GlobalPlatform.Security;

namespace WSCT.Layers.GlobalPlatform;

public class GlobalPlatformController
{
    public static AID SecurityDomainAid { get; set; } = new([]);

    public static Keys CardKeys { get; set; } = new(
        new byte[16],
        new byte[16],
        new byte[16]
    );
}
