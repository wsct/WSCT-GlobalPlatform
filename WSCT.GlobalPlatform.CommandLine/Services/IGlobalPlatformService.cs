using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IGlobalPlatformService
{
    ErrorCode Authenticate(byte[] sEnc, byte[] sMac, byte[] dek, byte keyVersion, byte keyIdentifier);

    bool DeleteApplication(byte[] aid);

    /// <summary>
    /// GlobalPlatform GET DATA Tag '66'.
    /// </summary>
    bool GetCardData();

    /// <summary>
    /// GET APPLICATIONS.
    /// </summary>
    Status[] GetApplications();

    /// <summary>
    /// GlobalPlatform INSTALL [for load].
    /// </summary>
    bool InstallForLoad(byte[] loadFileAid, byte[] securityDomainAid, byte[] loadFileDataBlockHash, byte[] loadParameters, byte[] loadToken);

    /// <summary>
    /// GlobalPlatform LOAD.
    /// </summary>
    bool Load(string pathToCapFile);

    /// <summary>
    /// GlobalPlatform INSTALL [for install and make selectable].
    /// </summary>
    bool InstallForInstallAndMakeSelectable(byte[] loadFileAid, byte[] moduleAid, byte[] applicationAid, byte[] privileges, byte[] installParameters, byte[] installToken);

    /// <summary>
    /// SELECT the Card Manager.
    /// </summary>
    bool SelectCardManager();
}


