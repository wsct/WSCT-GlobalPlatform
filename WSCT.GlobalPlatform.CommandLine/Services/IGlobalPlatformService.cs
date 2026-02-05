using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IGlobalPlatformService
{
    ErrorCode Authenticate(byte[] sEnc, byte[] sMac, byte[] dek, byte keyVersion, byte keyIdentifier);

    ErrorCode DeleteApplication(byte[] aid);

    ErrorCode GetCardData();

    Status[] GetApplications();

    bool InstallForLoad(byte[] loadFileAid, byte[] securityDomainAid, byte[] loadFileDataBlockHash, byte[] loadParameters, byte[] loadToken);

    ErrorCode Load(string pathToCapFile);

    ErrorCode InstallForInstallAndMakeSelectable(byte[] loadFileAid, byte[] moduleAid, byte[] applicationAid, byte[] privileges, byte[] installParameters, byte[] installToken);

    ErrorCode SelectCardManager();
}


