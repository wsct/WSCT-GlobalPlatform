namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IGlobalPlatformConsoleService
{
    bool Delete(byte[] aid, AuthenticationParameters authParams);

    bool Install(byte[] aid, string pathToCapFile, byte[] executableAid, byte[] privileges, byte[] installParameters, AuthenticationParameters authParams);

    bool ListApplications(AuthenticationParameters authParams);

    bool ListReaders();

    bool SelectCardManager();
}
