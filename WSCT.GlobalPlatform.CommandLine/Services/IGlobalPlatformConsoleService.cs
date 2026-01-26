namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IGlobalPlatformConsoleService
{
    bool AuthenticateCard(string readerName);

    string InitializeAndSelectReader();
}
