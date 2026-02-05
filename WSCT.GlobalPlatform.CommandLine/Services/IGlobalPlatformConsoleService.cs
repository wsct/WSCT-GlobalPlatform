namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IGlobalPlatformConsoleService
{
    bool AuthenticateCard(string readerName, byte[] sEnc, byte[] sMac, byte[] dek, byte keyVersion, byte keyIdentifier);

    string InitializeAndSelectReader();
}
