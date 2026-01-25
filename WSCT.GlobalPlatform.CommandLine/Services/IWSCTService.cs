using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IWSCTService
{
    ErrorCode Connect(string readerName);

    ErrorCode Disconnect();

    ErrorCode Establish();

    string[] GetReaders();

    ErrorCode Release();

    ErrorCode SelectCardManager();

    ErrorCode GetCardData();

    ErrorCode Authenticate(byte[] sEnc, byte[] sMac, byte[] dek, byte keyVersion, byte keyIdentifier);

    Status[] GetApplications();
}
