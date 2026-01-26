using WSCT.Core;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public interface IWSCTService
{
    ICardChannelObservable? CardChannel { get; }

    ErrorCode Connect(string readerName);

    ErrorCode Disconnect();

    ErrorCode Establish();

    string[] GetReaders();

    ErrorCode Release();
}
