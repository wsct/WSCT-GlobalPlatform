using Microsoft.Extensions.Logging;
using WSCT.Core;
using WSCT.Linq;
using WSCT.Stack;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Stack;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public class WSCTStackService(ILogger<WSCTService> logger) : IWSCTService
{
    private readonly Observer _observer = new(logger);
    private ICardContextObservable? _cardContext;
    private ICardChannelObservable? _cardChannel;

    public ICardChannelObservable? CardChannel => _cardChannel;

    public ErrorCode Connect(string readerName)
    {
        if (_cardContext is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var cardChannelCore = new CardChannelStack([new CardChannelLayer()]);

        _cardChannel = cardChannelCore
            .ToT0Friendly()
            .ToObservable();

        _observer.Observe(_cardChannel);

        var connectResult = _cardChannel
            .Connect(ShareMode.Exclusive, Protocol.Any);

        if (connectResult != ErrorCode.Success)
        {
            _cardChannel = null;
            return connectResult;
        }

        return connectResult;
    }

    public ErrorCode Disconnect()
    {
        if (_cardChannel is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var disconnectResult = _cardChannel
            .Disconnect(Disposition.UnpowerCard);

        if (disconnectResult != ErrorCode.Success)
        {
            _cardChannel = null;
        }

        return disconnectResult;
    }

    public ErrorCode Establish()
    {
        _cardContext = new CardContextStack([new CardContextLayer()])
            .ToObservable();

        _observer.Observe(_cardContext);

        var establishResult = _cardContext
            .Establish();

        if (establishResult != ErrorCode.Success)
        {
            _cardContext = null;
        }

        return establishResult;
    }

    public string[] GetReaders()
    {
        if (_cardContext is null)
        {
            return [];
        }

        var listReaderGroupsResult = _cardContext
            .ListReaderGroups();

        if (listReaderGroupsResult != ErrorCode.Success)
        {
            return [];
        }

        var listReadersResult = _cardContext
            .ListReaders(_cardContext.Groups[0]);

        if (listReadersResult != ErrorCode.Success)
        {
            return [];
        }

        return _cardContext.Readers;
    }

    public ErrorCode Release()
    {
        if (_cardContext is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var disconnectResult = _cardContext.Release();

        _cardContext = null;

        return disconnectResult;
    }
}
