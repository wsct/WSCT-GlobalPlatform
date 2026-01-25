using System;
using Spectre.Console;
using WSCT.Core;
using WSCT.Core.Fluent.Helpers;
using WSCT.Linq;
using WSCT.GlobalPlatform;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;
using Microsoft.Extensions.Logging;
using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security;
using System.Security.Cryptography;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public class WSCTService(ILogger<WSCTService> logger) : IWSCTService
{
    private readonly Observer _observer = new(logger);
    private ICardContextObservable? _cardContext;
    private ICardChannelObservable? _cardChannel;
    private GlobalPlatformCard? _gpCard;


    public ErrorCode Connect(string readerName)
    {
        if (_cardContext is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var cardChannelCore = new CardChannel(_cardContext, readerName);

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

        _gpCard = new GlobalPlatformCard(_cardChannel);

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
            _gpCard = null;
        }

        return disconnectResult;
    }

    public ErrorCode Establish()
    {
        _cardContext = new CardContext()
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

    public ErrorCode SelectCardManager()
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var selectCardManagerResult = _gpCard
            .ProcessSelectCardManager();

        return selectCardManagerResult.ErrorCode;
    }

    public ErrorCode GetCardData()
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var getCardDataResult = _gpCard
            .ProcessGetCardData();

        return getCardDataResult.ErrorCode;
    }

    public ErrorCode Authenticate(byte[] sEnc, byte[] sMac, byte[] dek, byte keyVersion, byte keyIdentifier)
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        _gpCard
            .ProcessGetCardData()
            .ThrowIfNotSuccess()
            .ThrowIfSWNot9000();

        var scpUsed = _gpCard.CardData.SupportedScps.First();

        var hostChallenge = RandomNumberGenerator.GetBytes(8);

        // INITIALIZE UPDATE
        _gpCard
            .ProcessInitializeUpdate(scpUsed, keyVersion, keyIdentifier, hostChallenge)
            .ThrowIfNotSuccess()
            .ThrowIfSWNot9000();

        _gpCard
            .CreateSessionKeys(new Keys(sEnc, sMac, dek));

        _gpCard
            .AuthenticateCard();

        _gpCard
            .ProcessExternalAuthenticate(SecurityLevel.CMac | SecurityLevel.CDecryption)
            .ThrowIfNotSuccess()
            .ThrowIfSWNot9000();

        return ErrorCode.Success;
    }

    public Status[] GetApplications()
    {
        if (_gpCard is null)
        {
            return [];
        }

        var crp = _gpCard
            .ProcessGetExecutableLoadFilesAndModulesStatusCommand([]);

        if (crp.ErrorCode != ErrorCode.Success || crp.RApdu.StatusWord != 0x9000)
        {
            return [];
        }

        return Status.Parse(crp.RApdu.Udr);
    }
}
