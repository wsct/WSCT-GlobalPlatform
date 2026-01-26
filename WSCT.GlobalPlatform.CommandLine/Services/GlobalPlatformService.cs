using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public class GlobalPlatformService(ILogger<GlobalPlatformService> logger, IWSCTService wsct) : IGlobalPlatformService
{
    private GlobalPlatformCard? _gpCard;

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

    public ErrorCode DeleteApplication(byte[] aid)
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var deleteApplicationResult = _gpCard
            .ProcessDelete(aid);

        return deleteApplicationResult.ErrorCode;
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

    public ErrorCode InstallForLoad(byte[] loadFileAid, byte[] securityDomainAid, byte[] loadFileDataBlockHash, byte[] loadParameters, byte[] loadToken)
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var installForLoadResult = _gpCard
            .ProcessInstallForLoad(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken);

        return installForLoadResult.ErrorCode;
    }

    public ErrorCode Load(string pathToCapFile)
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var loadResult = _gpCard
            .ProcessLoad(pathToCapFile);

        return loadResult.ErrorCode;
    }

    public ErrorCode InstallForInstallAndMakeSelectable(byte[] loadFileAid, byte[] moduleAid, byte[] applicationAid, byte[] privileges, byte[] installParameters, byte[] installToken)
    {
        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var installForInstallAndMakeSelectableResult = _gpCard
            .ProcessInstallForInstallAndMakeSelectable(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken);

        return installForInstallAndMakeSelectableResult.ErrorCode;
    }

    public ErrorCode SelectCardManager()
    {
        AttachToChannel();

        if (_gpCard is null)
        {
            return ErrorCode.InvalidHandle;
        }

        var selectCardManagerResult = _gpCard
            .ProcessSelectCardManager();

        return selectCardManagerResult.ErrorCode;
    }

    private void AttachToChannel()
    {
        if (_gpCard is not null)
        {
            return;
        }

        if (wsct.CardChannel is null)
        {
            logger.LogInformation("Card channel is not initialized");

            throw new InvalidOperationException("Card channel is not initialized");
        }

        _gpCard = new GlobalPlatformCard(wsct.CardChannel);
    }
}
