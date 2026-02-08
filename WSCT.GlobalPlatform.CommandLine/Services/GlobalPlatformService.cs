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

    /// <inheritdoc/>
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

    /// <inheritdoc/>
    public bool DeleteApplication(byte[] aid)
    {
        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var deleteApplicationResult = _gpCard
            .ProcessDelete(aid);

        return deleteApplicationResult.ErrorCode == ErrorCode.Success && deleteApplicationResult.RApdu.StatusWord == 0x9000;
    }

    /// <inheritdoc/>
    public Status[] GetApplications()
    {
        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var crp = _gpCard
            .ProcessGetExecutableLoadFilesAndModulesStatusCommand([]);

        if (crp.ErrorCode != ErrorCode.Success || crp.RApdu.StatusWord != 0x9000)
        {
            return [];
        }

        return Status.Parse(crp.RApdu.Udr);
    }

    /// <inheritdoc/>
    public bool GetCardData()
    {
        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var getCardDataResult = _gpCard
            .ProcessGetCardData();

        return getCardDataResult.ErrorCode == ErrorCode.Success && getCardDataResult.RApdu.StatusWord == 0x9000;
    }

    /// <inheritdoc/>
    public bool InstallForLoad(byte[] loadFileAid, byte[] securityDomainAid, byte[] loadFileDataBlockHash, byte[] loadParameters, byte[] loadToken)
    {
        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var installForLoadResult = _gpCard
            .ProcessInstallForLoad(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken);

        return installForLoadResult.ErrorCode == ErrorCode.Success && installForLoadResult.RApdu.StatusWord == 0x9000;
    }

    /// <inheritdoc/>
    public bool Load(string pathToCapFile)
    {
        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var loadResult = _gpCard
            .ProcessLoad(pathToCapFile);

        return loadResult.ErrorCode == ErrorCode.Success && loadResult.RApdu.StatusWord == 0x9000;
    }

    /// <inheritdoc/>
    public bool InstallForInstallAndMakeSelectable(byte[] loadFileAid, byte[] moduleAid, byte[] applicationAid, byte[] privileges, byte[] installParameters, byte[] installToken)
    {
        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var installForInstallAndMakeSelectableResult = _gpCard
            .ProcessInstallForInstallAndMakeSelectable(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken);

        return installForInstallAndMakeSelectableResult.ErrorCode == ErrorCode.Success && installForInstallAndMakeSelectableResult.RApdu.StatusWord == 0x9000;
    }

    /// <inheritdoc/>
    public bool SelectCardManager()
    {
        AttachToChannel();

        GlobalPlatformServiceException.ThrowIfNull(_gpCard);

        var selectCardManagerResult = _gpCard
            .ProcessSelectCardManager();

        return selectCardManagerResult.ErrorCode == ErrorCode.Success && selectCardManagerResult.RApdu.StatusWord == 0x9000;
    }

    private void AttachToChannel()
    {
        if (wsct.CardChannel is null)
        {
            logger.LogInformation("Card channel is not initialized");

            throw new InvalidOperationException("Card channel is not initialized");
        }

        _gpCard = new GlobalPlatformCard(wsct.CardChannel);
    }
}
