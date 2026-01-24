using WSCT.Core;
using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security;
using WSCT.ISO7816;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform.JavaCard;

namespace WSCT.GlobalPlatform
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GlobalPlatformCard"/> class.
    /// </summary>
    /// <param name="cardChannel">Card channel to use for communication with the card.</param>
    public class GlobalPlatformCard(ICardChannel cardChannel)
    {
        readonly ICardChannel _cardChannel = cardChannel;

        private CardData? _cardData;
        private SecureChannelData? _scpData;
        private ISecureChannelProtocol? _scp;

        public CardData CardData => _cardData!;
        public SecureChannelData SecureChannelData => _scpData!;

        public bool AuthenticateCard()
        {
            GlobalPlatformException.ThrowIfNull(_scp);
            GlobalPlatformException.ThrowIfNull(_scpData);

            return _scp.AuthenticateCard();
        }

        /// <summary>
        /// Creates the session keys between the reader and the card.
        /// </summary>
        /// <param name="keys">The initial keys to use for creating the session keys.</param>
        /// <returns>The created session keys.</returns>
        public SessionKeys CreateSessionKeys(Keys keys)
        {
            GlobalPlatformException.ThrowIfNull(_scp);
            GlobalPlatformException.ThrowIfNull(_scpData);

            _scpData.Keys = keys;

            _scpData.SessionKeys = _scp.GenerateSessionKeys();

            return _scpData.SessionKeys;
        }

        /// <summary>
        /// Sends any command to the card using the established secure channel and returns the resulting CRP.
        /// </summary>
        /// <param name="cApdu">The command APDU to send to the card.</param>
        /// <returns>The resulting command response pair.</returns>
        public CommandResponsePair ProcessCommand(CommandAPDU cApdu)
        {
            GlobalPlatformException.ThrowIfNull(_scp);
            GlobalPlatformException.ThrowIfNull(_scpData);

            var command = _scp.Wrap(cApdu);

            var crp = command
                .Transmit(_cardChannel);

            return crp;
        }

        #region >> ProcessDelete

        /// <summary>
        /// Sends a DELETE command to the card to delete an application.<br/>
        /// GlobalPlatform: DELETE [card content] with simplified options.
        /// </summary>
        /// <param name="aid">Executable Load File or Application AID to delete.</param>
        /// <param name="deleteRelated">Whether to delete related contents.</param>
        /// <returns>The resulting CRP.</returns>
        public CommandResponsePair ProcessDelete(Span<byte> aid, bool deleteRelated = true)
            => ProcessCommand(new DeleteCommand(aid, deleteRelated));

        /// <summary>
        /// Sends a DELETE command to the card to delete a card content.<br/>
        /// GlobalPlatform: DELETE [card content] with full options.
        /// </summary>
        /// <param name="aid">The AID of the application to delete.</param>
        /// <param name="tokenIssuerId">The token issuer ID.</param>
        /// <param name="cardImageNumber">The card image number.</param>
        /// <param name="applicationProviderIdentifier">The application provider identifier.</param>
        /// <param name="tokenIdentifierNumber">The token identifier number.</param>
        /// <param name="deleteToken">The delete token.</param>
        /// <param name="deleteRelated">Whether to delete related applications.</param>
        /// <returns>The resulting CRP.</returns>
        public CommandResponsePair ProcessDelete(Span<byte> aid, Span<byte> tokenIssuerId, Span<byte> cardImageNumber, Span<byte> applicationProviderIdentifier, Span<byte> tokenIdentifierNumber, Span<byte> deleteToken, bool deleteRelated)
            => ProcessCommand(new DeleteCommand(aid, tokenIssuerId, cardImageNumber, applicationProviderIdentifier, tokenIdentifierNumber, deleteToken, deleteRelated));

        #endregion

        public CommandResponsePair ProcessExternalAuthenticate(SecurityLevel securityLevel)
        {
            GlobalPlatformException.ThrowIfNull(_scp);
            GlobalPlatformException.ThrowIfNull(_scpData);
            GlobalPlatformException.ThrowIfNull(_scpData.HostCryptogram, "Host cryptogram not initialized: Call AuthenticateCard(...) first");

            _scpData.SecurityLevel = securityLevel;

            var externalAuthenticate = new ExternalAuthenticateCommand(securityLevel, _scpData.HostCryptogram);

            externalAuthenticate = _scp.Wrap(externalAuthenticate);

            var crp = externalAuthenticate
                .Transmit(_cardChannel);

            return crp;
        }

        public CommandResponsePair ProcessGetCardData()
        {
            var crp = new GetCardDataCommand()
                .Transmit(_cardChannel);

            if (crp.RApdu.StatusWord == 0x9000)
            {
                _cardData = CardData.Create(crp.RApdu.Udr);
            }

            return crp;
        }

        #region >> ProcessInitializeUpdate

        public CommandResponsePair ProcessInitializeUpdate(SecureChannelProtocolDetails scp, byte keySetVersion, byte keyIdentifier)
        {
            var hostChallenge = new byte[8];
            Random.Shared.NextBytes(hostChallenge);

            return ProcessInitializeUpdate(scp, keySetVersion, keyIdentifier, hostChallenge);
        }

        public CommandResponsePair ProcessInitializeUpdate(SecureChannelProtocolDetails scp, byte keySetVersion, byte keyIdentifier, byte[] hostChallenge)
        {
            _scpData = new SecureChannelData(scp, keySetVersion, keyIdentifier, hostChallenge);

            _scp = scp.Identifier switch // TODO Move this in a better place
            {
                1 => new Security.Scp01.Scp01(_scpData),
                2 => new Security.Scp02.Scp02(_scpData),
                _ => throw new GlobalPlatformException($"Unsupported SCP: {scp.Identifier:X2}"),
            };

            var crp = new InitializeUpdateCommand(keySetVersion, keyIdentifier, hostChallenge)
                .Transmit(_cardChannel);

            if (crp.RApdu.StatusWord == 0x9000)
            {
                _scpData.ParseInitializeUpdateResponse(crp.RApdu.Udr);
            }

            return crp;
        }

        #endregion

        #region >> ProcessInstall*

        public CommandResponsePair ProcessInstallForInstall(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            => ProcessCommand(new InstallForInstallCommand(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken));

        public CommandResponsePair ProcessInstallForInstallAndMakeSelectable(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            => ProcessCommand(new InstallForInstallAndMakeSelectableCommand(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken));

        public CommandResponsePair ProcessInstallForLoad(byte[] loadFileAid, byte[] securityDomainAid, byte[] loadFileDataBlockHash, byte[] loadParameters, byte[] loadToken)
            => ProcessCommand(new InstallForLoadCommand(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken));

        public CommandResponsePair ProcessInstallForMakeSelectable(Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            => ProcessCommand(new InstallForMakeSelectableCommand(applicationAid, privileges, installParameters, installToken));

        #endregion

        #region >> ProcessLoad

        public CommandResponsePair ProcessLoad(Stream rawCapFileStream)
        {
            var capFile = new CapFile(rawCapFileStream);

            var loadData = capFile.GetLoadData();
            byte blockNumber = 0x00;
            var loadDataSentLength = 0;

            CommandResponsePair lastCrp = new();
            foreach (var chunk in loadData.Chunk(0xE0))
            {
                loadDataSentLength += chunk.Length;

                lastCrp = ProcessCommand(new LoadCommand(loadDataSentLength == loadData.Length, blockNumber, chunk));

                blockNumber++;

                if (lastCrp.RApdu.StatusWord != 0x9000)
                {
                    break;
                }
            }

            return lastCrp;
        }

        public CommandResponsePair ProcessLoad(string pathToCapFile)
            => ProcessLoad(File.OpenRead(pathToCapFile));

        #endregion

        #region >> ProcessSelectCardManager

        public CommandResponsePair ProcessSelectCardManager()
        {
            var selectManager = new SelectCardManager()
                .Transmit(_cardChannel);

            return selectManager;
        }

        public CommandResponsePair ProcessSelectCardManager(byte[] aid)
        {
            var selectManager = new SelectCardManager(aid)
                .Transmit(_cardChannel);

            return selectManager;
        }

        #endregion
    }
}
