using WSCT.Core;
using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security.Scp02;
using WSCT.GlobalPlatform.Security;
using WSCT.ISO7816;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform.JavaCard;

namespace WSCT.GlobalPlatform
{
    public class GlobalPlatformCard
    {
        readonly ICardChannel _cardChannel;

        private CardData _cardData;
        private SecureChannelData _scpData;
        private ISecureChannelProtocol _scp;

        public CardData CardData => _cardData;
        public SecureChannelData SecureChannelData => _scpData;

        #region >> Constructors

        public GlobalPlatformCard(ICardChannel cardChannel)
        {
            _cardChannel = cardChannel;
        }

        #endregion

        public bool AuthenticateCard()
        {
            return _scp.AuthenticateCard(_scpData);
        }

        public SessionKeys CreateSessionKeys(Keys keys)
        {
            _scpData.Keys = keys;

            _scpData.SessionKeys = _scp.GenerateSessionKeys(_scpData);

            return _scpData.SessionKeys;
        }

        public CommandResponsePair ProcessExternalAuthenticate(SecurityLevel securityLevel)
        {
            _scpData.SecurityLevel = securityLevel;

            var externalAuthenticate = new ExternalAuthenticateCommand(securityLevel, _scpData.HostCryptogram);

            externalAuthenticate = _scp.Wrap(externalAuthenticate, _scpData);

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

        public CommandResponsePair ProcessInitializeUpdate(SecureChannelProtocolDetails scp, byte keySetVersion, byte keyIdentifier)
        {
            var hostChallenge = new byte[8];
            Random.Shared.NextBytes(hostChallenge);

            return ProcessInitializeUpdate(scp, keySetVersion, keyIdentifier, hostChallenge);
        }

        public CommandResponsePair ProcessInitializeUpdate(SecureChannelProtocolDetails scp, byte keySetVersion, byte keyIdentifier, byte[] hostChallenge)
        {
            _scpData = new SecureChannelData(scp, keySetVersion, keyIdentifier, hostChallenge);
            _scp = new Scp02(_scpData); // TODO Move this in a better place

            var crp = new InitializeUpdateCommand(keySetVersion, keyIdentifier, hostChallenge)
                .Transmit(_cardChannel);

            if (crp.RApdu.StatusWord == 0x9000)
            {
                _scpData.ParseInitializeUpdateResponse(crp.RApdu.Udr);
            }

            return crp;
        }

        public CommandResponsePair ProcessCommand(CommandAPDU cApdu)
        {
            var command = _scp.Wrap(cApdu, _scpData);

            var crp = command
                .Transmit(_cardChannel);

            return crp;
        }

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

        public CommandResponsePair ProcessInstallForInstall(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            => ProcessCommand(new InstallForInstallCommand(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken));

        public CommandResponsePair ProcessInstallForInstallAndMakeSelectable(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            => ProcessCommand(new InstallForInstallAndMakeSelectableCommand(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken));

        public CommandResponsePair ProcessInstallForLoad(byte[] loadFileAid, byte[] securityDomainAid, byte[] loadFileDataBlockHash, byte[] loadParameters, byte[] loadToken)
            => ProcessCommand(new InstallForLoadCommand(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken));

        public CommandResponsePair ProcessInstallForMakeSelectable(Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            => ProcessCommand(new InstallForMakeSelectableCommand(applicationAid, privileges, installParameters, installToken));

        public CommandResponsePair ProcessLoad(string pathToCapFile)
            => ProcessLoad(File.OpenRead(pathToCapFile));

        public CommandResponsePair ProcessLoad(Stream rawCapFileStream)
        {
            var capFile = new CapFile(rawCapFileStream);

            var loadData = capFile.GetLoadData();
            byte blockNumber = 0x00;
            var loadDataSentLength = 0;

            CommandResponsePair lastCrp = null;
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

        #endregion
    }
}
