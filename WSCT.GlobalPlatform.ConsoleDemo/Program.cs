// See https://aka.ms/new-console-template for more information
using WSCT.Core;
using WSCT.GlobalPlatform.Security;
using WSCT.Helpers;
using WSCT.ISO7816;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

using WSCT.GlobalPlatform.ConsoleDemo;
using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform.ConsoleDemo.Helpers;
using WSCT.Linq;

var SEnc = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
var SMac = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
var Dek = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();

var keyVersion = (byte)0x00;
var KeyIdentifier = (byte)0x00;
var hostChallenge = "01 02 03 04 05 06 07 08".FromHexa();

#region >> CardContext

var cardContext = new CardContextObservable(new CardContext());
var logger = new Observer();
logger.Observe(cardContext);

cardContext
    .Establish()
    .ThrowIfNotSuccess();

cardContext
    .ListReaderGroups()
    .ThrowIfNotSuccess();

cardContext
    .ListReaders(cardContext.Groups[0])
    .ThrowIfNotSuccess();

#endregion

var cardChannel = new CardChannel(cardContext, cardContext.Readers[0])
    .ToT0Friendly()
    .ToObservable();
logger.Observe(cardChannel);

try
{
    #region >> CardChannel

    cardChannel
        .Connect(ShareMode.Exclusive, Protocol.Any)
        .ThrowIfNotSuccess();

    #endregion

    var gpCard = new GlobalPlatformCard(cardChannel);

    gpCard
        .ProcessSelectCardManager("A0 00 00 01 51 00".FromHexa())
        .ThrowIfNotSuccess()
        .ThrowIfSWNot9000();

    gpCard
        .ProcessGetCardData()
        .ThrowIfNotSuccess()
        .ThrowIfSWNot9000();

    gpCard.CardData.Dump();

    var scpUsed = gpCard.CardData.SupportedScps.First(scp => scp.Identifier == 0x02);

    gpCard
        .ProcessInitializeUpdate(scpUsed, keyVersion, KeyIdentifier, hostChallenge)
        .ThrowIfNotSuccess()
        .ThrowIfSWNot9000();

    gpCard.SecureChannelData.Dump();

    gpCard
        .CreateSessionKeys(new Keys(SEnc, SMac, Dek));

    gpCard.SecureChannelData.Dump();

    gpCard
        .AuthenticateCard();

    gpCard
        .ProcessExternalAuthenticate(SecurityLevel.CMac | SecurityLevel.CDecryption)
        .ThrowIfNotSuccess()
        .ThrowIfSWNot9000();

    gpCard.SecureChannelData.Dump();

    // GET STATUS command
    gpCard
        .ProcessCommand(new CommandAPDU(0x80, 0xF2, 0x40, 0x00, 0x02, new byte[] { 0x4F, 0x00 }, 0x00));

    // GET DATA Key Information Template
    gpCard
        .ProcessCommand(new GetDataCommand(0xE0));

    // GET DATA Sequence Counter of the default Key Version Number
    gpCard
        .ProcessCommand(new GetDataCommand(0xC1));
}
finally
{
    cardChannel?
        .Disconnect(Disposition.UnpowerCard);

    cardContext
        .Release();
}