using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.VisualBasic;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using WSCT.Core;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security;
using static System.Net.Mime.MediaTypeNames;
namespace WSCT.GlobalPlatform.UnitTests;

public class Tests
{
    [SetUp]
    public void Setup()
    {
    }
    //[APDU-C] > 00A40400 08[A000000151000000]
    //[APDU-R] < [6F618408A000000151000000A555734B06072A864886FC6B01600B06092A864886FC6B020202630906072A864886FC6B03640B06092A864886FC6B040370650D060B2A864886FC6B0507020100660C060A2B060104012A026E01039F6E01019F6501FE] SW:9000

    //[APDU-C] > 80500000 08[949E83628290BB9C]
    //[APDU - R] < [009D0000000000000000010370A34617087C6DCA1C1294CCE4EAA05156000001] SW:9000

    //[APDU-C] > 84820100 10[15A009373E3198DECDF94BBE952A2694]
    //[APDU - R] < [] SW:9000

    [Test]
    public void Sessions()
    {
        var scpProtocolDetails = new SecureChannelProtocolDetails(0x03, 0x70);
        byte keySetVersion = 0x00;
        byte keyIdentifier = 0x00;
        Span<byte> hostChallenge = Convert.FromHexString("949E83628290BB9C");
        var scpData = new Scp03SecureChannelData(scpProtocolDetails, keySetVersion, keyIdentifier, hostChallenge);
        // AES-128bits
        var L = 0080;
        //var context = hostChall + card Chall
        var Enc = Convert.FromHexString("00000000000000000000000000000000");
        var Mac = Convert.FromHexString("00000000000000000000000000000000");
        var Dek = Convert.FromHexString("00000000000000000000000000000000");
        scpData.Keys = new Keys(Enc, Mac, Dek);
        var scp03 = new Security.Scp03.Scp03(scpData);
        ;
        var keyDiversificationData = Convert.FromHexString("009D0000000000000000");
        var KeyInformation = Convert.FromHexString("010370");
        var cardChallenge = Convert.FromHexString("A34617087C6DCA1C");
        var cardCryptogram = Convert.FromHexString("1294CCE4EAA05156");
        var sequenceCounter = Convert.FromHexString("000001");

        // Gives Card chall.
        scpData.ParseInitializeUpdateResponse(
            Convert.FromHexString("009D0000000000000000010370A34617087C6DCA1C1294CCE4EAA05156000001")
        );

        scpData.SessionKeys = scp03.GenerateSessionKeys();

    }


    [Test]
    public void Cryptograms()
    {
        var scpProtocolDetails = new SecureChannelProtocolDetails(0x03, 0x70);
        byte keySetVersion = 0x00;
        byte keyIdentifier = 0x00;
        Span<byte> hostChallenge = Convert.FromHexString("949E83628290BB9C");
        var scpData = new Scp03SecureChannelData(scpProtocolDetails, keySetVersion, keyIdentifier, hostChallenge);
        var Enc = Convert.FromHexString("00000000000000000000000000000000");
        var Mac = Convert.FromHexString("00000000000000000000000000000000");
        var Dek = Convert.FromHexString("00000000000000000000000000000000");
        scpData.Keys = new Keys(Enc, Mac, Dek);
        var scp03 = new Security.Scp03.Scp03(scpData);
        ;
        var keyDiversificationData = Convert.FromHexString("009D0000000000000000");
        var KeyInformation = Convert.FromHexString("010370");
        var cardChallenge = Convert.FromHexString("A34617087C6DCA1C");
        var cardCryptogram = Convert.FromHexString("1294CCE4EAA05156");
        var sequenceCounter = Convert.FromHexString("000001");
        scpData.ParseInitializeUpdateResponse(
            Convert.FromHexString("009D0000000000000000010370A34617087C6DCA1C1294CCE4EAA05156000001")
        );

        scpData.SessionKeys = scp03.GenerateSessionKeys();
        var Authenticated = scp03.AuthenticateCard();
        Assert.That(Authenticated, Is.True);


        scpData.SecurityLevel = (SecurityLevel)0x01; // EXT AUTH p1

    }

    [Test]
    public void FullSequence()
    {
        var scpProtocolDetails = new SecureChannelProtocolDetails(0x03,0x70);
        byte keySetVersion = 0x00;
        byte keyIdentifier = 0x00;
        Span<byte> hostChallenge = Convert.FromHexString("949E83628290BB9C");
        var scpData = new Scp03SecureChannelData(scpProtocolDetails, keySetVersion, keyIdentifier, hostChallenge);
        var Enc = Convert.FromHexString("00000000000000000000000000000000");
        var Mac = Convert.FromHexString("00000000000000000000000000000000");
        var Dek= Convert.FromHexString("00000000000000000000000000000000");
        scpData.Keys = new Keys(Enc, Mac, Dek);
        var scp03 = new Security.Scp03.Scp03(scpData);
        ;
        var keyDiversificationData = Convert.FromHexString("009D0000000000000000");
        var KeyInformation = Convert.FromHexString("010370");
        var cardChallenge = Convert.FromHexString("A34617087C6DCA1C");
        var cardCryptogram = Convert.FromHexString("1294CCE4EAA05156");
        var sequenceCounter = Convert.FromHexString("000001");
        scpData.ParseInitializeUpdateResponse(
            Convert.FromHexString("009D0000000000000000010370A34617087C6DCA1C1294CCE4EAA05156000001")
        );

        scpData.SessionKeys = scp03.GenerateSessionKeys();
        var Authenticated = scp03.AuthenticateCard();

        scpData.SecurityLevel = (SecurityLevel) 0x01; // EXT AUTH p1

        var externalAuthenticate = new ExternalAuthenticateCommand(scpData.SecurityLevel, scpData.HostCryptogram);

        var externalAuthenticateTransmitter = scp03.Wrap(externalAuthenticate);

        var extAut = externalAuthenticateTransmitter.ToString();
        Console.WriteLine(extAut);


    }
}
