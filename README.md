# WSCT GlobalPlatform

Public repository for WSCT GlobalPlatform project [![NuGet](https://img.shields.io/nuget/v/WSCT.GlobalPlatform.svg)](https://www.nuget.org/packages/WSCT.GlobalPlatform/).

## Features

The current status of this project is *work in progress*.

- GP 2.2 commands:
  - [x] `SELECT CARD MANAGER`
  - [x] `GET CARD DATA`
  - [x] `GET DATA`
  - [x] `GET STATUS`
  - [x] `INSTALL [for load]`
  - [x] `INSTALL [for install]`
  - [x] `INSTALL [for make selectable]`
  - [x] `INSTALL [for install and make selectable]`
  - [x] `LOAD`
  - [x] `DELETE`
- SCP01 support:
  - [x] Mutual authentication (`INITIALIZE UPDATE`, `EXTERNAL AUTHENTICATE`)
  - [x] Automatic wrapping / unwrapping of APDU
  - [x] CMAC
  - [x] CDEC
- SCP02 support:
  - [x] 3-keys
  - [ ] 1-key
  - [x] Mutual authentication (`INITIALIZE UPDATE`, `EXTERNAL AUTHENTICATE`)
  - [x] Automatic wrapping / unwrapping of APDU
  - [x] CMAC
  - [ ] RMAC
  - [x] CDEC

## Some examples of usage

### Establish a secure channel

```csharp
// Define card keys
var SEnc = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
var SMac = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
var Dek = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();

CardContext? cardContext;
CardChannel? cardChannel;
try
{
    // Get a valid cardChannel instance
    // ...

    // Use GlobalPlatform API
    var gpCard = new GlobalPlatformCard(cardChannel);

    gpCard
        .ProcessSelectCardManager();

    gpCard
        .ProcessGetCardData();

    Console.WriteLine(gpCard.CardData);

    // Do SCP02 Mutual Authentication
    var scpUsed = gpCard.CardData.SupportedScps.First(scp => scp.Identifier == 0x02);

    gpCard
        .ProcessInitializeUpdate(scpUsed, keyVersion, KeyIdentifier, hostChallenge);

    Console.WriteLine(gpCard.SecureChannelData);

    gpCard
        .CreateSessionKeys(new Keys(SEnc, SMac, Dek));

    Console.WriteLine(gpCard.SecureChannelData);

    gpCard
        .AuthenticateCard();

    gpCard
        .ProcessExternalAuthenticate(SecurityLevel.CMac /*| SecurityLevel.CEnc */);

    Console.WriteLine(gpCard.SecureChannelData);

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
```

### INSTALL [for load]

Once the secure channel is established, a new application on the card can be loaded on the card.

```csharp
var loadFileAid = "F04341454E42".FromHexa();
byte[] securityDomainAid = [];
byte[] loadFileDataBlockHash = [];
byte[] loadParameters = [];
byte[] loadToken = [];

gpCard
	.ProcessInstallForLoad(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken);

var pathToCapFile = @"path/to/cap/file/applet.cap";

gpCard
	.ProcessLoad(pathToCapFile);
```

### INSTALL [for install and make selectable]

```csharp
var moduleAid = "F04341454E42 01".FromHexa();
var applicationAid = "F04341454E42 01".FromHexa();
var privileges = "00".FromHexa();
var installParameters = "C9 00".FromHexa();
byte[] installToken = [];

gpCard
	.ProcessInstallForInstallAndMakeSelectable(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken);
```
### DELETE

```csharp
var aid = "F04341454E42".FromHexa();

gpCard
	.ProcessDelete(aid);
```

## `wsct-gp` command line tool

See [wsct-gp](WSCT.GlobalPlatform.CommandLine/README.md) for more information.

```bash
wsct-gp --list-applications
```
