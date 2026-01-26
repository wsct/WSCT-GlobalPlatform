using Spectre.Console;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public class GlobalPlatformConsoleService(IWSCTService wsctService, IGlobalPlatformService gpService) : IGlobalPlatformConsoleService
{
    protected static readonly byte[] _defaultSEnc = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
    protected static readonly byte[] _defaultSMac = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
    protected static readonly byte[] _defaultDek = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
    protected const byte _defaultKeyVersion = 0x00;
    protected const byte _defaultKeyIdentifier = 0x00;

    public bool AuthenticateCard(string readerName)
    {
        AnsiConsole.MarkupLine("[yellow]Connecting to card...[/]");

        var connectResult = wsctService.Connect(readerName);
        if (connectResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Connect failed: {connectResult}[/]");
            return false;
        }

        AnsiConsole.MarkupLine("[yellow]Selecting card manager...[/]");

        var selectCardManagerResult = gpService.SelectCardManager();
        if (selectCardManagerResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]SelectCardManager failed: {selectCardManagerResult}[/]");
            return false;
        }

        AnsiConsole.MarkupLine("[yellow]Getting card data...[/]");

        var getCardDataResult = gpService.GetCardData();
        if (getCardDataResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]GetCardData failed: {getCardDataResult}[/]");
            return false;
        }

        AnsiConsole.MarkupLine("[yellow]Authenticating...[/]");

        var authenticateResult = gpService.Authenticate(_defaultSEnc, _defaultSMac, _defaultDek, _defaultKeyVersion, _defaultKeyIdentifier);
        if (authenticateResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Authenticate failed: {authenticateResult}[/]");
            return false;
        }

        return true;
    }

    public string InitializeAndSelectReader()
    {
        var establishResult = wsctService.Establish();

        if (establishResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Establish failed: {establishResult}[/]");
            return "";
        }

        var readers = wsctService.GetReaders();

        if (readers.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]No readers found[/]");
            return "";
        }

        var readerName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[yellow]Select the reader to use[/]")
                .AddChoices(readers));

        return readerName ?? "";
    }
}
