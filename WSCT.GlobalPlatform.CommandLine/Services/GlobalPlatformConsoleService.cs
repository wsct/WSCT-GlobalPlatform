using Spectre.Console;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public class GlobalPlatformConsoleService(IWSCTService wsctService, IGlobalPlatformService gpService) : IGlobalPlatformConsoleService
{
    public bool AuthenticateCard(string readerName, byte[] sEnc, byte[] sMac, byte[] dek, byte keyVersion, byte keyIdentifier)
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

        var authenticateResult = gpService.Authenticate(sEnc, sMac, dek, keyVersion, keyIdentifier);
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
