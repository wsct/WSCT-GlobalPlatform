using Microsoft.VisualBasic;
using Spectre.Console;
using Spectre.Console.Cli;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform.CommandLine.Services;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class ListApplicationsCommand(IWSCTService wsctService) : Command
{
    private static readonly byte[] _defaultSEnc = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
    private static readonly byte[] _defaultSMac = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
    private static readonly byte[] _defaultDek = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F".FromHexa();
    private const byte _defaultKeyVersion = 0x00;
    private const byte _defaultKeyIdentifier = 0x00;

    public override int Execute(CommandContext context)
    {
        var establishResult = wsctService.Establish();

        if (establishResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Establish failed: {establishResult}[/]");
            return 1;
        }

        var readers = wsctService.GetReaders();

        if (readers.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]No readers found[/]");
            return 1;
        }

        var readerName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select a [green]reader[/]:")
                .AddChoices(readers));

        AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

        try
        {
            AnsiConsole.MarkupLine("[yellow]Connecting to card...[/]");

            var connectResult = wsctService.Connect(readerName);
            if (connectResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLine($"[red]Connect failed: {connectResult}[/]");
                return 1;
            }

            AnsiConsole.MarkupLine("[yellow]Selecting card manager...[/]");

            var selectCardManagerResult = wsctService.SelectCardManager();
            if (selectCardManagerResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLine($"[red]SelectCardManager failed: {selectCardManagerResult}[/]");
                return 1;
            }

            AnsiConsole.MarkupLine("[yellow]Getting card data...[/]");

            var getCardDataResult = wsctService.GetCardData();
            if (getCardDataResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLine($"[red]GetCardData failed: {getCardDataResult}[/]");
                return 1;
            }

            AnsiConsole.MarkupLine("[yellow]Authenticating...[/]");

            var authenticateResult = wsctService.Authenticate(_defaultSEnc, _defaultSMac, _defaultDek, _defaultKeyVersion, _defaultKeyIdentifier);
            if (authenticateResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLine($"[red]Authenticate failed: {authenticateResult}[/]");
                return 1;
            }

            AnsiConsole.MarkupLine("[yellow]Getting applications on card...[/]");

            var applications = wsctService.GetApplications();

            var table = new Table()
                .RoundedBorder()
                .AddColumn("Id")
                .AddColumn("AID")
                .AddColumn("LifeCycle State")
                .AddColumn("Privileges")
                .AddColumn("Executable Modules AID")
                .AddColumn("LoadFile AID")
                .AddColumn("LoadFile Version")
                .AddColumn("Security Domain");

            var id = 1;
            foreach (var application in applications)
            {
                table.AddRow($"{id}",
                    $"{application.Aid}",
                    $"{application.LifeCycleState}",
                    $"{application.Privileges.ToHexa()}",
                    $"{string.Join<AID>("\n", application.ModuleAids)}",
                    $"{application.LoadFileAid}",
                    $"{application.LoadFileVersion.ToHexa()}",
                    $"{application.SecurityDomainAid}");
                id++;
            }

            AnsiConsole.Write(table);
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Exception: {e.Message}[/]");
            return 1;
        }
        finally
        {
            wsctService.Disconnect();
            wsctService.Release();
        }
        return 0;
    }
}
