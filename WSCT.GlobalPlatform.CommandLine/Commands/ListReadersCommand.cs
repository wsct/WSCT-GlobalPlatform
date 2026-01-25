using Spectre.Console;
using Spectre.Console.Cli;

using WSCT.Core;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class ListReadersCommand : Command
{
    public override int Execute(CommandContext context)
    {
        var cardContext = new CardContextObservable(new CardContext());

        var establishResult = cardContext
            .Establish();

        if (establishResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Establish failed: {establishResult}[/]");
            return 1;
        }

        var listReaderGroupsResult = cardContext
            .ListReaderGroups();

        if (listReaderGroupsResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]List reader groups failed: {listReaderGroupsResult}[/]");
            return 1;
        }

        var listReadersResult = cardContext
            .ListReaders(cardContext.Groups[0]);

        if (listReadersResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]List readers failed: {listReadersResult}[/]");
            return 1;
        }

        var table = new Table()
            .RoundedBorder()
            .AddColumn("Id")
            .AddColumn("Reader");

        var id = 1;
        foreach (var reader in cardContext.Readers)
        {
            table.AddRow($"{id}", reader);
            id++;
        }

        AnsiConsole.Write(table);

        return 0;
    }
}
