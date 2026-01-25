using Spectre.Console;
using Spectre.Console.Cli;

using WSCT.Core;
using WSCT.GlobalPlatform.CommandLine.Services;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class ListReadersCommand(IWSCTService wsctService) : Command
{
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

        var table = new Table()
            .RoundedBorder()
            .AddColumn("Id")
            .AddColumn("Reader");

        var id = 1;
        foreach (var reader in readers)
        {
            table.AddRow($"{id}", reader);
            id++;
        }

        AnsiConsole.Write(table);

        return 0;
    }
}
