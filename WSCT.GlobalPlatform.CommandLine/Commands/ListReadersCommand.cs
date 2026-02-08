using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class ListReadersCommand(IGlobalPlatformConsoleService gpConsoleService)
    : Command
{
    public override int Execute(CommandContext context, CancellationToken cancellationToken)
    {
        var result = gpConsoleService.ListReaders();

        return result ? 0 : 1;
    }
}
