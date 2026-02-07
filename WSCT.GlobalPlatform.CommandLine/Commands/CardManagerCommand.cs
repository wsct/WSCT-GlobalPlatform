using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class CardManagerCommand(IGlobalPlatformConsoleService gpConsoleService)
    : Command
{
    public override int Execute(CommandContext context, CancellationToken cancellationToken)
    {
        var result = gpConsoleService.SelectCardManager();

        return result ? 0 : 1;
    }
}
