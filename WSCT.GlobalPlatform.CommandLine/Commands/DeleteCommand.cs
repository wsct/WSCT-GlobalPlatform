using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class DeleteCommand(IGlobalPlatformConsoleService gpConsoleService)
    : Command<DeleteSettings>
{
    public override int Execute(CommandContext context, DeleteSettings settings, CancellationToken cancellationToken)
    {
        var authParams = new AuthenticationParameters(settings.SEnc, settings.SMac, settings.Dek, settings.KeyVersion, settings.KeyIdentifier);

        var result = gpConsoleService.Delete(settings.Aid, authParams);

        return result ? 0 : 1;
    }
}
