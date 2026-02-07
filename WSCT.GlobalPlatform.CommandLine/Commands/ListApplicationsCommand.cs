using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class ListApplicationsCommand(IGlobalPlatformConsoleService gpConsoleService)
   : Command<AuthenticationSettings>
{
    public override int Execute(CommandContext context, AuthenticationSettings settings, CancellationToken cancellationToken)
    {
        var authParams = new AuthenticationParameters(settings.SEnc, settings.SMac, settings.Dek, settings.KeyVersion, settings.KeyIdentifier);

        var result = gpConsoleService.ListApplications(authParams);

        return result ? 0 : 1;
    }
}
