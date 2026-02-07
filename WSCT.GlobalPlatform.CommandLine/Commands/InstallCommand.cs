using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class InstallCommand(IGlobalPlatformConsoleService gpConsoleService)
    : Command<InstallSettings>
{
    public override int Execute(CommandContext context, InstallSettings settings, CancellationToken cancellationToken)
    {
        var authParams = new AuthenticationParameters(settings.SEnc, settings.SMac, settings.Dek, settings.KeyVersion, settings.KeyIdentifier);

        var result = gpConsoleService.Install(settings.Aid, settings.PathToCapFile, settings.ExecutableAid, settings.Privileges, settings.InstallParameters, authParams);

        return result ? 0 : 1;
    }
}
