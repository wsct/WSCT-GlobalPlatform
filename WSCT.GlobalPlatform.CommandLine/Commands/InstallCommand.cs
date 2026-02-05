using Spectre.Console;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Commands
{

    public class InstallCommand(IWSCTService wsctService, IGlobalPlatformService gpService, IGlobalPlatformConsoleService gpConsoleService)
        : Command<InstallSettings>
    {
        public override int Execute(CommandContext context, InstallSettings settings, CancellationToken cancellationToken)
        {
            try
            {
                var readerName = gpConsoleService.InitializeAndSelectReader();

                if (string.IsNullOrEmpty(readerName))
                {
                    return 1;
                }

                AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

                var authenticated = gpConsoleService.AuthenticateCard(readerName, settings.SEnc.FromHexa(), settings.SMac.FromHexa(), settings.Dek.FromHexa(), settings.KeyVersion.FromHexa()[0], settings.KeyIdentifier.FromHexa()[0]);

                if (!authenticated)
                {
                    return 1;
                }

                AnsiConsole.MarkupLine($"[yellow]Install {settings.Aid} on card...[/]");

                // INSTALL [for load] parameters
                var loadFileAid = settings.Aid.FromHexa();
                byte[] securityDomainAid = [];
                byte[] loadFileDataBlockHash = [];
                byte[] loadParameters = [];
                byte[] loadToken = [];

                // INSTALL [for load]
                var installForLoadResult = gpService.InstallForLoad(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken);

                if (!installForLoadResult)
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]Failed to INSTALL [[for load]][/]");
                    return 1;
                }

                // LOAD
                var loadResult = gpService.Load(settings.PathToCapFile);

                if (loadResult != ErrorCode.Success)
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]Failed to LOAD: {loadResult}[/]");
                    return 1;
                }

                // INSTALL [for *] parameters
                var moduleAid = settings.ExecutableAid.FromHexa();
                var applicationAid = settings.ExecutableAid.FromHexa();
                var privileges = settings.Privileges.FromHexa();
                var installParameters = settings.InstallParameters.FromHexa();
                var installToken = Array.Empty<byte>();

                // INSTALL [for install and make selectable]
                var installForInstallAndMakeSelectableResult = gpService.InstallForInstallAndMakeSelectable(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken);

                if (installForInstallAndMakeSelectableResult != ErrorCode.Success)
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]Failed to install for install and make selectable: {installForInstallAndMakeSelectableResult}[/]");
                    return 1;
                }

                AnsiConsole.MarkupLineInterpolated($"[yellow]Application {settings.Aid} installed successfully[/]");
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
}