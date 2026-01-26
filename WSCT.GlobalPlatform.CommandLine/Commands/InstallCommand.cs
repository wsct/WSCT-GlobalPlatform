using System.ComponentModel;
using Spectre.Console;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Commands
{
    public class InstallCommand(IWSCTService wsctService, IGlobalPlatformService gpService, IGlobalPlatformConsoleService gpConsoleService)
        : Command<InstallCommand.Settings>
    {
        public class Settings : CommandSettings
        {
            [CommandOption(template: "--aid", isRequired: true)]
            [Description("The AID of the application to install")]
            public string Aid { get; init; } = string.Empty;

            [CommandOption(template: "--cap", isRequired: true)]
            [Description("The path to the .cap file to load")]
            public string PathToCapFile { get; init; } = string.Empty;

            [CommandOption(template: "--priv", isRequired: false)]
            [Description("The privileges of the application")]
            public string Privileges { get; init; } = "00";

            [CommandOption(template: "--aid-exec", isRequired: true)]
            [Description("The AID of the executable module")]
            public string ExecutableAid { get; init; } = string.Empty;

            [CommandOption(template: "--install-params")]
            [Description("The install parameters")]
            public string InstallParameters { get; init; } = "C9 00";
        }

        public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var readerName = gpConsoleService.InitializeAndSelectReader();

                if (string.IsNullOrEmpty(readerName))
                {
                    return 1;
                }

                AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

                var authenticated = gpConsoleService.AuthenticateCard(readerName);

                if (!authenticated)
                {
                    return 1;
                }

                AnsiConsole.MarkupLine($"[yellow]Install {settings.Aid} on card...[/]");
                /*
                                var deleteResult = gpService.DeleteApplication(settings.Aid.FromHexa());

                                if (deleteResult != ErrorCode.Success)
                                {
                                    AnsiConsole.MarkupLineInterpolated($"[red]Failed to delete application: {deleteResult}[/]");
                                    return 1;
                                }
                */

                // INSTALL [for load] parameters
                var loadFileAid = settings.Aid.FromHexa();
                byte[] securityDomainAid = [];
                byte[] loadFileDataBlockHash = [];
                byte[] loadParameters = [];
                byte[] loadToken = [];

                // INSTALL [for load]
                var installForLoadResult = gpService.InstallForLoad(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken);

                if (installForLoadResult != ErrorCode.Success)
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]Failed to install for load: {installForLoadResult}[/]");
                    return 1;
                }

                // LOAD
                var loadResult = gpService.Load(settings.PathToCapFile);

                if (loadResult != ErrorCode.Success)
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]Failed to load: {loadResult}[/]");
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