using Spectre.Console;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;
using WSCT.Helpers;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class ListApplicationsCommand(IWSCTService wsctService, IGlobalPlatformService gpService, IGlobalPlatformConsoleService gpConsoleService)
   : Command<AuthenticationSettings>
{
    public override int Execute(CommandContext context, AuthenticationSettings settings, CancellationToken cancellationToken)
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

            AnsiConsole.MarkupLine("[yellow]Getting applications on card...[/]");

            var applications = gpService.GetApplications();

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
