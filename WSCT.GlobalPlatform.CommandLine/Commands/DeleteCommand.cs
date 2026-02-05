using Spectre.Console;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Services;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public partial class DeleteCommand(IWSCTService wsctService, IGlobalPlatformService gpService, IGlobalPlatformConsoleService gpConsoleService)
    : Command<DeleteSettings>
{
    public override int Execute(CommandContext context, DeleteSettings settings, CancellationToken cancellationToken)
    {
        try
        {
            var readerName = gpConsoleService.InitializeAndSelectReader();

            if (string.IsNullOrEmpty(readerName))
            {
                return 1;
            }

            AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

            byte[] sEnc, sMac, dek;
            byte keyVersion, keyIdentifier;

            try
            {
                sEnc = settings.SEnc.FromHexa();
                sMac = settings.SMac.FromHexa();
                dek = settings.Dek.FromHexa();
                keyVersion = settings.KeyVersion.FromHexa()[0];
                keyIdentifier = settings.KeyIdentifier.FromHexa()[0];
            }
            catch (Exception e)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]Exception: {e.Message}[/]");
                return 1;
            }

            var authenticated = gpConsoleService.AuthenticateCard(readerName, sEnc, sMac, dek, keyVersion, keyIdentifier);

            if (!authenticated)
            {
                return 1;
            }

            AnsiConsole.MarkupLine($"[yellow]Delete {settings.Aid} on card...[/]");

            var deleteResult = gpService.DeleteApplication(settings.Aid.FromHexa());

            if (deleteResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]Failed to delete application: {deleteResult}[/]");
                return 1;
            }

            AnsiConsole.MarkupLineInterpolated($"[yellow]Application {settings.Aid} deleted successfully[/]");
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
