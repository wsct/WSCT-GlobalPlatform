using Spectre.Console;
using WSCT.Helpers;
using WSCT.Wrapper;

namespace WSCT.GlobalPlatform.CommandLine.Services;

public class GlobalPlatformConsoleService(IWSCTService wsctService, IGlobalPlatformService gpService) : IGlobalPlatformConsoleService
{
    private bool Authenticate(string readerName, AuthenticationParameters authParams)
    {
        AnsiConsole.MarkupLine("[yellow]Connecting to card...[/]");

        var connectResult = wsctService.Connect(readerName);
        if (connectResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Connect failed: {connectResult}[/]");
            return false;
        }

        AnsiConsole.MarkupLine("[yellow]Selecting card manager...[/]");

        var selectCardManagerResult = gpService.SelectCardManager();
        if (!selectCardManagerResult)
        {
            AnsiConsole.MarkupLine($"[red]SelectCardManager failed[/]");
            return false;
        }

        AnsiConsole.MarkupLine("[yellow]Getting card data...[/]");

        var getCardDataStatus = gpService.GetCardData();
        if (!getCardDataStatus)
        {
            AnsiConsole.MarkupLine($"[red]GetCardData failed[/]");
            return false;
        }

        AnsiConsole.MarkupLine("[yellow]Authenticating...[/]");

        var authenticateResult = gpService.Authenticate(authParams.SEnc, authParams.SMac, authParams.Dek, authParams.KeyVersion, authParams.KeyIdentifier);
        if (authenticateResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Authenticate failed: {authenticateResult}[/]");
            return false;
        }

        return true;
    }

    public bool Delete(byte[] aid, AuthenticationParameters authParams)
    {
        try
        {
            var readerName = InitializeAndSelectReader();

            if (string.IsNullOrEmpty(readerName))
            {
                return false;
            }

            AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

            var authenticated = Authenticate(readerName, authParams);

            if (!authenticated)
            {
                return false;
            }

            AnsiConsole.MarkupLine($"[yellow]Deleting application {aid.ToHexa()}...[/]");

            var applicationDeleted = gpService.DeleteApplication(aid);

            if (!applicationDeleted)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]Failed to delete application[/]");
                return false;
            }

            AnsiConsole.MarkupLineInterpolated($"[yellow]Application {aid.ToHexa()} deleted successfully[/]");
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Exception: {e.Message}[/]");
            return false;
        }
        finally
        {
            wsctService.Disconnect();
            wsctService.Release();
        }
        return true;
    }

    private string InitializeAndSelectReader()
    {
        var establishResult = wsctService.Establish();

        if (establishResult != ErrorCode.Success)
        {
            AnsiConsole.MarkupLine($"[red]Establish failed: {establishResult}[/]");
            return "";
        }

        var readers = wsctService.GetReaders();

        if (readers.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]No readers found[/]");
            return "";
        }

        var readerName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[yellow]Select the reader to use[/]")
                .AddChoices(readers));

        return readerName ?? "";
    }

    public bool Install(byte[] aid, string pathToCapFile, byte[] executableAid, byte[] privileges, byte[] installParameters, AuthenticationParameters authParams)
    {
        byte[] loadFileAid = aid;
        byte[] moduleAid = executableAid;
        byte[] applicationAid = executableAid;

        try
        {
            var readerName = InitializeAndSelectReader();

            if (string.IsNullOrEmpty(readerName))
            {
                return false;
            }

            AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

            var authenticated = Authenticate(readerName, authParams);

            if (!authenticated)
            {
                return false;
            }

            AnsiConsole.MarkupLine($"[yellow]Install {aid.ToHexa()} on card...[/]");

            // INSTALL [for load] parameters
            byte[] securityDomainAid = [];
            byte[] loadFileDataBlockHash = [];
            byte[] loadParameters = [];
            byte[] loadToken = [];

            // INSTALL [for load]
            var installForLoadStatus = gpService.InstallForLoad(loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken);

            if (!installForLoadStatus)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]Failed to INSTALL [[for load]][/]");
                return false;
            }

            // LOAD
            var loadResult = gpService.Load(pathToCapFile);

            if (!loadResult)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]Failed to LOAD[/]");
                return false;
            }

            // INSTALL [for *] parameters
            byte[] installToken = [];

            // INSTALL [for install and make selectable]
            var installForInstallAndMakeSelectableResult = gpService.InstallForInstallAndMakeSelectable(loadFileAid, moduleAid, applicationAid, privileges, installParameters, installToken);

            if (!installForInstallAndMakeSelectableResult)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]Failed to INSTALL [[for install and make selectable]][/]");
                return false;
            }

            AnsiConsole.MarkupLineInterpolated($"[yellow]Application {loadFileAid.ToHexa()} installed successfully[/]");
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Exception: {e.Message}[/]");
            return false;
        }
        finally
        {
            wsctService.Disconnect();
            wsctService.Release();
        }
        return true;
    }

    public bool ListApplications(AuthenticationParameters authParams)
    {
        try
        {
            var readerName = InitializeAndSelectReader();

            if (string.IsNullOrEmpty(readerName))
            {
                return false;
            }

            AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

            var authenticated = Authenticate(readerName, authParams);

            if (!authenticated)
            {
                return false;
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
            return false;
        }
        finally
        {
            wsctService.Disconnect();
            wsctService.Release();
        }
        return true;
    }

    public bool ListReaders()
    {
        try
        {
            var establishResult = wsctService.Establish();

            if (establishResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLine($"[red]Establish failed: {establishResult}[/]");
                return false;
            }

            var readers = wsctService.GetReaders();

            if (readers.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]No readers found[/]");
                return false;
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

            return true;
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Exception: {e.Message}[/]");
            return false;
        }
        finally
        {
            wsctService.Release();
        }
    }

    public bool SelectCardManager()
    {
        try
        {
            var readerName = InitializeAndSelectReader();

            if (string.IsNullOrEmpty(readerName))
            {
                return false;
            }

            AnsiConsole.MarkupLine($"Now working with [blue]{readerName}[/]");

            AnsiConsole.MarkupLine("[yellow]Connecting to card...[/]");

            var connectResult = wsctService.Connect(readerName);
            if (connectResult != ErrorCode.Success)
            {
                AnsiConsole.MarkupLine($"[red]Connect failed: {connectResult}[/]");
                return false;
            }

            AnsiConsole.MarkupLine("[yellow]Selecting card manager...[/]");

            var selectCardManagerResult = gpService.SelectCardManager();
            if (!selectCardManagerResult)
            {
                AnsiConsole.MarkupLine($"[red]SelectCardManager failed[/]");
                return false;
            }

            AnsiConsole.MarkupLine("[yellow]Getting card data...[/]");

            var getCardDataStatus = gpService.GetCardData();
            if (!getCardDataStatus)
            {
                AnsiConsole.MarkupLine($"[red]GetCardData failed[/]");
                return false;
            }
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Exception: {e.Message}[/]");
            return false;
        }
        finally
        {
            wsctService.Disconnect();
            wsctService.Release();
        }

        return true;
    }
}