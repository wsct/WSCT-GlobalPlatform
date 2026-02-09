using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Commands;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine;

public class Program
{
    public static int Main(string[] args)
    {
        var services = new ServiceCollection();

        // Services
        services.AddSingleton<IWSCTService, WSCTService>();
        services.AddSingleton<IGlobalPlatformService, GlobalPlatformService>();
        services.AddSingleton<IGlobalPlatformConsoleService, GlobalPlatformConsoleService>();

        // Logging
        services.AddLogging(configure => configure.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.IncludeScopes = true;
        }));

        var registrar = new TypeRegistrar(services);

        var app = new CommandApp(registrar);
        app.Configure(config =>
        {
            config.AddCommand<ListReadersCommand>("list-readers")
                .WithDescription("Lists available readers");
            config.AddCommand<ListApplicationsCommand>("list-applications")
                .WithDescription("Lists available applications on the card");
            config.AddCommand<DeleteCommand>("delete")
                .WithDescription("Deletes an application from the card");
            config.AddCommand<InstallCommand>("install")
                .WithDescription("Installs an application on the card");
            config.AddCommand<CardManagerCommand>("card-manager")
                .WithDescription("Selects the card manager");
        });

        return app.Run(args);
    }
}
