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
        services.AddSingleton<IWSCTService, WSCTService>();
        services.AddLogging(configure => configure.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.IncludeScopes = false;
        }));

        var registrar = new TypeRegistrar(services);
        var app = new CommandApp(registrar);
        app.Configure(config =>
        {
            config.AddCommand<ListReadersCommand>("list-readers")
                .WithDescription("Lists available readers");
            config.AddCommand<ListApplicationsCommand>("list-applications")
                .WithDescription("Lists available applications on the card");
        });

        return app.Run(args);
    }
}
