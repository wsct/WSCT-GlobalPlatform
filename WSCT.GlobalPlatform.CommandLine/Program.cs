using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Commands;

namespace WSCT.GlobalPlatform.CommandLine;

public class Program
{
    public static int Main(string[] args)
    {
        var app = new CommandApp();
        app.Configure(config =>
        {
            config.AddCommand<ListReadersCommand>("list-readers")
                .WithDescription("Lists available readers");
        });

        return app.Run(args);
    }
}
