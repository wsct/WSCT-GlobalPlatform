using System.ComponentModel;
using Spectre.Console.Cli;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class DeleteSettings : AuthenticationSettings
{
    [CommandOption(template: "--aid", isRequired: true)]
    [Description("The AID of the application to delete")]
    public string Aid { get; init; } = string.Empty;
}

