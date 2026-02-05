using System.ComponentModel;
using Spectre.Console.Cli;

namespace WSCT.GlobalPlatform.CommandLine.Commands
{
    public class InstallSettings : AuthenticationSettings
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
}