using System.ComponentModel;
using Spectre.Console.Cli;

namespace WSCT.GlobalPlatform.CommandLine.Commands
{
    public class AuthenticationSettings : CommandSettings
    {
        [CommandOption(template: "--senc", isRequired: false)]
        [Description("The SEnc key")]
        public string SEnc { get; init; } = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F";

        [CommandOption(template: "--smac", isRequired: false)]
        [Description("The SMac key")]
        public string SMac { get; init; } = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F";

        [CommandOption(template: "--dek", isRequired: false)]
        [Description("The DEK key")]
        public string Dek { get; init; } = "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F";

        [CommandOption(template: "--key-version", isRequired: false)]
        [Description("The key version")]
        public string KeyVersion { get; init; } = "00";

        [CommandOption(template: "--key-identifier", isRequired: false)]
        [Description("The key identifier")]
        public string KeyIdentifier { get; init; } = "00";
    }
}