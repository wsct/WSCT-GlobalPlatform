using System.ComponentModel;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Converters;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class DeleteSettings : AuthenticationSettings
{
    [CommandOption(template: "--aid", isRequired: true)]
    [Description("The AID of the application to delete")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] Aid { get; init; } = [];
}

