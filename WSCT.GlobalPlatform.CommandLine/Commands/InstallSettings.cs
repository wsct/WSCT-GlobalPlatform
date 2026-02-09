using System.ComponentModel;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Converters;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class InstallSettings : AuthenticationSettings
{
    [CommandOption(template: "--aid", isRequired: true)]
    [Description("The AID of the application to install")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] Aid { get; init; } = [];

    [CommandOption(template: "--cap", isRequired: true)]
    [Description("The path to the .cap file to load")]
    public string PathToCapFile { get; init; } = String.Empty;

    [CommandOption(template: "--priv", isRequired: false)]
    [Description("The privileges of the application")]
    [TypeConverter(typeof(HexaStringToByteConverter))]
    public byte[] Privileges { get; init; } = [0x00];

    [CommandOption(template: "--aid-exec", isRequired: true)]
    [Description("The AID of the executable module")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] ExecutableAid { get; init; } = [];

    [CommandOption(template: "--install-params")]
    [Description("The install parameters")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] InstallParameters { get; init; } = [0xC9, 0x00];
}