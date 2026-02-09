using System.ComponentModel;
using Spectre.Console.Cli;
using WSCT.GlobalPlatform.CommandLine.Converters;

namespace WSCT.GlobalPlatform.CommandLine.Commands;

public class AuthenticationSettings : CommandSettings
{
    [CommandOption(template: "--senc", isRequired: false)]
    [Description("The SEnc key")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] SEnc { get; init; } = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F];

    [CommandOption(template: "--smac", isRequired: false)]
    [Description("The SMac key")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] SMac { get; init; } = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F];

    [CommandOption(template: "--dek", isRequired: false)]
    [Description("The DEK key")]
    [TypeConverter(typeof(HexaStringToByteArrayConverter))]
    public byte[] Dek { get; init; } = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F];

    [CommandOption(template: "--key-version", isRequired: false)]
    [Description("The key version (hexa)")]
    [TypeConverter(typeof(HexaStringToByteConverter))]
    public byte KeyVersion { get; init; } = 0x00;

    [CommandOption(template: "--key-identifier", isRequired: false)]
    [Description("The key identifier (hexa)")]
    [TypeConverter(typeof(HexaStringToByteConverter))]
    public byte KeyIdentifier { get; init; } = 0x00;
}