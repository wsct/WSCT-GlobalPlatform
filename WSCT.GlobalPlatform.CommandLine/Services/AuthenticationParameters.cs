namespace WSCT.GlobalPlatform.CommandLine.Services;

public record AuthenticationParameters(
    byte[] SEnc,
    byte[] SMac,
    byte[] Dek,
    byte KeyVersion,
    byte KeyIdentifier)
{
}