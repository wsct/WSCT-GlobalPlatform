using WSCT.Helpers;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

public static class GlobalPlatformExtensions
{
    public static CommandResponsePair ProcessGetStatus(this GlobalPlatformCard gpCard, GetStatusCommand.Subset subset, Span<byte> applicationAid, GetStatusCommand.Occurrence occurrence, GetStatusCommand.ResponseFormat responseFormat)
    {
        return gpCard
            .ProcessCommand(new GetStatusCommand(subset, applicationAid, occurrence, responseFormat));
    }

    public static CommandResponsePair ProcessGetIsdStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid)
    {
        return gpCard
            .ProcessGetStatus(GetStatusCommand.Subset.IssuerSecurityDomain, applicationAid, gpCard.GuessBestResponseFormat());
    }

    public static CommandResponsePair ProcessGetAppAndSsdStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid)
    {
        return gpCard
            .ProcessGetStatus(GetStatusCommand.Subset.ApplicationAndSupplementarySecurityDomains, applicationAid, gpCard.GuessBestResponseFormat());
    }

    public static CommandResponsePair ProcessGetExecutableLoadFilesStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid)
    {
        return gpCard
            .ProcessGetStatus(GetStatusCommand.Subset.ExecutableLoadFiles, applicationAid, gpCard.GuessBestResponseFormat());
    }

    public static CommandResponsePair ProcessGetExecutableLoadFilesAndModulesStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid)
    {
        return gpCard
            .ProcessGetStatus(GetStatusCommand.Subset.ExecutableLoadFilesAndTheirModules, applicationAid, gpCard.GuessBestResponseFormat());
    }

    private static GetStatusCommand.ResponseFormat GuessBestResponseFormat(this GlobalPlatformCard gpCard)
    {
        // Guess best response format based on Card Data format when previously retrieved
        if (String.Compare(gpCard.CardData?.GlobalPlatformVersion.ToHexa('\0'), "020101") >= 0)
        {
            return GetStatusCommand.ResponseFormat.Tlv;
        }

        return GetStatusCommand.ResponseFormat.Deprecated;
    }
}