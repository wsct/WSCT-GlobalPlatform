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

    public static CommandResponsePair ProcessGetIsdStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid, GetStatusCommand.Occurrence occurrence = GetStatusCommand.Occurrence.FirstOrAll)
    {
        return gpCard
            .ProcessCommand(new GetStatusCommand(GetStatusCommand.Subset.IssuerSecurityDomain, applicationAid, occurrence, GuessBestResponseFormat(gpCard)));
    }

    public static CommandResponsePair ProcessGetAppAndSsdStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid, GetStatusCommand.Occurrence occurrence = GetStatusCommand.Occurrence.FirstOrAll)
    {
        return gpCard
            .ProcessCommand(new GetStatusCommand(GetStatusCommand.Subset.ApplicationAndSupplementarySecurityDomains, applicationAid, occurrence, GuessBestResponseFormat(gpCard)));
    }

    public static CommandResponsePair ProcessGetExecutableLoadFilesStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid, GetStatusCommand.Occurrence occurrence = GetStatusCommand.Occurrence.FirstOrAll)
    {
        return gpCard
            .ProcessCommand(new GetStatusCommand(GetStatusCommand.Subset.ExecutableLoadFiles, applicationAid, occurrence, GuessBestResponseFormat(gpCard)));
    }

    public static CommandResponsePair ProcessGetExecutableLoadFilesAndModulesStatusCommand(this GlobalPlatformCard gpCard, Span<byte> applicationAid, GetStatusCommand.Occurrence occurrence = GetStatusCommand.Occurrence.FirstOrAll)
    {
        return gpCard
            .ProcessCommand(new GetStatusCommand(GetStatusCommand.Subset.ExecutableLoadFilesAndTheirModules, applicationAid, occurrence, GuessBestResponseFormat(gpCard)));
    }

    private static GetStatusCommand.ResponseFormat GuessBestResponseFormat(GlobalPlatformCard gpCard)
    {
        // Guess best response format based on Card Data format when previously retrieved
        if (String.Compare(gpCard.CardData?.GlobalPlatformVersion.ToHexa('\0'), "020101") >= 0)
        {
            return GetStatusCommand.ResponseFormat.Tlv;
        }

        return GetStatusCommand.ResponseFormat.Deprecated;
    }
}