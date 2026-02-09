using WSCT.Helpers.BasicEncodingRules;

namespace WSCT.GlobalPlatform;

/// <summary>
/// Status of a card (response to GlobalPlatform GET STATUS command).
/// </summary>
public record Status(AID Aid, byte LifeCycleState, byte[] Privileges, AID LoadFileAid, byte[] LoadFileVersion, AID[] ModuleAids, AID SecurityDomainAid)
{
    /// <summary>
    /// Parse the status from the response data sent by the card.
    /// </summary>
    /// <param name="data">Raw data.</param>
    /// <returns>Status array.</returns>
    public static Status[] Parse(Span<byte> data)
    {
        if (data[0] != 0xE3)
        {
            return ParseRaw(data);
        }

        return ParseTlv(data);
    }

    /// <summary>
    /// Parse the status from a TLV sequence of bytes.
    /// </summary>
    /// <param name="data">TLV data.</param>
    /// <returns>Status array.</returns>
    private static Status[] ParseTlv(Span<byte> data)
    {
        var parsedData = new List<Status>();

        int readBytes;
        for (var span = data; span.Length > 0; span = span[readBytes..])
        {
            var tlvE3 = new TlvData();
            readBytes = (int)tlvE3.Parse(span.ToArray());

            parsedData.Add(ReadFromTlvE3(tlvE3));
        }

        return [.. parsedData];
    }

    /// <summary>
    /// Parse the status from a raw sequence of bytes.
    /// </summary>
    /// <param name="data">Raw data.</param>
    /// <returns>Status array.</returns>
    private static Status[] ParseRaw(Span<byte> data)
    {
        // TODO
        throw new NotImplementedException();
    }

    /// <summary>
    /// Read the status from a TLV E3 tag.
    /// </summary>
    /// <param name="tlv">TLV E3.</param>
    /// <returns>Status.</returns>  
    private static Status ReadFromTlvE3(TlvData tlv)
    {
        var aid = new AID(tlv.GetTag(0x4F).Value);
        var lifeCycle = tlv.GetTag(0x9F70).Value[0];
        var privileges = tlv.HasTag(0xC5) ? tlv.GetTag(0xC5).Value : [];
        var loadFileAid = new AID(tlv.HasTag(0xC4) ? tlv.GetTag(0xC4).Value : []);
        var loadFileVersion = tlv.HasTag(0xCE) ? tlv.GetTag(0xCE).Value : [];

        var moduleAids = new List<AID>();
        if (tlv.HasTag(0x84))
        {
            foreach (var tag84 in tlv.GetTags(0x84))
            {
                moduleAids.Add(new AID(tag84.Value));
            }
        }

        var securityDomainAid = tlv.HasTag(0xCC) ? new AID(tlv.GetTag(0xCC).Value) : new AID([]);

        return new Status(aid, lifeCycle, privileges, loadFileAid, loadFileVersion, [.. moduleAids], securityDomainAid);
    }
}
