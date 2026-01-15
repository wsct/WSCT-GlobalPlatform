using WSCT.Helpers.BasicEncodingRules;

namespace WSCT.GlobalPlatform
{
    public record Status(AID Aid, byte LifeCycleState, byte[] Privileges, AID LoadFileAid, byte[] LoadFileVersion, AID[] moduleAids, AID SecurityDomain)
    {
        public static Status[] Parse(Span<byte> data)
        {
            if (data[0] != 0xE3)
            {
                return ParseRaw(data);
            }

            return ParseTlv(data);
        }

        private static Status[] ParseTlv(Span<byte> data)
        {
            var parsedData = new List<Status>();

            var readBytes = 0;
            for (var span = data; span.Length > 0; span = span[readBytes..])
            {
                var tlvE3 = new TlvData();
                readBytes = (int)tlvE3.Parse(span.ToArray());

                parsedData.Add(ReadFromTlvE3(tlvE3));

            }

            return parsedData.ToArray();
        }

        private static Status[] ParseRaw(Span<byte> data)
        {
            // TODO
            throw new NotImplementedException();
        }

        private static Status ReadFromTlvE3(TlvData tlv)
        {
            var aid = new AID(tlv.GetTag(0x4F).Value);
            var lifeCycle = tlv.GetTag(0x9F70).Value[0];
            var privileges = tlv.HasTag(0xC5) ? tlv.GetTag(0xC5).Value : Array.Empty<byte>();
            var loadFileAid = new AID(tlv.HasTag(0xC4) ? tlv.GetTag(0xC4).Value : Array.Empty<byte>());
            var loadFileVersion = tlv.HasTag(0xCE) ? tlv.GetTag(0xCE).Value : Array.Empty<byte>();

            var moduleAids = new List<AID>();
            if (tlv.HasTag(0x84))
            {
                foreach (var tag84 in tlv.GetTags(0x84))
                {
                    moduleAids.Add(new AID(tag84.Value));
                }
            }

            var securityDomainAid = tlv.HasTag(0xCC, true) ? new AID(tlv.GetTag(0xCC, true).Value) : new AID(Array.Empty<byte>());

            return new Status(aid, lifeCycle, privileges, loadFileAid, loadFileVersion, moduleAids.ToArray(), securityDomainAid);
        }
    }
}
