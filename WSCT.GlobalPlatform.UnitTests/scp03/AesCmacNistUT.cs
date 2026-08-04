using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security;
using WSCT.GlobalPlatform.Security.Scp03;
namespace WSCT.GlobalPlatform.UnitTests;

[TestFixture]
public class AesCmacNistUT
{
    private static IEnumerable<TestCaseData> CmacVectors()
    {
        string file = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "scp03",
            "nist",
            "CMACGenAES128.rsp");

        foreach (var vector in ParseRsp(file))
        {
            yield return new TestCaseData(
                vector.Key,
                vector.Msg,
                vector.Mac)
                .SetName($"CMAC Count={vector.Count}");
        }
    }


    [TestCaseSource(nameof(CmacVectors))]
    public void Cmac_ShouldMatchNistVector_CMACGenAES128(
        byte[] key,
        byte[] msg,
        byte[] expected)
    {
        if (msg.SequenceEqual([(byte)0x00]))
        {
            msg = Array.Empty<byte>();
        }
        byte[] result = AesCmac.Compute(key, msg);

        // Gestion Tlen (MAC tronqué)
        result = result.Take(expected.Length).ToArray();

        Assert.That(result, Is.EqualTo(expected));
    }


    private static IEnumerable<CmacVector> ParseRsp(string file)
    {
        var current = new CmacVector();

        foreach (string line in File.ReadLines(file))
        {
            string l = line.Trim();

            if (string.IsNullOrEmpty(l))
            {
                if (current.Key != null)
                {
                    yield return current;
                    current = new CmacVector();
                }

                continue;
            }


            var parts = l.Split('=', 2);
            if (parts.Length != 2)
                continue;

            string name = parts[0].Trim();
            string value = parts[1].Trim();

            switch (name)
            {
                case "Count":
                    current.Count = int.Parse(value);
                    break;

                case "Key":
                    current.Key = HexToBytes(value);
                    break;

                case "Msg":
                    current.Msg = HexToBytes(value);
                    break;

                case "Mac":
                    current.Mac = HexToBytes(value);
                    break;
            }
        }

        if (current.Key != null)
            yield return current;
    }


    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex))
            return Array.Empty<byte>();

        return Enumerable.Range(0, hex.Length / 2)
            .Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16))
            .ToArray();
    }


    private class CmacVector
    {
        public int Count { get; set; }
        public byte[] Key { get; set; }
        public byte[] Msg { get; set; }
        public byte[] Mac { get; set; }
    }
}