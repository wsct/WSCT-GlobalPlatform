using System.IO.Compression;
using WSCT.Helpers.BasicEncodingRules;

namespace WSCT.GlobalPlatform.JavaCard
{
    public class CapFile
    {
        private readonly ZipArchive _capFile;

        #region >> Static data

        private static readonly string[] ComponentNamesOrder = {
            "Header.cap",
            "Directory.cap",
            "Import.cap",
            "Applet.cap",
            "Class.cap",
            "Method.cap",
            "StaticField.cap",
            "Export.cap",
            "ConstantPool.cap",
            "RefLocation.cap",
            "StaticResources.cap"
            //"Descriptor.cap"
        };

        #endregion

        public CapFile(string pathToCapFile)
            : this(File.OpenRead(pathToCapFile))
        {

        }

        public CapFile(Stream rawCapFileStream)
        {
            _capFile = new ZipArchive(rawCapFileStream);
        }

        public int GetLoadSize()
        {
            return (int)GetComponents()
                .Sum(component => component.Length);
        }

        public byte[] GetLoadData()
        {
            var loadData = new byte[GetLoadSize()];
            var span = loadData.AsSpan();

            foreach (var component in GetComponents())
            {
                using (var data = new BinaryReader(component.Open()))
                {
                    data.ReadBytes((int)component.Length)
                        .AsSpan()
                        .CopyTo(span);
                }

                span = span[(int)component.Length..];
            }

            return new TlvData(0xC4, (uint)loadData.Length, loadData).ToByteArray();
        }

        private IEnumerable<ZipArchiveEntry> GetComponents()
        {
            foreach (var componentName in ComponentNamesOrder)
            {
                var component = _capFile.Entries
                    .FirstOrDefault(e => e.Name.StartsWith(componentName, StringComparison.InvariantCultureIgnoreCase));

                if (component is not null)
                {
                    yield return component;
                }
            }
        }
    }
}
