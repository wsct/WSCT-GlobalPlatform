using System.Security.Cryptography;

namespace WSCT.GlobalPlatform.Security.Cryptography
{
    internal static class BytesExtensions
    {
        #region >> EncryptDes *

        /// <summary>
        /// Encrypts the <paramref name="input"/> using <paramref name="des"/> instance.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="des">DES instance.</param>
        /// <returns>Encrypted data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptDes(this byte[] input, DES des)
        {
            _ = input ?? throw new ArgumentNullException(nameof(input));
            _ = des ?? throw new ArgumentNullException(nameof(des));

            using var encryptor = des.CreateEncryptor();

            return encryptor.TransformFinalBlock(input, 0, input.Length);
        }

        /// <summary>
        /// Encrypts the <paramref name="input"/> using DES-CBC algorithm with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <returns>Encrypted data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptDesCbc(this byte[] input, byte[] key, byte[] iv)
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var des = DES.Create();
            des.Key = key;
            des.IV = iv;
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.None;

            return input.EncryptDes(des);
        }

        /// <summary>
        /// Encrypts the <paramref name="input"/> using DES-ECB algorithm with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <returns>Encrypted data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptDesEcb(this byte[] input, byte[] key, byte[] iv)
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var des = DES.Create();
            des.Key = key;
            des.IV = iv;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;

            return input.EncryptDes(des);
        }

        #endregion

        #region >> EncryptTripleDes *

        /// <summary>
        /// Encrypts the <paramref name="input"/> using <paramref name="tripleDes"/> instance.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="tripleDes">3DES instance.</param>
        /// <returns>Encrypted data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptTripleDes(this byte[] input, TripleDES tripleDes)
        {
            _ = input ?? throw new ArgumentNullException(nameof(input));
            _ = tripleDes ?? throw new ArgumentNullException(nameof(tripleDes));

            using var encryptor = tripleDes.CreateEncryptor();

            return encryptor.TransformFinalBlock(input, 0, input.Length);
        }

        /// <summary>
        /// Encrypts the <paramref name="input"/> using 3DES-CBC algorithm with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">3DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <returns>Encrypted data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptTripleDesCbc(this byte[] input, byte[] key, byte[] iv)
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var tripleDes = TripleDES.Create();
            tripleDes.Key = key;
            tripleDes.IV = iv;
            tripleDes.Mode = CipherMode.CBC;
            tripleDes.Padding = PaddingMode.None;

            return input.EncryptTripleDes(tripleDes);
        }

        /// <summary>
        /// Encrypts the <paramref name="input"/> using 3DES-ECB algorithm with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">3DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <returns>Encrypted data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptTripleDesEcb(this byte[] input, byte[] key, byte[] iv)
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var tripleDes = TripleDES.Create();
            tripleDes.Key = key;
            tripleDes.IV = iv;
            tripleDes.Mode = CipherMode.ECB;
            tripleDes.Padding = PaddingMode.None;

            return input.EncryptTripleDes(tripleDes);
        }

        #endregion

        #region >> GenerateDesMac *

        /// <summary>
        /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using <paramref name="des"/> instance.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="des">DES instance.</param>
        /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
        /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
        /// <returns>MAC value.</returns>
        public static byte[] GenerateDesMac(this byte[] input, DES des, int inputOffset, int inputCount)
        {
            using var encryptor = des.CreateEncryptor();

            var mac = new byte[8];
            des.IV.CopyTo(mac, 0);

            for (var i = 0; i < (inputCount - inputOffset) / 8; i++)
            {
                _ = encryptor.TransformBlock(input, inputOffset + 8 * i, 8, mac, 0);
            }

            return mac;
        }

        /// <summary>
        /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using DES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
        /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
        /// <returns>MAC value.</returns>
        public static byte[] GenerateDesMacCbc(this byte[] input, byte[] key, byte[] iv, int inputOffset, int inputCount)
        {
            using var des = DES.Create();
            des.Key = key;
            des.IV = iv;
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.None;

            return input.GenerateDesMac(des, inputOffset, inputCount);
        }

        #endregion

        #region >> GenerateTripleDesMac *

        /// <summary>
        /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using <paramref name="tripleDES"/> instance.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="tripleDes">3DES instance.</param>
        /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
        /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
        /// <returns>MAC value.</returns>
        public static byte[] GenerateTripleDesMac(this byte[] input, TripleDES tripleDes, int inputOffset, int inputCount)
        {
            _ = tripleDes ?? throw new ArgumentNullException(nameof(tripleDes));

            using var encryptor = tripleDes.CreateEncryptor();

            var mac = new byte[8];
            tripleDes.IV.CopyTo(mac, 0);

            for (var i = 0; i < (inputCount - inputOffset) / 8; i++)
            {
                _ = encryptor.TransformBlock(input, inputOffset + 8 * i, 8, mac, 0);
            }

            return mac;
        }


        /// <summary>
        /// Computes the MAC of <paramref name="input"/> using 3DES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">3DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <returns>MAC value.</returns>
        public static byte[] GenerateTripleDesMacCbc(this byte[] input, byte[] key, byte[] iv)
        {
            return input.GenerateTripleDesMacCbc(key, iv, 0, input.Length);
        }

        /// <summary>
        /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using 3DES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
        /// </summary>
        /// <param name="input">Clear text data.</param>
        /// <param name="key">3DES key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
        /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
        /// <returns>MAC value.</returns>
        public static byte[] GenerateTripleDesMacCbc(this byte[] input, byte[] key, byte[] iv, int inputOffset, int inputCount)
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var tripleDes = TripleDES.Create();
            tripleDes.Key = key;
            tripleDes.IV = iv;
            tripleDes.Mode = CipherMode.CBC;
            tripleDes.Padding = PaddingMode.None;

            return input.GenerateTripleDesMac(tripleDes, inputOffset, inputCount);
        }

        #endregion

        #region >> PadDataForDes

        /// <summary>
        /// Returns a new array consisting of <paramref name="input"/> bytes and a DES padding ('80 00 ... 00')
        /// </summary>
        /// <param name="input">Input data to be padded.</param>
        /// <returns>The padded data.</returns>
        public static byte[] PadDataForDes(this byte[] input)
        {
            return input.AsSpan()
                .PadDataForDes();
        }

        /// <summary>
        /// Returns a new array consisting of <paramref name="input"/> bytes and a DES padding ('80 00 ... 00')
        /// </summary>
        /// <param name="input">Input data to be padded.</param>
        /// <returns>The padded data.</returns>
        public static byte[] PadDataForDes(this Span<byte> input)
        {
            var lastInputBlockLength = input.Length % 8;

            var output = new byte[8 * (input.Length / 8 + 1)];
            input.CopyTo(output);
            Array.Copy(Constants.Padding, 0, output, input.Length, 8 - lastInputBlockLength);

            return output;
        }

        #endregion
    }
}
