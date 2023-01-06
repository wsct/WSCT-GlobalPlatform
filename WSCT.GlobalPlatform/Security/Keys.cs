using WSCT.Helpers;

namespace WSCT.GlobalPlatform.Security
{
    public record Keys(
        /// <summary>The static Encryption key</summary>
        byte[] Enc,
        /// <summary>The static Message Authentication Code key</summary>
        byte[] Mac,
        /// <summary>The static Data Encryption Key</summary>
        byte[] Dek
    )
    {
        #region >> Object

        /// <inheritdoc />
        public override string ToString()
        {
            return $"Enc:{Enc.ToHexa()}, Mac:{Mac.ToHexa()}, Dek:{Dek.ToHexa()}";
        }

        #endregion
    }
}
