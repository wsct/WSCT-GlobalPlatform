using WSCT.Helpers;

namespace WSCT.GlobalPlatform.Security
{
    /// <summary>
    /// Container for the session keys used for the secure channel.
    /// </summary>
    public record SessionKeys(
        /// <summary>Secure Channel C-MAC session key</summary>
        byte[] CMac,
        /// <summary>Secure Channel R-MAC session key</summary>
        byte[] RMac,
        /// <summary>Secure Channel data encryption session key</summary>
        byte[] Enc,
        /// <summary>Secure Channel data decryption session key</summary>
        byte[] Dek
    )
    {
        #region >> Object

        /// <inheritdoc />
        public override string ToString()
        {
            return $"CMac:{CMac.ToHexa()}, RMac:{RMac.ToHexa()}, Enc:{Enc.ToHexa()}, Dek:{Dek.ToHexa()}";
        }

        #endregion
    }
}
