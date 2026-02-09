namespace WSCT.GlobalPlatform.Security;

/// <summary>
/// The secure channel protocol details - 2 bytes (SCPxx, i).
/// </summary>
public record SecureChannelProtocolDetails(
    /// <summary>
    /// The identifier (SCPxx) of the secure channel protocol.
    /// </summary>
    byte Identifier,
    /// <summary>
    /// The options (i) of the secure channel protocol.
    /// </summary>
    byte Options)
{
    /// <summary>
    /// Creates a new instance of <see cref="SecureChannelProtocolDetails"/> from the specified 2 bytes.
    /// </summary>
    /// <param name="scpBytes">The 2 bytes of the secure channel protocol.</param>
    /// <returns>A new instance of <see cref="SecureChannelProtocolDetails"/>.</returns>
    public static SecureChannelProtocolDetails Create(Span<byte> scpBytes)
    {
        if (scpBytes.Length != 2)
        {
            throw new ArgumentOutOfRangeException(nameof(scpBytes), "Should be 2 bytes long");
        }

        return new SecureChannelProtocolDetails(scpBytes[0], scpBytes[1]);
    }

    #region >> Object

    /// <inheritdoc />
    public override string ToString()
    {
        return $"SCP{Identifier:X2}.i={Options:X2}";
    }

    #endregion
}
