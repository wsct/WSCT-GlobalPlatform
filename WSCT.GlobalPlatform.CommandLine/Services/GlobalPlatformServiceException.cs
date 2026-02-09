using System.Diagnostics.CodeAnalysis;

using WSCT.GlobalPlatform;

public class GlobalPlatformServiceException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GlobalPlatformException"/> class.
    /// </summary>
    public GlobalPlatformServiceException() : base()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GlobalPlatformServiceException"/> class.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public GlobalPlatformServiceException(string message) : base(message)
    {
    }

    /// <summary>
    /// Throws a <see cref="GlobalPlatformServiceException"/> if the <see cref="GlobalPlatformCard"/> instance is null.
    /// </summary>
    /// <param name="argument">The <see cref="GlobalPlatformCard"/> instance to check.</param>
    /// <exception cref="GlobalPlatformServiceException"></exception>
    public static void ThrowIfNull([NotNull] GlobalPlatformCard? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformServiceException("gpCard not initialized");
        }
    }
}