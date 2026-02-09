using System.Diagnostics.CodeAnalysis;

using WSCT.GlobalPlatform.Security;

namespace WSCT.GlobalPlatform;

/// <summary>
/// Exception thrown when a GlobalPlatform error occurs.
/// </summary>
public class GlobalPlatformException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GlobalPlatformException"/> class.
    /// </summary>
    public GlobalPlatformException() : base()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GlobalPlatformException"/> class.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public GlobalPlatformException(string message) : base(message)
    {
    }

    /// <summary>
    /// Throws a <see cref="GlobalPlatformException"/> if the specified argument is null.
    /// </summary>
    /// <param name="argument">The argument to check.</param>
    /// <param name="message">The message to throw with the exception.</param>
    /// <exception cref="GlobalPlatformException"></exception>
    public static void ThrowIfNull([NotNull] object? argument, string message)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException(message);
        }
    }

    /// <summary>
    /// Throws a <see cref="GlobalPlatformException"/> if the <see cref="ISecureChannelProtocol"/> instance is null.
    /// </summary>
    /// <param name="argument">The <see cref="ISecureChannelProtocol"/> instance to check.</param>
    /// <exception cref="GlobalPlatformException"></exception>
    public static void ThrowIfNull([NotNull] ISecureChannelProtocol? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException("SCP not initialized: Call ProcessInitializeUpdate(...) first");
        }
    }

    /// <summary>
    /// Throws a <see cref="GlobalPlatformException"/> if the <see cref="SecureChannelData"/> instance is null.
    /// </summary>
    /// <param name="argument">The <see cref="SecureChannelData"/> instance to check.</param>
    /// <exception cref="GlobalPlatformException"></exception>
    public static void ThrowIfNull([NotNull] SecureChannelData? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException("SCP data not initialized: Call ProcessGetCardData(...) first");
        }
    }

    public static void ThrowIfNull([NotNull] Keys? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException("Keys not initialized: Call CreateSessionKeys(...) first");
        }
    }

    public static void ThrowIfNull([NotNull] CardData? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException("Card data not initialized: Call ProcessGetCardData(...) first");
        }
    }

    /// <summary>
    /// Throws a <see cref="GlobalPlatformException"/> if the <see cref="SessionKeys"/> instance is null.
    /// </summary>
    /// <param name="argument">The <see cref="SessionKeys"/> instance to check.</param>
    /// <exception cref="GlobalPlatformException"></exception>
    public static void ThrowIfNull([NotNull] SessionKeys? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException("Session keys not initialized: Call GenerateSessionKeys(...) first");
        }
    }

    /// <summary>
    /// Throws a <see cref="GlobalPlatformException"/> if the <see cref="ISecureChannelSpecifics"/> instance is null.
    /// </summary>
    /// <param name="argument">The <see cref="ISecureChannelSpecifics"/> instance to check.</param>
    /// <exception cref="GlobalPlatformException"></exception>
    public static void ThrowIfNull([NotNull] ISecureChannelSpecifics? argument)
    {
        if (argument is null)
        {
            throw new GlobalPlatformException("Something went wrong: SCP02 specific data is missing");
        }
    }
}
