namespace WSCT.GlobalPlatform
{
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
    }
}
