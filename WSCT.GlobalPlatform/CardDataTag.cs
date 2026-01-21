namespace WSCT.GlobalPlatform
{
    internal enum CardDataTag : uint
    {
        /// <summary>
        /// Application tag 0 - Card Management Type and Version.
        /// </summary>
        /// <remarks>
        /// <c>{globalPlatform 2 v}</c>
        /// </remarks>
        ApplicationTag0 = 0x60,
        /// <summary>
        /// Application tag 3 - Card Identification Scheme.
        /// </summary>
        /// <remarks>
        /// <c>{globalPlatform 3}</c>
        /// </remarks>
        ApplicationTag3 = 0x63,
        /// <summary>
        /// Application tag 4 - Secure Channel Protocol of the Issuer Security Domain and its implementation options.
        /// </summary>
        /// <remarks>
        /// <c>{globalPlatform 4 scp i}</c>
        /// </remarks>
        ApplicationTag4 = 0x64,
        /// <summary>
        /// Application tag 5 - Card configuration details.
        /// </summary>
        ApplicationTag5 = 0x65,
        /// <summary>
        /// Application tag 6 - Card / chip details.
        /// </summary>
        ApplicationTag6 = 0x66,
        /// <summary>
        /// Application tag 7 - Issuer Security Domain's Trust Point certificate information.
        /// </summary>
        ApplicationTag7 = 0x67,
        /// <summary>
        /// Application tag 8 - Issuer Security Domain certificate information.
        /// </summary>
        ApplicationTag8 = 0x68
    }
}
