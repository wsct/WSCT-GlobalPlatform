using WSCT.Core;
using WSCT.Core.APDU;
using WSCT.ISO7816;
using WSCT.ISO7816.Commands;
using WSCT.Stack;
using WSCT.Wrapper;

namespace WSCT.Layers.GlobalPlatform
{
    internal class CardChannelLayerBase : ICardChannelLayer
    {
        #region >> Fields

        private ICardChannelStack stack;

        #endregion

        #region >> ICardChannelLayer

        /// <inheritdoc />
        public void SetStack(ICardChannelStack stack)
        {
            this.stack = stack;
        }

        /// <inheritdoc />
        public string LayerId
        {
            get { return "GP"; }
        }

        #endregion

        #region >> ICardChannel

        /// <inheritdoc />
        public Protocol Protocol
        {
            get { return stack.RequestLayer(this, SearchMode.Next).Protocol; }
        }

        /// <inheritdoc />
        public string ReaderName
        {
            get { return stack.RequestLayer(this, SearchMode.Next).ReaderName; }
        }

        /// <inheritdoc />
        public void Attach(ICardContext context, string readerName)
        {
            stack.RequestLayer(this, SearchMode.Next).Attach(context, readerName);
        }

        /// <inheritdoc />
        public ErrorCode Connect(ShareMode shareMode, Protocol preferedProtocol)
        {
            // Next channel layer needs to be stored for use at GlobalPlatformCard creation time.
            GlobalPlatformController.NextChannelLayer = stack.RequestLayer(this, SearchMode.Next);

            return stack.RequestLayer(this, SearchMode.Next).Connect(shareMode, preferedProtocol);
        }

        /// <inheritdoc />
        public ErrorCode Disconnect(Disposition disposition)
        {
            return stack.RequestLayer(this, SearchMode.Next).Disconnect(disposition);
        }

        /// <inheritdoc />
        public ErrorCode GetAttrib(Attrib attrib, ref byte[] buffer)
        {
            return stack.RequestLayer(this, SearchMode.Next).GetAttrib(attrib, ref buffer);
        }

        /// <inheritdoc />
        public State GetStatus()
        {
            return stack.RequestLayer(this, SearchMode.Next).GetStatus();
        }

        /// <inheritdoc />
        public ErrorCode Reconnect(ShareMode shareMode, Protocol preferedProtocol, Disposition initialization)
        {
            if (GlobalPlatformController.IsLayerActive == true)
            {
                GlobalPlatformController.NextChannelLayer = stack.RequestLayer(this, SearchMode.Next);
            }

            return stack.RequestLayer(this, SearchMode.Next).Reconnect(shareMode, preferedProtocol, initialization);
        }

        /// <inheritdoc />
        public ErrorCode Transmit(ICardCommand command, ICardResponse response)
        {
            if (GlobalPlatformController.IsLayerActive == false)
            {
                return stack.RequestLayer(this, SearchMode.Next).Transmit(command, response);
            }

            if (GlobalPlatformController.GpCard is null)
            {
                GlobalPlatformController.GpCard = new WSCT.GlobalPlatform.GlobalPlatformCard(stack.RequestLayer(this, SearchMode.Next));
            }

            if (command is not CommandAPDU command7816 || response is not ResponseAPDU response7816)
            {
                return stack.RequestLayer(this, SearchMode.Next).Transmit(command, response);
            }

            // if Security bit is set in CLA
            if ((command7816.Cla & 0x04) == 0x04)
            {
                // TODO : Implement the security layer for GlobalPlatform commands
                var gpResponse = GlobalPlatformController.GpCard.ProcessCommand(command7816).RApdu;

                if (gpResponse != null)
                {
                    response.Parse([.. gpResponse.Udr, gpResponse.Sw1, gpResponse.Sw2]);
                }

                return ErrorCode.Success;
            }

            return stack.RequestLayer(this, SearchMode.Next).Transmit(command, response);
        }

        #endregion
    }
}