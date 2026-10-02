using WSCT.Stack;

namespace WSCT.Layers.GlobalPlatform
{
    public class CardChannelLayer : CardChannelLayerObservable
    {
        public CardChannelLayer()
            : base(new CardChannelLayerBase())
        {
        }
    }
}