using WSCT.Core.Events;
using WSCT.Core;
using WSCT.Helpers.Linq;

namespace WSCT.GlobalPlatform.ConsoleDemo
{
    class Observer
    {
        public void Observe(ICardContextObservable context)
        {
            context.AfterEstablishEvent += (s, args) => Console.WriteLine($"Establish: {args.ReturnValue}");
            context.AfterListReadersEvent += (s, args) => context.Readers.DoForEach(r => Console.WriteLine(r));
            context.AfterReleaseEvent += AfterRelease;
        }

        public void Observe(ICardChannelObservable channel)
        {
            channel.BeforeTransmitEvent += (s, args) => Console.WriteLine($"Transmit >>>: {args.Command}");
            channel.AfterTransmitEvent += (s, args) => Console.WriteLine($"Transmit <<< : {args.ReturnValue}, {args.Response.ToString()}");
            channel.AfterDisconnectEvent += (s, args) => Console.WriteLine($"Disconnect: {args.ReturnValue}");
        }

        private void AfterRelease(object? sender, AfterReleaseEventArgs args)
        {
            Console.WriteLine($"Release: {args.ReturnValue}");
        }
    }

}
