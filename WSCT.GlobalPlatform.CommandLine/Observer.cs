using WSCT.Core;
using Microsoft.Extensions.Logging;
using WSCT.GlobalPlatform.CommandLine.Services;

namespace WSCT.GlobalPlatform.CommandLine
{
    class Observer(ILogger<WSCTService> logger)
    {
        ILogger<WSCTService> _logger = logger;

        public void Observe(ICardContextObservable context)
        {
            context.AfterEstablishEvent += (s, args) => _logger.LogInformation("Establish: {ReturnValue}", args.ReturnValue);
            context.AfterListReadersEvent += (s, args) => _logger.LogInformation("ListReaders: {ReturnValue}", args.ReturnValue);
            context.AfterReleaseEvent += (s, args) => _logger.LogInformation("Release: {ReturnValue}", args.ReturnValue);
        }

        public void Observe(ICardChannelObservable channel)
        {
            channel.BeforeTransmitEvent += (s, args) => _logger.LogInformation("Transmit >>>: {Command}", args.Command);
            channel.AfterTransmitEvent += (s, args) => _logger.LogInformation("Transmit <<< : {ReturnValue}, {Response}", args.ReturnValue, args.Response.ToString());
            channel.AfterDisconnectEvent += (s, args) => _logger.LogInformation("Disconnect: {ReturnValue}", args.ReturnValue);
        }
    }
}
