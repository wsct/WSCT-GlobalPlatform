namespace WSCT.GlobalPlatform.ConsoleDemo.Helpers
{
    internal static class LINQPadLikeExtensions
    {
        public static T Dump<T>(this T obj)
        {
            Console.WriteLine(obj);

            return obj;
        }
    }
}
