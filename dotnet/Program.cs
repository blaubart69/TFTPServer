using Serilog;

namespace TFTPServer
{
    internal class Program
    {
        static void Main(string[] args)
        {   
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Error()
                .WriteTo.Console()
                .CreateLogger();

            Task.WaitAll(TFTP.Start(3, 69));
        }
    }
}