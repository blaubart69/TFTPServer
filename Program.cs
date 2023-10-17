namespace TFTPServer
{
    internal class Program
    {
        static void Main(string[] args)
        {   
            Task.WaitAll(TFTP.Start(3, 69));
        }
    }
}