using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TFTPServer
{
    /*
            opcode  operation
            1     Read request (RRQ)
            2     Write request (WRQ)
            3     Data (DATA)
            4     Acknowledgment (ACK)
            5     Error (ERROR)
     */
    enum OPCODE : uint
    {
        RRQ = 1,
        WRQ = 2,
        DATA = 3,
        ACK = 4,
        ERROR = 5
    }
    internal class Request
    {
        public readonly UInt16 opcode;
        public readonly string filename;
        public readonly string mode;
        public Dictionary<string, string>? options;

        public Request(UInt16 opcode, string filename, string mode)
        {
            this.opcode = opcode;
            this.filename = filename;
            this.mode = mode;
        }
    }
    internal class TFTP
    {
        public static Task[] Start(int numberListening, int port)
        {
            return
                Enumerable
                    .Repeat(port, numberListening)
                    .Select(p => AcceptRequest(p))
                    .ToArray();
        }
        static async Task AcceptRequest(int port)
        {
            try
            {
                for (;;)
                {
                    var client = new System.Net.Sockets.UdpClient();
                    //
                    // ReuseAddress AND Bind() are important to have multiple Receives() in flight
                    //
                    client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    client.Client.Bind(new IPEndPoint(IPAddress.Any, port));
                    var request = await client.ReceiveAsync().ConfigureAwait(false);
                    HandleRequest(request, client);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("X: AcceptRequest\n" + ex.Message);
            }
        }
        static async void HandleRequest(UdpReceiveResult receive, UdpClient client)
        {
            try
            {
                string hexPayload = BitConverter.ToString(receive.Buffer).Replace("-", "");
                Console.WriteLine($"request from {receive.RemoteEndPoint}. {receive.Buffer.Length} bytes. {hexPayload}");
                try
                {
                    var request = Parse.ParseRequest(receive.Buffer);
                    PrintRequest(request);
                    var errBuf = CreateError("SCHOD");
                    Console.WriteLine($"sending: {BitConverter.ToString(errBuf).Replace("-", "")}");
                    client.Send(errBuf, errBuf.Length, receive.RemoteEndPoint);
                }
                catch (ParseException pex)
                {
                    Console.Error.WriteLine($"request is malformed. {pex.Message}");
                }
            }
            finally
            {
                client.Close();
            }
        }
        static void PrintRequest(Request request)
        {
            Console.WriteLine(
                $"opcode    {request.opcode}"
            + $"\nfilename  {request.filename}"
            + $"\nmode      {request.mode}");

            if (request.options != null)
            {
                foreach (var opt in request.options)
                {
                    Console.WriteLine($"option: [{opt.Key}]\t[{opt.Value}]");
                }
            }
        }
        /*
           2 bytes     2 bytes      string    1 byte
          -----------------------------------------
         | Opcode |  ErrorCode |   ErrMsg   |   0  |
          -----------------------------------------
                  Figure 5-4: ERROR packet
         */
        static byte[] CreateError(string message)
        {
            var ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);

            var header = new byte[4].AsSpan();
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0,2), (UInt16)OPCODE.ERROR);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2,2), (UInt16)99);
            bw.Write(header);
            bw.Write(Encoding.ASCII.GetBytes(message));
            bw.Write((byte)0);

            return ms.ToArray();
        }
        static void CreateACK()
        {
            ArrayPool<byte>.
        }
    }
}
