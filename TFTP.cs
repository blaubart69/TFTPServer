//using CommunityToolkit.HighPerformance;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using Serilog;

namespace TFTPServer
{
    /*
            opcode  operation
            1     Read request (RRQ)
            2     Write request (WRQ)
            3     Data (DATA)
            4     Acknowledgment (ACK)
            5     Error (ERROR)
            6     Option Acknowledgment (OACK)
     */
    enum OPCODE : uint
    {
        RRQ = 1,
        WRQ = 2,
        DATA = 3,
        ACK = 4,
        ERROR = 5,
        OACK = 6
    }
    internal class Request
    {
        public readonly OPCODE opcode;
        public readonly string filename;
        public readonly string mode;
        public Dictionary<string, string>? options;

        public Request(UInt16 opcode, string filename, string mode)
        {
            this.opcode = (OPCODE)opcode;
            this.filename = filename;
            this.mode = mode;
        }
        public int GetBlockSize()
        {
            if (options == null)
            {
                return 512;
            }
            else if ( ! options.TryGetValue("blksize", out string? strBlksize) )
            {
                return 512;
            }
            else
            {
                return Convert.ToInt32(strBlksize);
            }
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
                var socket = new System.Net.Sockets.UdpClient();
                //
                // ReuseAddress AND Bind() are important to have multiple Receives() in flight
                //
                socket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                var listenEndpoint = new IPEndPoint(IPAddress.Any, port);
                socket.Client.Bind(listenEndpoint);
                Log.Information("TFTP server is listening to: {listenEndpoint}",listenEndpoint);

                for (;;)
                {
                    var request = await socket.ReceiveAsync().ConfigureAwait(false);
                    ReadOnlyMemory<byte> requestMem = request.Buffer.AsMemory<byte>();
                    HandleRequest(request.Buffer.AsMemory<byte>(), request.RemoteEndPoint);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex,"AcceptRequest");
            }
        }
        static async Task HandleRequest(ReadOnlyMemory<byte> requestBuf, IPEndPoint client)
        {
            var tmpWriter = new ArrayBufferWriter<byte>();
            using var socket = new UdpClient();
            socket.Connect(client);

            try
            {
                var timeout = TimeSpan.FromSeconds(3);
                var request = Parse.ParseRequest(requestBuf);
                PrintRequest(client, request);

                if (request.opcode != OPCODE.RRQ)
                {
                    await socket.SendAsync(CreateError("server only supports READ", 12, tmpWriter));
                }
                else if (!File.Exists(request.filename))
                {
                    await socket.SendAsync(CreateError("File not found", 2, tmpWriter));
                }
                else
                {
                    if (request.options == null)
                    {
                        // if there are no options, start with DATA block 1
                        //await socket.SendAsync(CreateACK(0, bufWriter));
                    }
                    else if ( ! await SendBlockWaitForACK(socket, 0, CreateOACK(request, tmpWriter), timeout))
                    {
                        // sending/ACKing block 0 failed
                    }
                    else
                    {
                        using (var rdr = new FileStream(request.filename, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
                        {
                            int blksize = request.GetBlockSize();
                            UInt16 blocknumber = 1;
                            for (;;)
                            {
                                var dataBlock = await CreateDATA(rdr, blocknumber, blksize, tmpWriter);
                                if ( ! await SendBlockWaitForACK(socket, blocknumber, dataBlock, timeout) )
                                {
                                    // sending/waiting failed
                                }
                                else if ( dataBlock.Length < blksize )
                                {
                                    // last block sent
                                    Log.Information("transfer success.");
                                    break;
                                }
                                else
                                {
                                    blocknumber += 1;
                                }
                            }
                        }
                    }
                }
            }
            catch (ParseException pex)
            {
                Log.Error("request is malformed. {ParseException}", pex.Message);
                await socket.SendAsync(CreateError($"request is malformed. {pex.Message}", 14, tmpWriter));
            }
            finally
            {
                socket.Close();
            }
        }
        static async Task<bool> SendBlockWaitForACK(UdpClient socket, UInt16 expectedBlocknumber, ReadOnlyMemory<byte> block, TimeSpan timeoutForACK)
        {
            int sentbytes = await socket.SendAsync(block);
            Log.Debug("sent block {blocknumber} ({sentbytes} bytes)", expectedBlocknumber, sentbytes);

            var receiveTask = socket.ReceiveAsync();
            if ( ! receiveTask.Wait( timeoutForACK ) )
            {
                Log.Error("did not receive ACK for block {blockNumber} within {timeoutForACK}", expectedBlocknumber, timeoutForACK);
            }
            else if ( receiveTask.Result.Buffer.Length < 4 )
            {
                Log.Error("received data is too small. expected: ACK for block {blocknumber}. got {hexBytes}", expectedBlocknumber, bytesToHex(receiveTask.Result.Buffer));
            }
            else
            {
                ReadOnlyMemory<byte> answer = receiveTask.Result.Buffer.AsMemory<byte>();
                OPCODE opcode = (OPCODE)Parse.ReadUInt16BigEndian(answer.Slice(0,2));

                if (opcode == OPCODE.ERROR)
                {
                    (UInt16 code, string? message) = Parse.ParseError(answer.Slice(2));
                    Log.Error("received error from client. code: {code}, message: {message}");
                }
                else if ( opcode != OPCODE.ACK )
                {
                     Log.Error("expected: ACK for block {blockNumber} or ERROR. got {hexBytes}", expectedBlocknumber, bytesToHex(receiveTask.Result.Buffer));
                }
                else 
                {
                    UInt16 ackForBlock = Parse.ReadUInt16BigEndian(answer.Slice(2, 2));
                    if ( ackForBlock != expectedBlocknumber ) 
                    {
                        Log.Error("expected: ACK for block {blockNumber}. received ACK for block {ackForBlock}.", expectedBlocknumber, ackForBlock);
                    }
                    else
                    {
                        // finally!
                        return true;
                    }
                }
            }
            return false;
        }
        static ReadOnlyMemory<byte> CreateOACK(Request request, ArrayBufferWriter<byte> writer)
        {
            writer.Clear();
            WriteUInt16((UInt16)OPCODE.OACK, writer);

            foreach ( var opt in request.options)
            {
                string value;
                if ( "tsize".Equals(opt.Key,StringComparison.OrdinalIgnoreCase) )
                {
                    value = new FileInfo(request.filename).Length.ToString();
                }
                else
                {
                    value = opt.Value;
                }
                Encoding.ASCII.GetBytes(opt.Key.AsSpan(), writer);
                WriteByte(0, writer);
                Encoding.ASCII.GetBytes(value.AsSpan(), writer);
                WriteByte(0, writer);
            }

            return writer.WrittenMemory;
        }
        static async Task<ReadOnlyMemory<byte>> CreateDATA(FileStream rdr, UInt16 blocknumber, int blksize, ArrayBufferWriter<byte> writer)
        {
            writer.Clear();
            
            var header = writer.GetMemory(4);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2).Span, (UInt16)OPCODE.DATA);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2).Span,         blocknumber);
            writer.Advance(4);

            var mem = writer.GetMemory(blksize);
            int bytesRead = await rdr.ReadAsync(mem.Slice(0, length: blksize));
            writer.Advance(bytesRead);

            return writer.WrittenMemory;
        }
        static ReadOnlyMemory<byte> CreateACK(UInt16 blocknumber, ArrayBufferWriter<byte> writer)
        {
            writer.Clear();
            var header = writer.GetSpan(4);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2), (UInt16)OPCODE.ACK);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), (UInt16)blocknumber);
            writer.Advance(4);
            return writer.WrittenMemory;
        }
        /*
           2 bytes     2 bytes      string    1 byte
          -----------------------------------------
         | Opcode |  ErrorCode |   ErrMsg   |   0  |
          -----------------------------------------
                  Figure 5-4: ERROR packet
        */
        static ReadOnlyMemory<byte> CreateError(string message, UInt16 code, ArrayBufferWriter<byte> writer)
        {
            writer.Clear();

            var header = writer.GetSpan(4);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2), (UInt16)OPCODE.ERROR);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), (UInt16)code);
            writer.Advance(4);
            
            Encoding.ASCII.GetBytes(message.AsSpan(), writer);

            byte Zero = 0;
            writer.Write(new Span<byte>(ref Zero));
            return writer.WrittenMemory;
        }
        static void WriteUInt16(UInt16 value, ArrayBufferWriter<byte> writer)
        {
            var header = writer.GetSpan(2);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2), value);
            writer.Advance(2);
        }
        static void WriteByte(byte value, ArrayBufferWriter<byte> writer)
        {
            var data = new Span<byte>(ref value);
            writer.Write(data);
        }
        static void PrintRequest(IPEndPoint client, Request request)
        {
            Console.WriteLine($"{request.opcode} from {client}: mode [{request.mode}] filename [{request.filename}]");

            if (request.options != null)
            {
                foreach (var opt in request.options)
                {
                    Console.WriteLine($"  option: [{opt.Key}]\t[{opt.Value}]");
                }
            }
        }
        static string bytesToHex(byte[] buf)
        {
            return BitConverter.ToString(buf).Replace("-", "");
        }
                static async Task ___HandleReadRequest(UdpClient client, FileStream rdr, int blksize, ArrayBufferWriter<byte> buf)
        {
            UInt16 blockNumber = 0;
            UInt64 dataBytesSent = 0;
            //int? lastBytesRead = null;
            int? bytesRead = null;

            for (;;)
            {
                // wait for the ACK of the block
                var receiveTask = client.ReceiveAsync();
                if ( ! receiveTask.Wait( millisecondsTimeout: 3000 ) )
                {
                    Log.Error("did not receive ACK for block #{blockNumber}", blockNumber);
                    break;
                }
                else if ( receiveTask.Result.Buffer.Length < 4 )
                {
                    Console.Error.WriteLine($"received data is too small. expected: ACK for block# {blockNumber}. got {bytesToHex(receiveTask.Result.Buffer)}");
                    break;
                }
                else
                {
                    ReadOnlyMemory<byte> answer = receiveTask.Result.Buffer.AsMemory<byte>();
                    OPCODE opcode = (OPCODE)Parse.ReadUInt16BigEndian(answer.Slice(0,2));

                    if (opcode == OPCODE.ERROR)
                    {
                        (UInt16 code, string? message) = Parse.ParseError(answer.Slice(2));
                        Console.Error.WriteLine($"received error from client. code: {code}, message: {message}");
                        break;
                    }
                    else if ( opcode == OPCODE.ACK )
                    {
                        UInt16 ackForBlock = Parse.ReadUInt16BigEndian(answer.Slice(2, 2));
                        if ( ackForBlock != blockNumber ) 
                        {
                            Console.Error.WriteLine($"expected: ACK for block {blockNumber}. received ACK for block# {ackForBlock}.");
                            break;
                        }
                        else if ( bytesRead.HasValue && bytesRead.Value < blksize)
                        {
                            // ACK for the last data packet
                            Console.WriteLine($"transfer finished. client {client.Client.RemoteEndPoint}, bytes {dataBytesSent}, blksize {blksize}");
                            break;
                        }
                        else
                        { 
                            blockNumber += 1;
                            buf.Clear();
                            var header = buf.GetMemory(4);
                            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2).Span, (UInt16)OPCODE.DATA);
                            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2).Span,         blockNumber);
                            buf.Advance(4);
                            var mem = buf.GetMemory(blksize);
                            bytesRead = await rdr.ReadAsync(mem.Slice(0, length: blksize));
                            buf.Advance(bytesRead.Value);

                            int sentbytes = await client.SendAsync(buf.WrittenMemory);
                            Console.WriteLine($"sent block {blockNumber}. {sentbytes-4} bytes of data");
                        }
                    }
                    else
                    {
                        Console.Error.WriteLine($"expected: ACK for block {blockNumber} or ERROR. got {bytesToHex(receiveTask.Result.Buffer)}");
                        break;
                    }
                }
            }
        }

    }
}
