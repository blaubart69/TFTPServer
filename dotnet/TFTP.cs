﻿using System.Buffers;
using System.Buffers.Binary;
using System.Net;
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
                    .Select(p => AcceptRequest2(p))
                    .ToArray();
        }
        /*
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
                    try
                    {
                        _ = HandleRequest(request.Buffer.AsMemory<byte>(), request.RemoteEndPoint);
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "HandleRequest failed");
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex,"AcceptRequest");
            }
        }*/
        static async Task AcceptRequest2(int port)
        {
            try
            {
                var socket = new System.Net.Sockets.Socket(SocketType.Dgram, ProtocolType.Udp);

                //
                // ReuseAddress AND Bind() are important to have multiple Receives() in flight
                //
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                var listenEndpoint = new IPEndPoint(IPAddress.Any, port);
                socket.Bind(listenEndpoint);
                Log.Information("TFTP server is listening to: {listenEndpoint}", listenEndpoint);

                for (;;)
                {
                    var buf = new ArraySegment<byte>(new byte[512]);
                    var request = await socket.ReceiveMessageFromAsync(
                        buf, new IPEndPoint(IPAddress.Any, 0)).ConfigureAwait(false);
                        
                    try
                    {
                        var mem = buf.AsMemory<byte>(0, request.ReceivedBytes);
                        Log.Information("REQ from {remote} ({remoteFamily}) received on address/interface {address}/{interface}",
                            request.RemoteEndPoint,
                            request.RemoteEndPoint.AddressFamily,
                            request.PacketInformation.Address,
                            request.PacketInformation.Interface);

                        _ = HandleRequest(mem, (IPEndPoint)request.RemoteEndPoint, request.PacketInformation.Address);
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "HandleRequest failed");
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "AcceptRequest");
            }
        }
        static async Task HandleRequest(ReadOnlyMemory<byte> requestBuf, IPEndPoint client, IPAddress receivedOn)
        {
            UdpClient? socket = null;

            try
            {
                socket = new UdpClient(new IPEndPoint(receivedOn, 0));
                if ( client.Address.IsIPv4MappedToIPv6 )
                {
                    socket.Connect(client.Address.MapToIPv4(), client.Port);
                }
                else
                {
                    socket.Connect(client);
                }
                Log.Debug("connect: {local}->{remote}", socket.Client.LocalEndPoint, socket.Client.RemoteEndPoint);


                var request = Parse.ParseRequest(requestBuf);
                PrintRequest(client, request);

                if (request.opcode != OPCODE.RRQ)
                {
                    await socket.SendAsync(CreateError("server only supports READ", 12));
                }
                else
                {
                    await HandleRead(socket, request, timeout: TimeSpan.FromSeconds(3));
                }
            }
            catch (ParseException pex)
            {
                Log.Error("request is malformed. {ParseException}", pex.Message);
                if ( socket != null )
                {
                    await socket.SendAsync(CreateError($"request is malformed. {pex.Message}", 14));
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "HandleRequest");
            }
            finally
            {
                socket?.Close();
            }
        }
        static async Task HandleRead(UdpClient socket, Request request, TimeSpan timeout)
        {
            try
            {
                using var rdr = new FileStream(request.filename, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
                var tmpWriter = new ArrayBufferWriter<byte>();
                if (request.options == null)
                {
                    // if there are no options, start with DATA block 1
                    //await socket.SendAsync(CreateACK(0, bufWriter));
                }
                else if ( ! await SendBlockWaitForACK(socket, 0, CreateOACK(request.options, rdr.Length, tmpWriter), timeout))
                {
                    // sending/ACKing block 0 failed
                    return;
                }

                int blksize = request.GetBlockSize();
                UInt16 blocknumber = 1;
                
                for (;;)
                {
                    var dataBlock = await CreateDATA(rdr, blocknumber, blksize, tmpWriter);
                    if (!await SendBlockWaitForACK(socket, blocknumber, dataBlock, timeout))
                    {
                        // sending/waiting failed
                    }
                    else if (dataBlock.Length < blksize)
                    {
                        // last block sent
                        Log.Information("transfer success. {filesent} -> {remote}", request.filename, socket.Client.RemoteEndPoint);
                        break;
                    }
                    else
                    {
                        blocknumber += 1;
                    }
                }
            }
            catch (FileNotFoundException)
            {
                Log.Information("File not found: {filenotfound}", request.filename);
                await socket.SendAsync(CreateError("File not found", 2));
            }
        }
        static async Task<bool> SendBlockWaitForACK(UdpClient socket, UInt16 expectedBlocknumber, ReadOnlyMemory<byte> block, TimeSpan timeoutForACK)
        {
            int sentbytes = await socket.SendAsync(block);
            Log.Debug("sent block {blocknumber} ({sentbytes} bytes)", expectedBlocknumber, sentbytes);

            try
            {
                var receiveTask = await socket.ReceiveAsync().WaitAsync(timeoutForACK).ConfigureAwait(false);
                if ( receiveTask.Buffer.Length < 4 )
                {
                    Log.Error("received data is too small. expected: ACK for block {blocknumber}. got {hexBytes}", expectedBlocknumber, bytesToHex(receiveTask.Buffer));
                }
                else
                {
                    return HandleClientAnswer(receiveTask.Buffer.AsMemory<byte>(), expectedBlocknumber);
                }
            }
            catch (TimeoutException)
            {
                Log.Error("did not receive ACK for block {blockNumber} within {timeoutForACK}", expectedBlocknumber, timeoutForACK);
            }

            return false;
        }
        static bool HandleClientAnswer(ReadOnlyMemory<byte> answer, UInt16 expectedBlocknumber)
        {
            OPCODE opcode = (OPCODE)Parse.ReadUInt16BigEndian(answer.Slice(0,2));

            if (opcode == OPCODE.ERROR)
            {
                (UInt16 code, string? message) = Parse.ParseError(answer.Slice(2));
                Log.Error("received error from client. code: {code}, message: {message}");
            }
            else if ( opcode != OPCODE.ACK )
            {
                Log.Error("expected: ACK for block {blockNumber} or ERROR. got {hexBytes}", expectedBlocknumber, bytesToHex(answer.ToArray()));
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
                    Log.Debug("received ACK for block {expectedBlocknumber}", expectedBlocknumber);
                    // finally!
                    return true;
                }
            }

            return false;
        }
        static ReadOnlyMemory<byte> CreateOACK(Dictionary<string,string> options, long filesize, ArrayBufferWriter<byte> writer)
        {
            writer.Clear();
            WriteUInt16((UInt16)OPCODE.OACK, writer);

            foreach ( var opt in options )
            {
                string value;
                if ( "tsize".Equals(opt.Key,StringComparison.OrdinalIgnoreCase) )
                {
                    value = filesize.ToString();
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
           2 bytes    2 bytes      string    1 byte
          -----------------------------------------
         | Opcode |  ErrorCode |   ErrMsg   |   0  |
          -----------------------------------------
                  Figure 5-4: ERROR packet
        */
        static ReadOnlyMemory<byte> CreateError(string message, UInt16 code)
        {
            ArrayBufferWriter<byte> writer = new ArrayBufferWriter<byte>();

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
            StringBuilder sb = new StringBuilder();
            sb.Append($"{request.opcode} from {client}: mode [{request.mode}] filename [{request.filename}]");

            if (request.options != null)
            {
                sb.Append(" options: ");
                sb.Append(String.Join(" ", request.options.Select(opt => $"[{opt.Key} {opt.Value}]")));
            }
            Log.Information("{request}", sb.ToString());
        }
        static string bytesToHex(byte[] buf)
        {
            return BitConverter.ToString(buf).Replace("-", "");
        }
    }
}
