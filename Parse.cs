using System.Buffers;
using System.Text;

namespace TFTPServer
{
    internal class Parse
    {
        public static Request ParseRequest(ReadOnlyMemory<byte> buffer)
        {
            // len
            // 2 ... bytes opcode
            // 1 ... at least one byte
            // 1 ... zero
            // 4 ... at least 4 bytes "mail" ("netascii", "octet", or "mail")
            // 1 ... zero
            // ----------
            // 9 ... minimal length of message
            //

            if (buffer.Length < 9)
            {
                throw new ParseException($"request length is {buffer.Length} bytes. minimal length is 9");
            }

            var seq = new ReadOnlySequence<byte>(buffer);
            SequenceReader<byte> rdr = new SequenceReader<byte>(seq);

            rdr.TryReadBigEndian(out short sopcode);
            UInt16 opcode = (ushort)sopcode;

            string filename = ReadNextField(ref rdr, "filename") ?? throw new ParseException("filename is missing");
            string mode     = ReadNextField(ref rdr, "mode")     ?? throw new ParseException("mode is missing");

            var request = new Request(opcode, filename, mode);
            request.options = ParseOptionKeyValues(ref rdr);

            return request;
        }
        static string? ReadNextField(ref SequenceReader<byte> rdr, string context)
        {
            if (!rdr.TryReadTo(
                out ReadOnlySpan<byte> field
                , delimiter: 0
                , advancePastDelimiter: true))
            {
                return null;
            }
            else if (field.Length == 0)
            {
                throw new ParseException($"{context} is empty");
            }
            else
            {
                return Encoding.ASCII.GetString(field);
            }
        }
        static Dictionary<string, string>? ParseOptionKeyValues(ref SequenceReader<byte> rdr)
        {
            Dictionary<string, string>? options = null;

            while (true)
            {
                var key = ReadNextField(ref rdr, "optionkey");
                if (key == null)
                {
                    break;
                }
                else
                {
                    var value = ReadNextField(ref rdr, "optionvalue");
                    if (value == null)
                    {
                        throw new ParseException($"value for option key {key} is missing");
                    }
                    if (options == null)
                    {
                        options = new Dictionary<string, string>();
                    }
                    options.Add(key, value);
                }
            }
            return options;
        }
    }
}
