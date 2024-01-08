use std::error::Error;
use std::net::{SocketAddr};
use std::str::Utf8Error;
use std::time::Duration;
use std::{env, io};

use tokio::io::AsyncReadExt;

use thiserror::Error;

/*
    opcode  operation
    1     Read request (RRQ)
    2     Write request (WRQ)
    3     Data (DATA)
    4     Acknowledgment (ACK)
    5     Error (ERROR)
    6     Option Acknowledgment (OACK)
*/
/*
enum OPCODE
{
    RRQ   = 1,
    WRQ   = 2,
    DATA  = 3,
    ACK   = 4,
    ERROR = 5,
    OACK  = 6
}*/

#[non_exhaustive]
struct OpCode;

impl OpCode {
    pub const READ  : u16 = 1;
    pub const WRITE : u16 = 2; 
    pub const DATA  : u16 = 3;
    pub const ACK   : u16 = 4;
    pub const ERROR : u16 = 5;
    pub const OACK  : u16 = 6;
}

// len
// 2 ... bytes opcode
// 1 ... at least one byte filename
// 1 ... zero
// 4 ... at least 4 bytes "mail" ("netascii", "octet", or "mail")
// 1 ... zero
// ----------
// 9 ... minimal length of message
//

struct Options {
    tsize   : Option<usize>,
    timeout : Option<usize>,
    blksize : Option<usize>
}

fn fmt_option(option : &Option<usize>) -> String {
    option.map_or("None".to_owned(), |val| val.to_string())
}

impl std::fmt::Display for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"blksize: {}, tsize: {}, timeout: {}"
            , fmt_option(&self.blksize)
            , fmt_option(&self.tsize)
            , fmt_option(&self.timeout)
            )
    }
}

impl Options {
    fn any_option_given(&self) -> bool {
        let empty = Options::empty();

        ! (    
               self.blksize.eq( &empty.blksize )
            && self.tsize.eq  ( &empty.tsize )
            && self.timeout.eq( &empty.timeout )
        )
    }

    fn empty() -> Options {
        Options {
            blksize : None,
            tsize : None,
            timeout : None
        }
    }
}

struct Request {
    opcode: u16,
    filename: String,
    //mode: &'a str,
    options : Options
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f,"opcode: {}, mode: octet, filename: {}, options [{}]", 
            self.opcode
            , self.filename
            , self.options)
    }
}

#[derive(Error,Debug)]
enum ParseError {
    #[error("invalid option: {0}")]
    Invalid(String),

    #[error("empty option: {0}")]
    Empty(&'static str),

    #[error("cannot convert option to UTF8. context: {context}, err: {utf8_error}")]
    FromStrError {
        context : &'static str, 
        utf8_error : Utf8Error
    },
    #[error("could not parse error message from client: {0}")]
    ErrorMessage(String)
}

#[derive(Error,Debug)]
enum TransferError {
    #[error("client answer is too small. only {0} bytes")]
    AnswerTooSmall(usize),
    #[error("client sent error. code {0} message {1}")]
    ClientError(u16,String),
    #[error("unexpected answer from client. expected was: {0}")]
    Unexpected(String),
    #[error("unexpected ACK for block {got}. expected: {expected}")]
    UnexpectedBlock {
        got: u16,
        expected: u16
    }
}


fn from_bytes<'a>(
    buf: Option<&'a [u8]>,
    context: &'static str,
) -> Result<&'a str, ParseError> {
    let bytes = 
        buf.ok_or(ParseError::Empty(context))?;
    
    let utf8string =
        std::str::from_utf8(bytes)
        .map_err(|utf8_error| 
            ParseError::FromStrError { context, utf8_error } )?;

    //println!("D: bytes {:?}, str: {}", bytes, utf8string);

    Ok(utf8string)
}

fn parse_request(buf: &[u8]) -> Result<Request, ParseError> {

    if buf.len() < 9 {
        return Err(ParseError::Invalid(format!(
            "request too small. len={}. must be at least 9 bytes", buf.len()).to_owned()));
    }

    if *buf.last().unwrap() != 0 {
        return Err(ParseError::Invalid(
            "request does not ends with a zero".to_owned()));
    }

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    if opcode != 1 {
        return Err(ParseError::Invalid(format!(
            "only READ REQ is supported. bytes given: {:#X} {:#X} resulted in opcode (u16) {:#X}", 
            buf[0], buf[1], opcode).to_owned()));
    }

    let mut elems = buf[2..buf.len() - 1].split(|&c| c == 0);

    let filename = from_bytes(elems.next(), "filename")?.to_owned();
    let mode = from_bytes(elems.next(), "mode")?;

    //if ! ["octet","mail", "netascii"].contains(&mode) {
    if ! ["octet"].contains(&mode) {
        return Err(ParseError::Invalid(format!("unsupported mode {}", mode).to_owned()));
    }

    let mut req = Request {
        opcode,
        filename,
        options : Options::empty()
    };

    loop {
        match from_bytes(elems.next(), "options/key") {
            Err(e) =>
                match e {
                    ParseError::Empty(_) => break,
                    _ => return Err(e)
                },
            Ok(option_name) => {

                match from_bytes(elems.next(), "options/value")  {
                    Err(e) =>
                        match e {
                            ParseError::Empty(_) => 
                                return Err(ParseError::Invalid(format!("option {} has no value set", option_name).to_owned())),
                            _ => return Err(e)
                        },
                    Ok(value_str) => {
                        match value_str.parse::<usize>() {
                            Err(e) => 
                                return Err(ParseError::Invalid(format!("error converting {} to a number. option: {}, error {}", value_str, option_name, e).to_owned())),
                            Ok(value) => {
                                match option_name {            
                                    "blksize"   => req.options.blksize = Some(value),
                                    "tsize"     => req.options.tsize   = Some(value),
                                    "timeout"   => req.options.timeout = Some(value),
                                    _ => eprintln!("unkown option {} with value {}", option_name, value)
                                }
                            }
                        }
                    }
                }
            }
        }   
    }

    Ok(req)
    
}

/*
2 bytes     2 bytes      string    1 byte
 -----------------------------------------
| Opcode |  ErrorCode |   ErrMsg   |   0  |
 -----------------------------------------

        Figure 5-4: ERROR packet
*/
fn parse_error(buf : &[u8]) -> Result<(u16,String),ParseError> {
    if buf.len() < 4 {
        Err(ParseError::ErrorMessage(format!("too small. got only {} bytes (without opcode)", buf.len())))
    } 
    else {
        let code = u16::from_be_bytes([buf[0], buf[1]]);
        let message = String::from_utf8_lossy(&buf[2..buf.len()-1]).to_string();
        Ok((code,message))
    }
}
async fn create_oack(mut buf: &mut Vec<u8>, opts : &Options, filename : &str) -> Result<(),Box<dyn Error>> {
    buf.clear();
    
    buf.extend_from_slice(OpCode::OACK.to_be_bytes().as_ref());

    use std::io::Write;

    if let Some(blksize) = opts.blksize {
        write!(buf,"blksize\0{}\0", blksize)?;    
    }

    if let Some(tsize) = opts.tsize {
        let meta = tokio::fs::metadata(filename).await?;
        write!(buf,"tsize\0{}\0", meta.len())?;    
    }

    if let Some(timeout) = opts.timeout {
        write!(buf,"timeout\0{}\0", timeout)?;    
    }

    Ok(())
}

async fn create_data(buf: &mut Vec<u8>, block_number : u16,  blocksize : usize, reader : &mut tokio::fs::File) -> Result<usize,io::Error> {
    buf.clear();
    buf.extend_from_slice(OpCode::DATA.to_be_bytes().as_ref());
    buf.extend_from_slice(block_number.to_be_bytes().as_ref());
    let header_only_len = buf.len();

    buf.resize( header_only_len + blocksize, 0);

    let bytes_read = reader.read( &mut buf[header_only_len..] ).await?;

    buf.resize(header_only_len + bytes_read, 0);

    Ok(bytes_read)
}

async fn send_block_wait_for_ack( buf: &mut Vec<u8>, expected_block_number : u16, socket: &tokio::net::UdpSocket) -> Result<(),Box<dyn Error>> {
    socket.send(buf.as_slice()).await?;

    let bytes_received = tokio::time::timeout( 
        Duration::from_secs(3)
        , socket.recv(&mut buf[..])).await??;

    if bytes_received < 4 {
        Err(TransferError::AnswerTooSmall(bytes_received))?
    }
    else        
    {
        let answer = &buf[0..bytes_received];
        let client_opcode = u16::from_be_bytes([answer[0], answer[1]]);
        if client_opcode == OpCode::ERROR {
            let (code,message) = parse_error(&answer[2..])?;
            Err(TransferError::ClientError(code,message))?
        }
        else if client_opcode != OpCode::ACK {
            Err(TransferError::Unexpected(format!("ACK or ERR")))?
        }
        else {
            /*
            2 bytes     2 bytes
            ---------------------
            | Opcode |   Block #  |  Figure 5-3: ACK packet
            ---------------------
            */
            let ack_for_block = u16::from_be_bytes([answer[2], answer[3]]);
            if ack_for_block != expected_block_number {
                Err(TransferError::UnexpectedBlock { got : ack_for_block, expected: expected_block_number })?
            }
            else {
                // FINALLY - a richtige Auntwurt!
                Ok(())
            }
        }
    }
    
}

async fn handle_request(reqlen: usize, mut buf: Vec<u8>, socket: tokio::net::UdpSocket) -> Result<(),Box<dyn Error>> {

    let req = {
        let reqbytes = &buf[0..reqlen];
        parse_request(reqbytes)?
    };

    println!("{} - {}", socket.peer_addr()?, req);
    
    let mut file_reader = tokio::fs::File::options()
        .read(true)
        .open(req.filename.as_str())
        .await?;

    if req.options.any_option_given() {
        create_oack(&mut buf, &req.options, req.filename.as_str() ).await?;
        send_block_wait_for_ack(&mut buf, 0, &socket).await?;
    }

    let mut block_number : u16 = 1;
    let blocksize = req.options.blksize.unwrap_or(512);

    loop {
        let bytes_read = create_data(&mut buf, block_number, blocksize, &mut file_reader).await?;
        send_block_wait_for_ack(&mut buf, block_number, &socket).await?;

        if bytes_read < blocksize {
            println!("{} - finished transfer of file {}", socket.peer_addr()?, req.filename);
            break;
        }
        else {
            block_number += 1;
        }
    }

    Ok(())
}

async fn main_request(buflen: usize, buf: Vec<u8>, from: SocketAddr) {

    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Err(e) => { 
            eprintln!("bind failed. {}", e);
            return;
        },
        Ok(s) => s
    };

    if let Err(e) = socket.connect(from).await {
        eprintln!("connect failed. {}", e);
        return;
    }

    if let Err(e) = handle_request(buflen, buf, socket).await {
        eprintln!("req from {} resulted in {}", from, e);
    }
}

async fn accept_request(addr: SocketAddr) -> Result<(), io::Error> {
    let sock69 = tokio::net::UdpSocket::bind(addr).await?;

    println!("listening: {}", sock69.local_addr()?);

    loop {
        let mut buf: Vec<u8> = vec![0; 1024];

        match sock69.recv_from(&mut buf[..]).await {
            Err(e) => eprintln!("{}", e),
            Ok((buflen, from)) => {
                tokio::spawn( main_request(buflen, buf, from) );
            }
        }
    }
}
#[tokio::main(flavor = "current_thread")] // single-threaded - gives minus 30kB binary
//#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let str_ip = env::args().nth(1).unwrap_or_else(|| "0.0.0.0".to_string());

    let ip = str_ip.parse()?;

    let sock_addr = std::net::SocketAddr::new(ip, 69);
    accept_request(sock_addr).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::matches;

    #[test]
    fn test_parse_request_doesnt_end_with_zero() {
        let buf = [65u8, 66, 0, 48, 0, 0, 41, 42, 0, 80, 47];
        match parse_request(&buf) {
            Err(e) => 
                match e {
                    ParseError::Invalid(_) => assert!(true),
                    _ => assert!(false)
                },
            Ok(_) => assert!(false)
        }
    }
    #[test]
    fn test_parse_request_invalid_opcode() {
        let buf = [65u8, 66, 0, 48, 0, 0, 41, 42, 0, 80, 47, 0];
        match parse_request(&buf) {
            Err(e) => assert!(matches!(e, ParseError::Invalid(_) )),
            Ok(_) => assert!(false)
        }
    }
    #[test]
    fn test_parse_request_wrong_mode() {
        let buf = [0u8, 1, 0, 65, 66, 0, 41, 42, 0, 80, 47, 0];
        match parse_request(&buf) {
            Err(e) => assert!(matches!(e, ParseError::Invalid(_) )),
            Ok(_) => assert!(false)
        }
    }
    #[test]
    fn test_parse_request_minimal() {
        // "octet" == 6F 63 74 65 74
        let buf = [0u8, 1, 0x41, 0x42, 0x43, 0, 0x6F, 0x63, 0x74, 0x65, 0x74, 0];
        match parse_request(&buf) {
            Err(e) => assert!(false),
            Ok(r) => {
                assert!( r.filename.eq("ABC"), "actual {}", r.filename );
                //assert!( r.mode.eq("octet"));
            }
        }
    }
    #[tokio::test]
    async fn test_create_oack() {
        let mut buf = Vec::<u8>::new();

        create_oack(&mut buf, 
            &Options {
                  blksize : Some(1024)
                , timeout : None
                , tsize   : None }, "dummy").await.unwrap();

        assert!(buf.len() > 0);
        assert_eq!(OpCode::OACK, u16::from_be_bytes([buf[0], buf[1]]));
        
        let mut elems = buf[2..buf.len() - 1].split(|&c| c == 0);
        
        assert_eq!("blksize", from_bytes( elems.next(), "blksize key").unwrap());
        assert_eq!("1024", from_bytes( elems.next(), "blksize value").unwrap());
        assert!( matches!( from_bytes(elems.next(), "end").unwrap_err(), ParseError::Empty(_)) );
    }

}
