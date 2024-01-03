use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::str::Utf8Error;
use std::{env, io};

use tokio::net::UdpSocket;

/*
    opcode  operation
    1     Read request (RRQ)
    2     Write request (WRQ)
    3     Data (DATA)
    4     Acknowledgment (ACK)
    5     Error (ERROR)
    6     Option Acknowledgment (OACK)
*/

// len
// 2 ... bytes opcode
// 1 ... at least one byte filename
// 1 ... zero
// 4 ... at least 4 bytes "mail" ("netascii", "octet", or "mail")
// 1 ... zero
// ----------
// 9 ... minimal length of message
//

struct Request<'a> {
    opcode: u16,
    filename: &'a str,
    mode: &'a str,
    tsize : Option<usize>,
    timeout : Option<usize>,
    blksize : Option<usize>
}

#[derive(Debug)]
enum RequestParseError {
    Invalid(String),
    Empty(&'static str),
    FromStrError(&'static str, Utf8Error),
}

fn from_bytes<'a>(
    buf: Option<&'a [u8]>,
    context: &'static str,
) -> Result<&'a str, RequestParseError> {
    let bytes = buf.ok_or(RequestParseError::Empty(context))?;
    
    let utf8string =
        std::str::from_utf8(bytes).map_err(|e| RequestParseError::FromStrError(context, e))?;

    println!("D: bytes {:?}, str: {}", bytes, utf8string);

    Ok(utf8string)
}

fn parse_request(buf: &[u8]) -> Result<Request, RequestParseError> {
    if buf.len() < 9 {
        return Err(RequestParseError::Invalid(format!(
            "request too small. len={}. must be at least 9 bytes", buf.len()).to_owned()));
    }

    if *buf.last().unwrap() != 0 {
        return Err(RequestParseError::Invalid(
            "request does not ends with a zero".to_owned()));
    }

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    if opcode != 1 {
        return Err(RequestParseError::Invalid(format!(
            "only READ REQ is supported. bytes given: {:#X} {:#X} resulted in opcode (u16) {:#X}", 
            buf[0], buf[1], opcode).to_owned()));
    }

    let mut elems = buf[2..buf.len() - 1].split(|&c| c == 0);

    let filename = from_bytes(elems.next(), "filename")?;
    let mode = from_bytes(elems.next(), "mode")?;

    if ! ["octet","mail", "netascii"].contains(&mode) {
        return Err(RequestParseError::Invalid(format!("unsupported mode {}", mode).to_owned()));
    }

    let mut req = Request {
        opcode,
        filename,
        mode,
        tsize: None,
        timeout: None,
        blksize : None
    };

    loop {
        match from_bytes(elems.next(), "options/key") {
            Err(e) =>
                match e {
                    RequestParseError::Empty(_) => break,
                    _ => return Err(e)
                },
            Ok(key) => {

                match from_bytes(elems.next(), "options/value")  {
                    Err(e) =>
                        match e {
                            RequestParseError::Empty(_) => 
                                return Err(RequestParseError::Invalid(format!("option {} has no value set", key).to_owned())),
                            _ => return Err(e)
                        },
                    Ok(value_str) => {
                        match value_str.parse::<usize>() {
                            Err(e) => 
                                return Err(RequestParseError::Invalid(format!("error converting {} to a number. option: {}", value_str, key).to_owned())),
                            Ok(value) => 
                                match key {            
                                    "blksize" => req.blksize = Some(value),
                                    "tsize" => req.tsize = Some(value),
                                    "timeout" => req.timeout = Some(value),
                                    _ => eprintln!("unkown option {} with value {}", key, value_str)
                                }
                        }
                    }
                }
            }
        }   
    }

    Ok(req)
    
}

async fn handle_request(reqlen: usize, buf: Vec<u8>, from: SocketAddr) {
    println!("request from {} with len {}", from, reqlen);
    let reqbytes = &buf[0..reqlen];

    let req = parse_request(reqbytes);

    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Err(e) => {
            eprintln!("handle_request(bind): {}", e);
            return;
        }
        Ok(s) => s,
    };

    if let Err(e) = socket.connect(from).await {
        eprintln!("handle_request(connect): {}", e);
        return;
    }
}

async fn accept_request(addr: SocketAddr) -> Result<(), io::Error> {
    let sock69 = tokio::net::UdpSocket::bind(addr).await?;

    println!("listening: {}", sock69.local_addr()?);

    loop {
        //let (datalen, from) = sock69.recv_from(&mut buf[..]).await?;

        let mut buf: Vec<u8> = vec![0; 1024];

        match sock69.recv_from(&mut buf[..]).await {
            Err(e) => eprintln!("{}", e),
            Ok((buflen, from)) => {
                tokio::spawn(handle_request(buflen, buf, from));
            }
        }
    }
}
#[tokio::main(flavor = "current_thread")] // single-threaded - gives minus 30kB binary
//#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
                    RequestParseError::Invalid(_) => assert!(true),
                    _ => assert!(false)
                },
            Ok(_) => assert!(false)
        }
    }
    #[test]
    fn test_parse_request_invalid_opcode() {
        let buf = [65u8, 66, 0, 48, 0, 0, 41, 42, 0, 80, 47, 0];
        match parse_request(&buf) {
            Err(e) => assert!(matches!(e, RequestParseError::Invalid(_) )),
            Ok(_) => assert!(false)
        }
    }
    #[test]
    fn test_parse_request_wrong_mode() {
        let buf = [0u8, 1, 0, 65, 66, 0, 41, 42, 0, 80, 47, 0];
        match parse_request(&buf) {
            Err(e) => assert!(matches!(e, RequestParseError::Invalid(_) )),
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
                assert!( r.mode.eq("octet"));
            }
        }
    }
}
