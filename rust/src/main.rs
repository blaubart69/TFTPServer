use std::error::Error;
use std::net::{SocketAddr, IpAddr};
use std::{env,io};

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

async fn handle_request(buflen : usize, buf : Vec<u8>, from : SocketAddr) {
	println!("request from {} with len {}", from, buflen);
	let req = &buf[0..buflen];

	let s1 = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
		Err(e) => { eprintln!("handle_request(bind): {}",e); return; },
		Ok(s) => s
	};

	if let Err(e) = s1.connect(from).await {
		eprintln!("handle_request(connect): {}",e); 
	}
	else {
		
	}

}

async fn accept_request(addr: SocketAddr) -> Result<(), io::Error> {

	let sock69 = tokio::net::UdpSocket::bind(addr).await?;

	println!("listening: {}", sock69.local_addr()?);
	
	loop {
        //let (datalen, from) = sock69.recv_from(&mut buf[..]).await?;

		let mut buf : Vec<u8> = vec![0; 1024];

		match sock69.recv_from(&mut buf[..]).await {
			Err(e) => eprintln!("{}",e),
			Ok( (buflen, from) ) => {
				tokio::spawn( handle_request(buflen, buf, from) );
			}
		}
	}
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let str_ip  = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let ip = str_ip.parse()?;

	let sock_addr = std::net::SocketAddr::new(ip, 69);
	accept_request(sock_addr).await?;

    Ok(())
}
