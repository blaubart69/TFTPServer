use std::error::Error;
use std::net::{SocketAddr, IpAddr};
use std::{env,io};

use tokio::net::UdpSocket;

async fn handle_request(buflen : usize, received_buf : Vec<u8>, from : SocketAddr) {
	println!("request from {} with len {}", from, buflen);
}

async fn accept_request(addr: SocketAddr) -> Result<(), io::Error> {

	let sock69 = tokio::net::UdpSocket::bind(addr).await?;

	println!("bound to: {}", sock69.local_addr()?);
	
	loop {
        //let (datalen, from) = sock69.recv_from(&mut buf[..]).await?;

		let mut buf : Vec<u8> = vec![0; 1024];

		match sock69.recv_from(&mut buf[..]).await {
			Err(e) => eprintln!("{}",e),
			Ok( (buflen, from) ) => {
				println!("request from {}", from);
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
