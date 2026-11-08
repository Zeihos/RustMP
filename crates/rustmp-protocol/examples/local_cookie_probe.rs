//! Local-only open.mp legacy offline cookie wire probe.
//! Not a connected client, auth response, or game login.

use std::env;
use std::error::Error;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let address=env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7777".into());
    let server:SocketAddr=address.parse()?;
    if !server.is_ipv4() || !server.ip().is_loopback() {
        return Err("local_cookie_probe supports only IPv4 loopback".into());
    }
    let socket=UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut data=[0u8;128];

    socket.send_to(&[24,0,0], server)?;
    let (n, source)=socket.recv_from(&mut data)?;
    if source!=server || n!=3 || data[0]!=26 {
        return Err(format!("expected 3-byte cookie challenge, got {:02X?}",&data[..n]).into());
    }
    let cookie=u16::from_le_bytes([data[1],data[2]]);
    println!("[1/2] Received open.mp cookie challenge");

    // open.mp fork uses a 16-bit XOR marker to distinguish this flavor.
    // This is NOT a cryptographically authenticated client identity.
    let [lo,hi]=(cookie ^ 0x6D70).to_le_bytes();
    socket.send_to(&[24,lo,hi],server)?;
    let (n,source)=socket.recv_from(&mut data)?;
    if source!=server || &data[..n]!=[25,0] {
        return Err(format!("expected offline open reply, got {:02X?}",&data[..n]).into());
    }
    println!("[2/2] Valid cookie accepted; open.mp offline open reply received");
    println!("Cookie transport probe complete. Game authentication is still disabled.");
    Ok(())
}
