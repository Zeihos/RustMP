//! Probe the first pre-connection exchange; NOT a playable SA-MP client.
use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;
use omp_transport::legacy_id;

fn main() -> Result<(), Box<dyn Error>> {
    let target = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7777".into());
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    sock.send_to(&[legacy_id::OPEN_CONNECTION_REQUEST, 0, 0], &target)?;
    let mut data = [0u8; 128];
    let (n, sender) = sock.recv_from(&mut data)?;
    println!("{sender}: raw reply = {:02X?}", &data[..n]);
    if n == 2 && data[0] == legacy_id::OPEN_CONNECTION_REPLY && data[1] == 0 {
        println!("Offline pre-handshake response received. This does NOT mean the game can connect.");
    }
    Ok(())
}
