//! Quick local SA-MP query test client. Run server first, then this example.
use std::env;
use std::error::Error;
use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use encoding_rs::WINDOWS_1251;

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, Box<dyn Error>> {
    let mut bytes = [0u8; 2];
    cursor.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String, Box<dyn Error>> {
    let mut size = [0u8; 4];
    cursor.read_exact(&mut size)?;
    let len = u32::from_le_bytes(size) as usize;
    if len > 1200 { return Err("response contains an oversized string".into()); }
    let mut bytes = vec![0u8; len];
    cursor.read_exact(&mut bytes)?;
    let (text, _, _) = WINDOWS_1251.decode(&bytes);
    Ok(text.into_owned())
}

fn main() -> Result<(), Box<dyn Error>> {
    let ip: Ipv4Addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1".into()).parse()?;
    let port: u16 = env::args().nth(2).unwrap_or_else(|| "7777".into()).parse()?;
    let mut query = b"SAMP".to_vec();
    query.extend_from_slice(&ip.octets());
    query.extend_from_slice(&port.to_le_bytes());
    query.push(b'i');

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.send_to(&query, (ip, port))?;
    let mut response = [0u8; 2048];
    let (size, _) = socket.recv_from(&mut response)?;
    if size < 16 || response[..11] != query[..] {
        return Err("invalid query response header".into());
    }
    let mut cursor = Cursor::new(&response[11..size]);
    let mut passworded = [0u8; 1];
    cursor.read_exact(&mut passworded)?;
    let current = read_u16(&mut cursor)?;
    let max = read_u16(&mut cursor)?;
    let hostname = read_string(&mut cursor)?;
    let mode = read_string(&mut cursor)?;
    let language = read_string(&mut cursor)?;
    println!("Server: {hostname}\nPlayers: {current}/{max}\nMode: {mode}\nLanguage: {language}\nPassworded: {}", passworded[0] != 0);
    Ok(())
}
