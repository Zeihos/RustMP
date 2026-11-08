//! Local-only end-to-end transport probe for --experimental-preauth.
//! This is NOT a real SA-MP client and does not attempt game login.
use std::env;
use std::error::Error;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use rustmp_protocol::legacy_frame::{decode_datagram, encode_datagram, Frame, Reliability};

fn reliable(sequence: u16, payload: Vec<u8>, acks: &[u16]) -> Result<Vec<u8>, Box<dyn Error>> {
    let frame=Frame{
        sequence, reliability:Reliability::Reliable, ordering:None, split:None,
        payload_bits:(payload.len()*8) as u16, payload,
    };
    encode_datagram(acks,&[frame]).map_err(|e|format!("{e:?}").into())
}
fn main()->Result<(),Box<dyn Error>> {
    let address=env::args().nth(1).unwrap_or_else(||"127.0.0.1:7777".into());
    let server:SocketAddr=address.parse()?;
    if !server.ip().is_loopback() || !server.is_ipv4() {
        return Err("probe works only with --bind 127.0.0.1 --experimental-preauth".into());
    }
    let sock=UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf=[0u8;1500];
    sock.send_to(&[16,0,0],server)?;
    let (n,sender)=sock.recv_from(&mut buf)?;
    if sender!=server || &buf[..n]!=[17,0] {
        return Err(format!("unexpected offline reply: {:02X?}",&buf[..n]).into());
    }
    println!("[1/3] offline open OK");
    sock.send_to(&reliable(0,vec![8],&[])?,server)?;
    let (n,sender)=sock.recv_from(&mut buf)?;
    if sender!=server {return Err("reply from unexpected peer".into());}
    let accepted=decode_datagram(&buf[..n]).map_err(|e|format!("{e:?}"))?;
    if accepted.acknowledgements.len()!=1 ||
        accepted.acknowledgements[0].start!=0 ||
        accepted.frames.len()!=1 ||
        accepted.frames[0].payload.first()!=Some(&23)
    {
        return Err("unexpected RakNet connection accepted response".into());
    }
    println!("[2/3] ACK #0 + reliable transport acceptance OK");
    let mut confirm=vec![26];
    if let IpAddr::V4(addr)=server.ip() {
        confirm.extend_from_slice(&addr.octets());
    }
    confirm.extend_from_slice(&server.port().to_le_bytes());
    sock.send_to(&reliable(1,confirm,&[0])?,server)?;
    let (n,sender)=sock.recv_from(&mut buf)?;
    if sender!=server {return Err("reply from unexpected peer".into());}
    let acknowledged=decode_datagram(&buf[..n]).map_err(|e|format!("{e:?}"))?;
    if acknowledged.acknowledgements.len()!=1 ||
        acknowledged.acknowledgements[0].start!=1 ||
        !acknowledged.frames.is_empty()
    {
        return Err("unexpected final ACK".into());
    }
    println!("[3/3] reliable transport confirmation ACK OK");
    println!("Protocol probe complete. No actual SA-MP player connected.");
    Ok(())
}
