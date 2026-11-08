//! Black-box tests run the actual rustmp-server executable, not just
//! the in-process dispatcher. This catches missing main.rs integration.
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use rustmp_protocol::legacy_frame::{decode_datagram, encode_datagram, Frame, Reliability};

struct LocalProcess {
    child: Child,
    address: SocketAddr,
}
impl Drop for LocalProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl LocalProcess {
    fn start(experimental: bool) -> Self {
        // Reserve an ephemeral loopback port, then give it to the child.
        let hold = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = hold.local_addr().unwrap();
        drop(hold);
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustmp-server"));
        command.args(["--bind","127.0.0.1","--port",&address.port().to_string()]);
        if experimental { command.arg("--experimental-preauth"); }
        let child = command.stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().expect("spawn compiled RUSTMP binary");
        Self { child, address }
    }

    fn first_reply(&mut self, client: &UdpSocket, data: &[u8]) -> Vec<u8> {
        let mut buf=[0u8;2048];
        client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        for _ in 0..50 {
            if let Some(exit) = self.child.try_wait().unwrap() {
                panic!("RUSTMP exited unexpectedly: {exit}");
            }
            client.send_to(data,self.address).unwrap();
            match client.recv_from(&mut buf) {
                Ok((n,addr)) if addr == self.address => return buf[..n].to_vec(),
                Ok(_) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("recv_from failed: {e}"),
            }
        }
        panic!("RUSTMP did not respond on loopback within startup timeout");
    }
}

fn reliable(sequence:u16,payload:&[u8],acks:&[u16])->Vec<u8> {
    encode_datagram(acks,&[Frame {
        sequence,reliability:Reliability::Reliable,ordering:None,
        payload_bits:(payload.len()*8) as u16,
        payload:payload.to_vec(),split:None,
    }]).unwrap()
}

#[test]
fn actual_binary_reliable_samp_transport_probe() {
    let mut server=LocalProcess::start(true);
    let client=UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(server.first_reply(&client,&[16,0,0]),vec![17,0]);

    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    client.send_to(&reliable(0,&[8],&[]),server.address).unwrap();
    let mut buf=[0u8;2048];
    let (n,addr)=client.recv_from(&mut buf).unwrap();
    assert_eq!(addr,server.address);
    let accepted=decode_datagram(&buf[..n]).unwrap();
    assert_eq!(accepted.acknowledgements[0].start,0);
    assert_eq!(accepted.frames[0].payload.first(),Some(&23));

    let mut confirmation=vec![26u8,127,0,0,1];
    confirmation.extend_from_slice(&server.address.port().to_le_bytes());
    client.send_to(&reliable(1,&confirmation,&[0]),server.address).unwrap();
    let (n,addr)=client.recv_from(&mut buf).unwrap();
    assert_eq!(addr,server.address);
    let ack=decode_datagram(&buf[..n]).unwrap();
    assert_eq!(ack.acknowledgements[0].start,1);
    assert!(ack.frames.is_empty());
}

#[test]
fn actual_binary_cookie_open_reply_retransmission_and_port_isolation() {
    let mut server=LocalProcess::start(true);
    let client=UdpSocket::bind("127.0.0.1:0").unwrap();
    let challenge=server.first_reply(&client,&[24,0,0]);
    assert_eq!(challenge.len(),3);
    assert_eq!(challenge[0],26);
    let cookie=u16::from_le_bytes([challenge[1],challenge[2]]);
    let [low,high]=(cookie ^ 0x6d70).to_le_bytes();
    let answer=[24,low,high];

    // Simulate losing the first OPEN_CONNECTION_REPLY: same client retries.
    let first=server.first_reply(&client,&answer);
    assert_eq!(first,vec![25,0]);
    let retried=server.first_reply(&client,&answer);
    assert_eq!(retried,vec![25,0]);

    // Another source port cannot redeem that same response.
    let other=UdpSocket::bind("127.0.0.1:0").unwrap();
    let challenge=server.first_reply(&other,&answer);
    assert_eq!(challenge.len(),3);
    assert_eq!(challenge[0],26);
}

#[test]
fn default_binary_does_not_complete_a_reliable_handshake() {
    let mut server=LocalProcess::start(false);
    let client=UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(server.first_reply(&client,&[16,0,0]),vec![17,0]);
    client.set_read_timeout(Some(Duration::from_millis(350))).unwrap();
    client.send_to(&reliable(0,&[8],&[]),server.address).unwrap();
    let mut buf=[0u8;2048];
    match client.recv_from(&mut buf) {
        Err(e) if e.kind()==io::ErrorKind::TimedOut
            || e.kind()==io::ErrorKind::WouldBlock => {},
        result => panic!("unexpected reply from default server: {result:?}"),
    }
}
