//! Black-box tests run the actual rustmp-server executable, not just
//! the in-process dispatcher. This catches missing main.rs integration.
use std::io::{self, Read};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use rustmp_protocol::legacy_frame::{decode_datagram, encode_datagram, Frame, Reliability};

/// Serialize black-box server startups. Parallel tests used to race on
/// ephemeral port reservation; a second UDP socket could claim the released
/// server port before its child started listening.
static SERVER_PROCESS_LOCK: Mutex<()> = Mutex::new(());

struct LocalProcess {
    child: Child,
    address: SocketAddr,
    _guard: MutexGuard<'static, ()>,
}
impl Drop for LocalProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl LocalProcess {
    fn start(experimental: bool) -> (Self, UdpSocket) {
        let guard=SERVER_PROCESS_LOCK.lock().unwrap_or_else(|poisoned|
            poisoned.into_inner());
        // Bind the test client WHILE the server port is reserved, ensuring
        // that the kernel cannot assign the same UDP port to both sockets.
        // The lock also prevents another test in this binary from racing on
        // the brief reserve/drop/startup interval.
        let hold = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = hold.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_ne!(client.local_addr().unwrap(), address);
        drop(hold);
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustmp-server"));
        command.args(["--bind","127.0.0.1","--port",&address.port().to_string()]);
        if experimental { command.arg("--experimental-preauth"); }
        let child = command.stdout(Stdio::null()).stderr(Stdio::piped())
            .spawn().expect("spawn compiled RUSTMP binary");
        (Self { child, address, _guard:guard }, client)
    }

    fn first_reply(&mut self, client: &UdpSocket, data: &[u8]) -> Vec<u8> {
        let mut buf=[0u8;2048];
        client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        for _ in 0..50 {
            if let Some(exit) = self.child.try_wait().unwrap() {
                let mut diagnostics=String::new();
                if let Some(stderr)=self.child.stderr.as_mut() {
                    let _=stderr.read_to_string(&mut diagnostics);
                }
                panic!("RUSTMP exited unexpectedly: {exit}; stderr: {diagnostics}");
            }
            client.send_to(data,self.address).unwrap();
            match client.recv_from(&mut buf) {
                Ok((n,addr)) if addr == self.address => return buf[..n].to_vec(),
                Ok(_) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock
                    // Windows turns an ICMP port-unreachable from a UDP
                    // request sent *before* the child binds into WSAECONNRESET.
                    // Treat it like a normal startup retry, not a test failure.
                    || e.raw_os_error() == Some(10054) =>
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
    let (mut server,client)=LocalProcess::start(true);
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
fn actual_binary_resends_lost_final_ack_then_clears_cache_on_new_open() {
    let (mut server,client)=LocalProcess::start(true);
    assert_eq!(server.first_reply(&client,&[16,0,0]),vec![17,0]);
    let accepted=server.first_reply(&client,&reliable(0,&[8],&[]));
    let response=decode_datagram(&accepted).unwrap();
    assert_eq!(response.frames[0].payload.first(),Some(&23));

    let mut final_payload=vec![26u8,127,0,0,1];
    final_payload.extend_from_slice(&server.address.port().to_le_bytes());
    let final_wire=reliable(1,&final_payload,&[0]);
    let first=server.first_reply(&client,&final_wire);
    let decoded=decode_datagram(&first).unwrap();
    assert!(decoded.frames.is_empty());
    assert_eq!(decoded.acknowledgements[0].start,1);

    // Simulate losing the server's final ACK and changing piggybacked ACK
    // metadata. Exact reliable frame content and endpoint still match.
    let resent=reliable(1,&final_payload,&[]);
    let replayed=server.first_reply(&client,&resent);
    assert_eq!(replayed,first);

    // This starts a new diagnostic attempt with the same UDP source port.
    // The ACK for the previous completion must no longer be served.
    assert_eq!(server.first_reply(&client,&[16,0,0]),vec![17,0]);
    client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    client.send_to(&resent,server.address).unwrap();
    let mut buf=[0u8;2048];
    match client.recv_from(&mut buf) {
        Err(ref err) if err.kind()==io::ErrorKind::TimedOut
            || err.kind()==io::ErrorKind::WouldBlock => {},
        reply => panic!("old final ACK was replayed after new offline open: {reply:?}"),
    }
    // The newly opened slot can begin a fresh local-only pre-auth probe.
    let new_accepted=server.first_reply(&client,&reliable(0,&[8],&[]));
    let decoded=decode_datagram(&new_accepted).unwrap();
    assert_eq!(decoded.frames[0].payload.first(),Some(&23));
}

#[test]
fn actual_binary_cookie_open_reply_retransmission_and_port_isolation() {
    let (mut server,client)=LocalProcess::start(true);
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
    let (mut server,client)=LocalProcess::start(false);
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


#[test]
fn production_binding_is_rejected_before_opening_public_diagnostic_socket() {
    for address in ["0.0.0.0", "192.0.2.10", "::1"] {
        let result=Command::new(env!("CARGO_BIN_EXE_rustmp-server"))
            .args(["--bind",address,"--experimental-preauth"])
            .output().expect("run server executable");
        assert!(!result.status.success(), "must refuse diagnostic on {address}");
        let stderr=String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("explicit IPv4 loopback"),
            "unexpected error for {address}: {stderr}");
    }
}

#[test]
fn malformed_udp_flood_does_not_break_next_legitimate_probe() {
    let (mut server,client)=LocalProcess::start(true);
    assert_eq!(server.first_reply(&client,&[16,0,0]),vec![17,0]);

    // The diagnostic transport must ignore oversized or nonsensical input
    // rather than terminate its process or allocate a second peer.
    for n in 0..48 {
        let mut garbage=vec![0xff;20+(n%50)];
        garbage[0]=0xEE;
        client.send_to(&garbage,server.address).unwrap();
    }
    let pong=server.first_reply(&client,&[3,1,2,3,4]);
    assert_eq!(pong,vec![37,1,2,3,4]);
}
