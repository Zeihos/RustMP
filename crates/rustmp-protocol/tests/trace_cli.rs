//! Run the compiled rustmp-trace binary against synthetic PCAP fixtures.
//! No real client captures or secrets are stored in this repository.

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_capture(payload: &[u8]) -> Vec<u8> {
    let mut cap=vec![0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0];
    cap.extend_from_slice(&65535u32.to_le_bytes());
    cap.extend_from_slice(&1u32.to_le_bytes());
    let ip_size = 20 + 8 + payload.len();
    let mut network=vec![0u8;14+ip_size];
    network[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let offset=14;
    network[offset]=0x45;
    network[offset+2..offset+4].copy_from_slice(&(ip_size as u16).to_be_bytes());
    network[offset+8]=64;
    network[offset+9]=17;
    network[offset+12..offset+16].copy_from_slice(&[192,0,2,10]);
    network[offset+16..offset+20].copy_from_slice(&[192,0,2,11]);
    network[offset+20..offset+22].copy_from_slice(&45000u16.to_be_bytes());
    network[offset+22..offset+24].copy_from_slice(&7777u16.to_be_bytes());
    network[offset+24..offset+26].copy_from_slice(&((payload.len()+8) as u16).to_be_bytes());
    network[offset+28..].copy_from_slice(payload);

    cap.extend_from_slice(&10u32.to_le_bytes());
    cap.extend_from_slice(&200u32.to_le_bytes());
    cap.extend_from_slice(&(network.len() as u32).to_le_bytes());
    cap.extend_from_slice(&(network.len() as u32).to_le_bytes());
    cap.extend_from_slice(&network);
    cap
}

struct TempCapture(std::path::PathBuf);
impl TempCapture {
    fn write(bytes: &[u8]) -> Self {
        let tick=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let file=std::env::temp_dir().join(format!("rustmp-trace-{}-{}.pcap",
            std::process::id(),tick));
        fs::write(&file,bytes).unwrap();
        Self(file)
    }
}
impl Drop for TempCapture {
    fn drop(&mut self) {let _=fs::remove_file(&self.0);}
}

#[test]
fn binary_classifies_without_printing_secrets_or_ips_by_default() {
    let fixture=TempCapture::write(&test_capture(b"TOP_SECRET_CAPTURE_PAYLOAD"));
    let output=Command::new(env!("CARGO_BIN_EXE_rustmp-trace"))
        .arg(&fixture.0).args(["--port","7777"]).output().unwrap();
    assert!(output.status.success(), "{:?}",String::from_utf8_lossy(&output.stderr));
    let stdout=String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("records=1 udp=1 filtered_udp=1"));
    assert!(stdout.contains("IP-hidden:45000 -> IP-hidden:7777"));
    assert!(!stdout.contains("TOP_SECRET_CAPTURE_PAYLOAD"));
    assert!(!stdout.contains("192.0.2.10"));
}

#[test]
fn endpoint_display_is_explicit_opt_in_and_port_filter_works() {
    let fixture=TempCapture::write(&test_capture(&[24,0,0]));
    let program=env!("CARGO_BIN_EXE_rustmp-trace");
    let shown=Command::new(program).arg(&fixture.0)
        .arg("--show-endpoints").output().unwrap();
    assert!(shown.status.success());
    let text=String::from_utf8_lossy(&shown.stdout);
    assert!(text.contains("192.0.2.10:45000"));
    assert!(text.contains("open.mp open-request"));
    let filtered=Command::new(program).arg(&fixture.0)
        .args(["--port","1234"]).output().unwrap();
    assert!(filtered.status.success());
    assert!(String::from_utf8_lossy(&filtered.stdout).contains("filtered_udp=0"));
}

#[test]
fn binary_rejects_bad_magic_and_has_help() {
    let fixture=TempCapture::write(&[0u8;24]);
    let program=env!("CARGO_BIN_EXE_rustmp-trace");
    let bad=Command::new(program).arg(&fixture.0).output().unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("BadMagic"));
    let help=Command::new(program).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("PCAPNG"));
}


fn two_way_open_capture() -> Vec<u8> {
    let mut combined=test_capture(&[24,0,0]);
    let mut server_reply=test_capture(&[25,0]);
    let ip=24+16+14;
    // Reverse the IPv4 endpoints and UDP ports of the server reply.
    server_reply[ip+12..ip+16].copy_from_slice(&[192,0,2,11]);
    server_reply[ip+16..ip+20].copy_from_slice(&[192,0,2,10]);
    server_reply[ip+20..ip+22].copy_from_slice(&7777u16.to_be_bytes());
    server_reply[ip+22..ip+24].copy_from_slice(&45000u16.to_be_bytes());
    combined.extend_from_slice(&server_reply[24..]);
    combined
}

#[test]
fn offline_handshake_timeline_correlates_both_directions_without_exposing_ips() {
    let fixture=TempCapture::write(&two_way_open_capture());
    let out=Command::new(env!("CARGO_BIN_EXE_rustmp-trace"))
        .arg(&fixture.0)
        .args(["--port","7777","--handshakes"])
        .output().unwrap();
    assert!(out.status.success(), "{}",String::from_utf8_lossy(&out.stderr));
    let text=String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("handshake_flows=1 repeated_requests=0 without_reply_in_capture=0"));
    assert!(text.contains("profile=open.mp state=OfflineReplyObserved"));
    assert!(text.contains("IP-hidden:45000 -> IP-hidden:7777"));
    assert!(!text.contains("192.0.2.10"));
    assert!(!text.contains("192.0.2.11"));
}

#[test]
fn repeated_request_without_reply_is_reported_as_capture_observation_only() {
    let mut capture=test_capture(&[16,0,0]);
    let second=test_capture(&[16,0,0]);
    capture.extend_from_slice(&second[24..]);
    let fixture=TempCapture::write(&capture);
    let out=Command::new(env!("CARGO_BIN_EXE_rustmp-trace"))
        .arg(&fixture.0)
        .args(["--port","7777","--handshakes"])
        .output().unwrap();
    assert!(out.status.success());
    let text=String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("handshake_flows=1 repeated_requests=1 without_reply_in_capture=1"));
    assert!(text.contains("state=AwaitingReply"));
    assert!(text.contains("missing reply may be caused"));
}

#[test]
fn flow_analysis_needs_explicit_server_port_and_endpoints_are_opt_in() {
    let fixture=TempCapture::write(&two_way_open_capture());
    let binary=env!("CARGO_BIN_EXE_rustmp-trace");
    let denied=Command::new(binary).arg(&fixture.0)
        .arg("--handshakes").output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("requires --port"));
    let allowed=Command::new(binary).arg(&fixture.0)
        .args(["--handshakes","--port","7777","--show-endpoints"])
        .output().unwrap();
    assert!(allowed.status.success());
    assert!(String::from_utf8_lossy(&allowed.stdout)
        .contains("192.0.2.10:45000 -> 192.0.2.11:7777"));
}
