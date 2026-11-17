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
