//! RUSTMP offline capture inspector; outputs packet metadata only.
//! Usage: cargo run -p rustmp-protocol --bin rustmp-trace -- trace.pcap --port 7777

use std::env;
use std::error::Error;
use std::fs;
use std::net::SocketAddrV4;
use std::path::Path;

use rustmp_protocol::capture::{
    analyze_pcap, FrameKind, TimestampResolution, MAX_PCAP_BYTES,
};

fn usage() {
    println!("RUSTMP trace inspector (classic .pcap only, read-only)");
    println!("Usage: rustmp-trace <trace.pcap> [--port N] [--show-endpoints]");
    println!("       rustmp-trace --help");
    println!("Default: endpoint IP addresses and all payload bytes are hidden.");
    println!("Only unencrypted SA-MP Query / RakNet offline and frame metadata are recognized.");
    println!("PCAPNG is not supported. Convert/export as classic PCAP in Wireshark.");
}

fn display_port(addr: SocketAddrV4, show: bool) -> String {
    if show { addr.to_string() } else { format!("IP-hidden:{}", addr.port()) }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut path: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut show_endpoints = false;
    let mut args=env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => { usage(); return Ok(()); }
            "--show-endpoints" => { show_endpoints = true; }
            "--port" => {
                if port.is_some() {return Err("--port must be supplied only once".into());}
                port = Some(args.next().ok_or("--port requires a UDP port")?.parse::<u16>()?);
            }
            unknown if unknown.starts_with('-') => return Err(format!("unknown option: {unknown}").into()),
            file => {
                if path.replace(file.to_string()).is_some() {
                    return Err("specify exactly one capture file".into());
                }
            }
        }
    }
    let file = path.ok_or("missing .pcap path; try --help")?;
    let path = Path::new(&file);
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_PCAP_BYTES as u64 {
        return Err(format!("capture exceeds {} bytes", MAX_PCAP_BYTES).into());
    }
    let data = fs::read(path)?;
    let report = analyze_pcap(&data, port).map_err(|e| format!("cannot parse classic PCAP: {e:?}"))?;

    println!("RUSTMP / packet metadata only / no payload output");
    println!("records={} udp={} filtered_udp={} skipped_ip_fragments={} skipped_bad_packets={}",
        report.records, report.udp_seen, report.events.len(),
        report.skipped_ip_fragments, report.skipped_malformed_packets);
    let precision = match report.resolution {
        TimestampResolution::Microseconds => 6,
        TimestampResolution::Nanoseconds => 9,
    };
    for event in report.events {
        let description=match event.kind {
            FrameKind::Query {opcode} => {
                let code = if opcode.is_ascii_graphic() {char::from(opcode)} else {'?'};
                format!("SA-MP Query ({code})")
            }
            FrameKind::Offline {profile,message} => format!("{profile} {message}"),
            FrameKind::Reliable {ack_ranges,frames,first} => {
                if let Some(frame) = first {
                    format!("RakNet candidate ACK-ranges={} frames={} first-seq={} \
reliability={:?} ordered={:?} split={:?} payload_bytes={}",
                        ack_ranges,frames,frame.sequence,frame.reliability,
                        frame.ordering,frame.split,frame.payload_bytes)
                } else {
                    format!("RakNet candidate ACK-ranges={} frames={} (ACK only)",
                        ack_ranges,frames)
                }
            }
            FrameKind::Unknown => "unknown/unsupported/encrypted".to_string(),
        };
        println!("#{} {}.{:0width$} {} -> {} UDP={} {}",
            event.record,event.seconds,event.fraction,
            display_port(event.source,show_endpoints),
            display_port(event.destination,show_endpoints),
            event.wire_bytes,description,width=precision);
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[ERROR] {err}");
        std::process::exit(2);
    }
}
