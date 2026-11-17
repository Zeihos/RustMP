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
use rustmp_protocol::handshake_trace::analyze_offline_flows;
use rustmp_protocol::reliable_trace::analyze_reliable_flows;

fn usage() {
    println!("RUSTMP trace inspector (classic .pcap only, read-only)");
    println!("Usage: rustmp-trace <trace.pcap> [--port N] [--show-endpoints] [--handshakes] [--reliable]");
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
    let mut show_handshakes = false;
    let mut show_reliable = false;
    let mut args=env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => { usage(); return Ok(()); }
            "--show-endpoints" => { show_endpoints = true; }
            "--handshakes" => { show_handshakes = true; }
            "--reliable" => { show_reliable = true; }
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
    if show_handshakes && port.is_none() {
        return Err("--handshakes requires --port N to identify the server endpoint".into());
    }
    if show_reliable && port.is_none() {
        return Err("--reliable requires --port N to identify the server endpoint".into());
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
    for event in &report.events {
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
    if show_handshakes {
        let server_port=port.expect("checked above");
        let flows=analyze_offline_flows(&report,server_port)
            .map_err(|e|format!("handshake timeline: {e:?}"))?;
        let repeated:usize=flows.flows.iter().map(|f|f.repeated_requests).sum();
        let missing=flows.flows.iter().filter(|f|f.missing_reply_in_capture()).count();
        println!("HANDSHAKE TIMELINE (observed offline packets, NOT authenticated clients)");
        println!("handshake_flows={} repeated_requests={} without_reply_in_capture={} skipped={}",
            flows.flows.len(),repeated,missing,flows.skipped_events);
        for (i,f) in flows.flows.iter().enumerate() {
            println!("flow={} {} -> {} profile={} state={:?} records={}..{} requests={} cookie_challenges={} open_replies={} repeated={} after_reply={} orphan_challenges={} orphan_replies={} timestamp_anomalies={}",
                i+1,display_port(f.client,show_endpoints),
                display_port(f.server,show_endpoints),
                f.profile,f.state,f.first_record,f.last_record,
                f.requests,f.cookie_challenges,f.open_replies,
                f.repeated_requests,f.retries_after_reply,
                f.challenges_before_request,f.replies_before_request,
                f.timestamp_order_issues);
        }
        println!("NOTICE: a missing reply may be caused by packet loss, capture loss or filtering.");
    }
    if show_reliable {
        let server_port=port.expect("checked above");
        let analysis=analyze_reliable_flows(&report,server_port)
            .map_err(|error|format!("reliable trace: {error:?}"))?;
        let outstanding:usize=analysis.flows.iter()
            .map(|flow|flow.outstanding_client+flow.outstanding_server).sum();
        let confirmed:usize=analysis.flows.iter()
            .map(|flow|flow.client_confirmed+flow.server_confirmed).sum();
        println!("RELIABLE TRACE (observed wire IDs; no game authentication)");
        println!("reliable_flows={} confirmed={} outstanding_in_capture={} ignored={}",
            analysis.flows.len(),confirmed,outstanding,analysis.ignored_events);
        for (index,flow) in analysis.flows.iter().enumerate() {
            println!("reliable_flow={} {} -> {} records={}..{} client_frames={} server_frames={} client_confirmed={} server_confirmed={} client_repeated={} server_repeated={} outstanding_client={} outstanding_server={} unmatched_acks={} untracked={}",
                index+1,display_port(flow.client,show_endpoints),
                display_port(flow.server,show_endpoints),
                flow.first_record,flow.last_record,flow.client_frames,
                flow.server_frames,flow.client_confirmed,flow.server_confirmed,
                flow.client_retransmissions,flow.server_retransmissions,
                flow.outstanding_client,flow.outstanding_server,
                flow.unmatched_acks,flow.untracked_frames);
        }
        println!("NOTICE: outstanding_in_capture is not proof of network loss, and unmatched ACKs may refer to frames outside the capture.");
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[ERROR] {err}");
        std::process::exit(2);
    }
}
