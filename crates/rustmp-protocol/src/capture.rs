//! Bounded, read-only classic PCAP inspector for SA-MP/open.mp UDP traces.
//!
//! This module intentionally does NOT retain raw payloads in its public
//! reports. Unredacted UDP data can contain passwords, authentication keys,
//! nicknames or player data. PCAP-NG is not supported; export as classic
//! libpcap (.pcap) in Wireshark before using this diagnostic.
//!
//! Wire reference: Wireshark libpcap file format (global header 24 bytes,
//! packet record header 16 bytes); Ethernet/IPv4/UDP and selected link types.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::ack::AckRange;
use crate::legacy_frame::{decode_datagram, Reliability, SplitInfo};

pub const MAX_PCAP_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 256 * 1024;
pub const MAX_PCAP_RECORDS: usize = 65_536;
pub const MAX_UDP_EVENTS: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    Empty,
    TooLarge,
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnsupportedLinkType(u32),
    InvalidHeader,
    InvalidRecord,
    TooManyRecords,
    TooManyEvents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampResolution { Microseconds, Nanoseconds }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Offline {
        profile: &'static str,
        message: &'static str,
    },
    Query { opcode: u8 },
    Reliable {
        ack_ranges: usize,
        frames: usize,
        first: Option<FrameSummary>,
    },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameSummary {
    pub sequence: u16,
    pub reliability: Reliability,
    pub ordering: Option<(u8, u16)>,
    pub split: Option<SplitInfo>,
    pub payload_bytes: usize,
}

/// Read-only packet-number evidence. No payload bytes, tokens, cookies,
/// passwords or client nicknames are stored in this structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceEvidence {
    pub sequence: u16,
    pub reliability: Reliability,
}

/// All validated ACK ranges and frame sequence numbers from a datagram.
/// The codec already bounds each datagram to 512 ACK numbers and 32 frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliableEvidence {
    pub acknowledgements: Vec<AckRange>,
    pub sequences: Vec<SequenceEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpEvent {
    pub record: usize,
    pub seconds: u32,
    pub fraction: u32,
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    pub wire_bytes: usize,
    pub kind: FrameKind,
    /// Present only if this datagram was decoded as a legacy RakNet frame.
    pub reliable: Option<ReliableEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureReport {
    pub resolution: TimestampResolution,
    pub records: usize,
    pub udp_seen: usize,
    pub events: Vec<UdpEvent>,
    pub skipped_ip_fragments: usize,
    pub skipped_malformed_packets: usize,
}

#[derive(Clone, Copy)]
enum ByteOrder { Little, Big }
impl ByteOrder {
    fn u16(self, bytes: &[u8]) -> u16 {
        let pair = [bytes[0], bytes[1]];
        match self { Self::Little => u16::from_le_bytes(pair), Self::Big => u16::from_be_bytes(pair) }
    }
    fn u32(self, bytes: &[u8]) -> u32 {
        let word = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self { Self::Little => u32::from_le_bytes(word), Self::Big => u32::from_be_bytes(word) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtractError { Fragmented, Malformed }

struct UdpPacket<'a> {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &'a [u8],
}

/// Returns a UDP packet only when the record contains complete, unfragmented
/// IPv4+UDP. IP fragments are skipped, not incorrectly decoded as UDP frames.
/// Ethernet padding, stacked VLAN tags (up to two), SLL, RAW and NULL are
/// handled without network access or external libraries.
fn extract_udp(record: &[u8], linktype: u32) -> Result<Option<UdpPacket<'_>>, ExtractError> {
    let ip = match linktype {
        1 => {
            if record.len() < 14 { return Err(ExtractError::Malformed); }
            let mut offset = 14usize;
            let mut ethertype = u16::from_be_bytes([record[12], record[13]]);
            for _ in 0..2 {
                if matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                    if record.len() < offset + 4 { return Err(ExtractError::Malformed); }
                    ethertype = u16::from_be_bytes([record[offset+2], record[offset+3]]);
                    offset += 4;
                }
            }
            if ethertype != 0x0800 { return Ok(None); }
            record.get(offset..).ok_or(ExtractError::Malformed)?
        }
        101 => record, // LINKTYPE_RAW
        0 => {
            // BSD LOOPBACK: AF_INET (2) in capture host byte order.
            if record.len() < 4 { return Err(ExtractError::Malformed); }
            if record[..4] != [2, 0, 0, 0] && record[..4] != [0, 0, 0, 2] {
                return Ok(None);
            }
            &record[4..]
        }
        113 => {
            // Linux cooked capture v1: protocol field at offset 14.
            if record.len() < 16 { return Err(ExtractError::Malformed); }
            if record[14..16] != [0x08, 0x00] { return Ok(None); }
            &record[16..]
        }
        276 => {
            // Linux cooked capture v2: protocol first, header is 20 bytes.
            if record.len() < 20 { return Err(ExtractError::Malformed); }
            if record[..2] != [0x08, 0x00] { return Ok(None); }
            &record[20..]
        }
        _ => return Ok(None),
    };
    if ip.len() < 20 || (ip[0] >> 4) != 4 { return Err(ExtractError::Malformed); }
    let header = usize::from(ip[0] & 0x0f) * 4;
    if header < 20 || header > ip.len() { return Err(ExtractError::Malformed); }
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if total < header || total > ip.len() { return Err(ExtractError::Malformed); }
    if ip[9] != 17 { return Ok(None); }
    // Reject both first fragments (MF) and subsequent fragments (offset).
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x3fff != 0 { return Err(ExtractError::Fragmented); }
    let ip_payload = &ip[header..total];
    if ip_payload.len() < 8 { return Err(ExtractError::Malformed); }
    let udp_length = usize::from(u16::from_be_bytes([ip_payload[4], ip_payload[5]]));
    if udp_length < 8 || udp_length > ip_payload.len() { return Err(ExtractError::Malformed); }
    let source = SocketAddrV4::new(
        Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        u16::from_be_bytes([ip_payload[0], ip_payload[1]]),
    );
    let destination = SocketAddrV4::new(
        Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        u16::from_be_bytes([ip_payload[2], ip_payload[3]]),
    );
    Ok(Some(UdpPacket { src: source, dst: destination, payload: &ip_payload[8..udp_length] }))
}

/// Classify known unencrypted messages by strict wire length. Unknown or
/// encrypted datagrams remain "Unknown". We never log raw application bytes.
pub fn classify_udp(payload: &[u8]) -> FrameKind {
    match payload {
        [16, _, _] => FrameKind::Offline { profile: "SA-MP", message: "open-request" },
        [17, _] => FrameKind::Offline { profile: "SA-MP", message: "open-reply" },
        [24, _, _] => FrameKind::Offline { profile: "open.mp", message: "open-request" },
        [25, _] => FrameKind::Offline { profile: "open.mp", message: "open-reply" },
        [26, _, _] => FrameKind::Offline { profile: "open.mp", message: "cookie-challenge" },
        [3, _, _, _, _] => FrameKind::Offline { profile: "SA-MP", message: "ping" },
        [4, _, _, _, _] => FrameKind::Offline { profile: "SA-MP", message: "ping-if-open" },
        [37, _, _, _, _] => FrameKind::Offline { profile: "SA-MP", message: "pong" },
        [7, _, _, _, _] => FrameKind::Offline { profile: "open.mp", message: "ping" },
        [8, _, _, _, _] => FrameKind::Offline { profile: "open.mp", message: "ping-if-open" },
        [39, _, _, _, _] => FrameKind::Offline { profile: "open.mp", message: "pong" },
        _ => {
            if payload.starts_with(b"SAMP") && payload.len() >= 11 {
                return FrameKind::Query { opcode: payload[10] };
            }
            if let Ok(decoded) = decode_datagram(payload) {
                return FrameKind::Reliable {
                    ack_ranges: decoded.acknowledgements.len(),
                    frames: decoded.frames.len(),
                    first: decoded.frames.first().map(|f| FrameSummary {
                        sequence: f.sequence,
                        reliability: f.reliability,
                        ordering: f.ordering,
                        split: f.split,
                        payload_bytes: f.payload.len(),
                    }),
                };
            }
            FrameKind::Unknown
        }
    }
}

/// Analyze a classic .pcap from memory, subject to strict global and record
/// limits. Port filtering is applied after validating IP/UDP bounds.
/// Does not support pcapng, encrypted payload decoding or fragmented IPv4.
pub fn analyze_pcap(bytes: &[u8], port: Option<u16>) -> Result<CaptureReport, CaptureError> {
    if bytes.is_empty() { return Err(CaptureError::Empty); }
    if bytes.len() > MAX_PCAP_BYTES { return Err(CaptureError::TooLarge); }
    if bytes.len() < 24 { return Err(CaptureError::Truncated); }
    let (order, resolution) = match &bytes[..4] {
        [0xd4,0xc3,0xb2,0xa1] => (ByteOrder::Little, TimestampResolution::Microseconds),
        [0xa1,0xb2,0xc3,0xd4] => (ByteOrder::Big, TimestampResolution::Microseconds),
        [0x4d,0x3c,0xb2,0xa1] => (ByteOrder::Little, TimestampResolution::Nanoseconds),
        [0xa1,0xb2,0x3c,0x4d] => (ByteOrder::Big, TimestampResolution::Nanoseconds),
        _ => return Err(CaptureError::BadMagic),
    };
    if order.u16(&bytes[4..6]) != 2 || order.u16(&bytes[6..8]) != 4 {
        return Err(CaptureError::UnsupportedVersion);
    }
    let snaplen = order.u32(&bytes[16..20]) as usize;
    if snaplen == 0 || snaplen > MAX_RECORD_BYTES {
        return Err(CaptureError::InvalidHeader);
    }
    let linktype = order.u32(&bytes[20..24]) & 0x0000_ffff;
    if !matches!(linktype, 0 | 1 | 101 | 113 | 276) {
        return Err(CaptureError::UnsupportedLinkType(linktype));
    }
    let mut offset = 24usize;
    let mut report = CaptureReport {
        resolution, records: 0, udp_seen: 0, events: Vec::new(),
        skipped_ip_fragments: 0, skipped_malformed_packets: 0,
    };
    while offset < bytes.len() {
        if report.records >= MAX_PCAP_RECORDS { return Err(CaptureError::TooManyRecords); }
        if bytes.len() - offset < 16 { return Err(CaptureError::Truncated); }
        let header = &bytes[offset..offset + 16];
        let seconds = order.u32(&header[..4]);
        let fraction = order.u32(&header[4..8]);
        let captured = order.u32(&header[8..12]) as usize;
        let original = order.u32(&header[12..16]) as usize;
        if fraction >= match resolution {
            TimestampResolution::Microseconds => 1_000_000,
            TimestampResolution::Nanoseconds => 1_000_000_000,
        } || captured > snaplen || captured > original || captured > MAX_RECORD_BYTES
        {
            return Err(CaptureError::InvalidRecord);
        }
        offset += 16;
        if captured > bytes.len() - offset { return Err(CaptureError::Truncated); }
        report.records += 1;
        let record = &bytes[offset..offset + captured];
        match extract_udp(record, linktype) {
            Ok(Some(udp)) => {
                report.udp_seen += 1;
                if port.is_none_or(|p| udp.src.port() == p || udp.dst.port() == p) {
                    if report.events.len() >= MAX_UDP_EVENTS {
                        return Err(CaptureError::TooManyEvents);
                    }
                    let kind = classify_udp(udp.payload);
                    // Never keep the raw payload; only validated wire
                    // sequence numbers and ACK ranges are retained.
                    let reliable = if matches!(kind, FrameKind::Reliable { .. }) {
                        decode_datagram(udp.payload).ok().map(|data| ReliableEvidence {
                            acknowledgements: data.acknowledgements,
                            sequences: data.frames.iter().map(|frame| SequenceEvidence {
                                sequence: frame.sequence,
                                reliability: frame.reliability,
                            }).collect(),
                        })
                    } else {
                        None
                    };
                    report.events.push(UdpEvent {
                        record: report.records,
                        seconds, fraction,
                        source: udp.src, destination: udp.dst,
                        wire_bytes: udp.payload.len(),
                        kind, reliable,
                    });
                }
            }
            Ok(None) => {}
            Err(ExtractError::Fragmented) => report.skipped_ip_fragments += 1,
            Err(ExtractError::Malformed) => report.skipped_malformed_packets += 1,
        }
        offset += captured;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_frame::{encode_datagram, Frame, Reliability};

    fn header(be: bool, nanos: bool, linktype: u32) -> Vec<u8> {
        let mut out=if be {
            if nanos {vec![0xa1,0xb2,0x3c,0x4d]} else {vec![0xa1,0xb2,0xc3,0xd4]}
        } else if nanos {vec![0x4d,0x3c,0xb2,0xa1]} else {vec![0xd4,0xc3,0xb2,0xa1]};
        fn word(out:&mut Vec<u8>, value:u32, be:bool) {
            if be {out.extend_from_slice(&value.to_be_bytes())}
            else {out.extend_from_slice(&value.to_le_bytes())}
        }
        if be {out.extend_from_slice(&2u16.to_be_bytes());out.extend_from_slice(&4u16.to_be_bytes());}
        else {out.extend_from_slice(&2u16.to_le_bytes());out.extend_from_slice(&4u16.to_le_bytes());}
        word(&mut out,0,be);word(&mut out,0,be);
        word(&mut out,MAX_RECORD_BYTES as u32,be);
        word(&mut out,linktype,be);
        out
    }
    fn add_record(dst:&mut Vec<u8>, packet:&[u8], be:bool) {
        let u32v=|x:u32| if be {x.to_be_bytes()} else {x.to_le_bytes()};
        dst.extend_from_slice(&u32v(10));
        dst.extend_from_slice(&u32v(123));
        dst.extend_from_slice(&u32v(packet.len() as u32));
        dst.extend_from_slice(&u32v(packet.len() as u32));
        dst.extend_from_slice(packet);
    }
    fn ipv4_udp(payload:&[u8], flags:u16)->Vec<u8> {
        let udp_len=8+payload.len();
        let ip_len=20+udp_len;
        let mut out=vec![0u8;ip_len];
        out[0]=0x45;
        out[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        out[6..8].copy_from_slice(&flags.to_be_bytes());
        out[8]=64;out[9]=17;
        out[12..16].copy_from_slice(&[192,0,2,1]);
        out[16..20].copy_from_slice(&[192,0,2,2]);
        out[20..22].copy_from_slice(&45000u16.to_be_bytes());
        out[22..24].copy_from_slice(&7777u16.to_be_bytes());
        out[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        out[28..].copy_from_slice(payload);
        out
    }
    fn ethernet(ip:&[u8],vlans:usize)->Vec<u8> {
        let mut out=vec![0u8;12];
        if vlans==0 {out.extend_from_slice(&[0x08,0x00]);}
        else {
            out.extend_from_slice(&[0x81,0x00]);
            for tag in 0..vlans {
                out.extend_from_slice(&[0,tag as u8]);
                if tag+1==vlans {out.extend_from_slice(&[0x08,0x00]);}
                else {out.extend_from_slice(&[0x81,0x00]);}
            }
        }
        out.extend_from_slice(ip);
        out
    }
    #[test]
    fn little_endian_ethernet_query_cookie_and_reliable_are_classified() {
        let mut pcap=header(false,false,1);
        let query=b"SAMP\x7f\0\0\x01\x61\x1e\x69";
        let frame=encode_datagram(&[1], &[Frame {
            sequence:8,reliability:Reliability::Reliable,ordering:None,
            payload_bits:8,payload:vec![11],split:None,
        }]).unwrap();
        for payload in [&query[..],&[24,0,0],&[26,9,1],&frame[..]] {
            add_record(&mut pcap,&ethernet(&ipv4_udp(payload,0),0),false);
        }
        let rep=analyze_pcap(&pcap,Some(7777)).unwrap();
        assert_eq!(rep.records,4);
        assert_eq!(rep.udp_seen,4);
        assert_eq!(rep.events.len(),4);
        assert_eq!(rep.events[0].kind,FrameKind::Query{opcode:b'i'});
        assert_eq!(rep.events[1].kind,FrameKind::Offline{profile:"open.mp",message:"open-request"});
        assert_eq!(rep.events[2].kind,FrameKind::Offline{profile:"open.mp",message:"cookie-challenge"});
        let FrameKind::Reliable {ack_ranges,frames,first} = rep.events[3].kind
            else {panic!("expected reliable")};
        assert_eq!((ack_ranges,frames),(1,1));
        assert_eq!(first.unwrap().sequence,8);
        assert_eq!(rep.events[0].source.port(),45000);
        let evidence=rep.events[3].reliable.as_ref().expect("evidence");
        assert_eq!(evidence.acknowledgements,[AckRange{start:1,end:1}]);
        assert_eq!(evidence.sequences,[SequenceEvidence {
            sequence:8,reliability:Reliability::Reliable,
        }]);
        assert!(rep.events[0].reliable.is_none());
    }

    #[test]
    fn keeps_all_sequence_ids_and_acks_without_any_raw_payload() {
        let mut pcap=header(false,false,1);
        let frames=[
            Frame{sequence:9,reliability:Reliability::Reliable,ordering:None,
                payload_bits:8,payload:vec![0x61],split:None},
            Frame{sequence:10,reliability:Reliability::Unreliable,ordering:None,
                payload_bits:8,payload:vec![0x62],split:None},
            Frame{sequence:11,reliability:Reliability::Reliable,ordering:None,
                payload_bits:8,payload:vec![0x63],split:None},
        ];
        let wire=encode_datagram(&[5,6,9],&frames).unwrap();
        add_record(&mut pcap,&ethernet(&ipv4_udp(&wire,0),0),false);
        let report=analyze_pcap(&pcap,Some(7777)).unwrap();
        let ev=report.events[0].reliable.as_ref().unwrap();
        assert_eq!(ev.acknowledgements,[AckRange{start:5,end:6},AckRange{start:9,end:9}]);
        assert_eq!(ev.sequences.iter().map(|x|x.sequence).collect::<Vec<_>>(),
            vec![9,10,11]);
        assert!(!format!("{report:?}").contains("password-secret"));
    }

    #[test]
    fn big_endian_nanoseconds_raw_ipv4_and_port_filter() {
        let mut pcap=header(true,true,101);
        add_record(&mut pcap,&ipv4_udp(&[16,0,0],0),true);
        let report=analyze_pcap(&pcap,None).unwrap();
        assert_eq!(report.resolution,TimestampResolution::Nanoseconds);
        assert_eq!(report.events.len(),1);
        assert_eq!(report.events[0].kind,FrameKind::Offline{profile:"SA-MP",message:"open-request"});
        assert_eq!(analyze_pcap(&pcap,Some(9999)).unwrap().events.len(),0);
    }

    #[test]
    fn vlan_and_linux_cooked_linktypes() {
        for vlan in [1,2] {
            let mut pcap=header(false,false,1);
            add_record(&mut pcap,&ethernet(&ipv4_udp(&[17,0],0),vlan),false);
            assert_eq!(analyze_pcap(&pcap,None).unwrap().events.len(),1);
        }
        for (linktype, prefix) in [(113,vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0]),
                                   (276,vec![8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                                   (0,vec![2,0,0,0])] {
            let mut pcap=header(false,false,linktype);
            let mut frame=prefix;
            frame.extend_from_slice(&ipv4_udp(&[17,0],0));
            add_record(&mut pcap,&frame,false);
            assert_eq!(analyze_pcap(&pcap,None).unwrap().events.len(),1);
        }
    }

    #[test]
    fn skip_fragmented_ipv4_and_malformed_ip_without_crashing() {
        let mut pcap=header(false,false,1);
        add_record(&mut pcap,&ethernet(&ipv4_udp(&[16,0,0],0x2000),0),false);
        add_record(&mut pcap,&ethernet(&ipv4_udp(&[16,0,0],0x0001),0),false);
        add_record(&mut pcap,&[0;3],false);
        let report=analyze_pcap(&pcap,None).unwrap();
        assert_eq!(report.events.len(),0);
        assert_eq!(report.skipped_ip_fragments,2);
        assert_eq!(report.skipped_malformed_packets,1);
    }

    #[test]
    fn truncated_record_unsupported_magic_and_bad_lengths() {
        assert_eq!(analyze_pcap(&[],None),Err(CaptureError::Empty));
        assert_eq!(analyze_pcap(&[0;10],None),Err(CaptureError::Truncated));
        assert_eq!(analyze_pcap(&[0;24],None),Err(CaptureError::BadMagic));
        let wrong=header(false,false,999);
        assert_eq!(analyze_pcap(&wrong,None),Err(CaptureError::UnsupportedLinkType(999)));
        let mut pcap=header(false,false,1);
        add_record(&mut pcap,&[0;14],false);
        pcap.truncate(pcap.len()-3);
        assert_eq!(analyze_pcap(&pcap,None),Err(CaptureError::Truncated));
        let mut malformed=header(false,false,1);
        add_record(&mut malformed,&[0;14],false);
        malformed[24+8..24+12].copy_from_slice(&500_000u32.to_le_bytes());
        assert_eq!(analyze_pcap(&malformed,None),Err(CaptureError::InvalidRecord));
    }

    #[test]
    fn sensitive_payload_is_not_retained_in_trace_summary() {
        let secret=b"SUPER_SECRET_TEST_PASSWORD";
        let packet=ethernet(&ipv4_udp(secret,0),0);
        let mut pcap=header(false,false,1);
        add_record(&mut pcap,&packet,false);
        let report=analyze_pcap(&pcap,None).unwrap();
        let rendered=format!("{report:?}");
        assert!(!rendered.contains("SUPER_SECRET_TEST_PASSWORD"));
        assert_eq!(report.events[0].wire_bytes,secret.len());
    }

    #[test]
    fn reject_oversized_capture_even_with_valid_header() {
        let big=vec![0;MAX_PCAP_BYTES+1];
        assert_eq!(analyze_pcap(&big,None),Err(CaptureError::TooLarge));
    }
}
