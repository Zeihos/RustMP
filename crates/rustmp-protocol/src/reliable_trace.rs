//! Correlate observed legacy reliable RakNet sequences and opposite-direction
//! ACKs in a bounded, metadata-only classic PCAP capture.
//!
//! "Outstanding" means no matching acknowledgement was *captured*, NOT
//! actual packet loss. A packet can be missing due to incomplete capture,
//! capture filters, delayed ACKs or because this is a synthetic protocol.
//! No client identity or authentication state is inferred from socket address.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddrV4;

use crate::capture::{CaptureReport, ReliableEvidence, UdpEvent};

/// Limit of distinct client/server endpoint pairs being correlated.
pub const MAX_RELIABLE_FLOWS: usize = 1024;
/// Per direction; do not allocate an unbounded sequence history for traffic
/// with no ACKs. Values beyond the cap are reported as untracked.
pub const MAX_PENDING_SEQUENCES: usize = 512;
/// Recently acknowledged IDs remembered separately for each direction.
/// Only metadata is stored. After eviction, reuse/duplicate classification
/// becomes uncertain; never infer client sessions or packet loss from it.
pub const MAX_RECENT_ACKNOWLEDGEMENTS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReliableTraceError {
    InvalidServerPort,
    TooManyFlows,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReliableFlow {
    pub client: SocketAddrV4,
    pub server: SocketAddrV4,
    pub first_record: usize,
    pub last_record: usize,
    pub client_frames: usize,
    pub server_frames: usize,
    pub client_retransmissions: usize,
    pub server_retransmissions: usize,
    /// Reliable IDs observed AGAIN after their ACK was captured. Could also
    /// represent legitimate reuse or a new session with the same endpoints.
    pub client_reused_after_ack: usize,
    pub server_reused_after_ack: usize,
    pub client_confirmed: usize,
    pub server_confirmed: usize,
    /// ACK sequence numbers with no matching outstanding frame IN THIS CAPTURE.
    pub unmatched_acks: usize,
    /// ACKs for sequences already acknowledged in this capture's bounded
    /// history (different from ACKs with no observed sender).
    pub repeated_acks: usize,
    pub outstanding_client: usize,
    pub outstanding_server: usize,
    /// New sequences omitted from tracking due to the bounded memory limit.
    pub untracked_frames: usize,
}

impl ReliableFlow {
    fn new(client: SocketAddrV4, server: SocketAddrV4, record: usize) -> Self {
        Self {
            client, server, first_record: record, last_record: record,
            client_frames: 0, server_frames: 0,
            client_retransmissions: 0, server_retransmissions: 0,
            client_reused_after_ack: 0, server_reused_after_ack: 0,
            client_confirmed: 0, server_confirmed: 0,
            unmatched_acks: 0, repeated_acks: 0,
            outstanding_client: 0, outstanding_server: 0,
            untracked_frames: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReliableTraceReport {
    pub server_port: u16,
    pub flows: Vec<ReliableFlow>,
    pub ignored_events: usize,
}

/// Most recently acknowledged message numbers, in observed ACK order.
/// Pending and confirmed message numbers are intentionally separate:
/// retransmits after acknowledgement must not create a second pending entry.
#[derive(Default)]
struct AckHistory {
    remembered: BTreeSet<u16>,
    oldest_first: VecDeque<u16>,
}

impl AckHistory {
    fn contains(&self, seq: u16) -> bool {
        self.remembered.contains(&seq)
    }

    fn remember(&mut self, seq: u16) {
        if !self.remembered.insert(seq) {
            return;
        }
        self.oldest_first.push_back(seq);
        if self.oldest_first.len() > MAX_RECENT_ACKNOWLEDGEMENTS {
            if let Some(old) = self.oldest_first.pop_front() {
                self.remembered.remove(&old);
            }
        }
    }
}

struct Tracker {
    summary: ReliableFlow,
    pending_client: BTreeSet<u16>,
    pending_server: BTreeSet<u16>,
    acknowledged_client: AckHistory,
    acknowledged_server: AckHistory,
}

impl Tracker {
    fn new(client: SocketAddrV4, server: SocketAddrV4, n: usize) -> Self {
        Self {
            summary: ReliableFlow::new(client, server, n),
            pending_client: BTreeSet::new(),
            pending_server: BTreeSet::new(),
            acknowledged_client: AckHistory::default(),
            acknowledged_server: AckHistory::default(),
        }
    }

    fn record(&mut self, observed: &ReliableEvidence, to_server: bool) {
        // ACKs on the client->server path acknowledge server-originated
        // reliable sequences, and vice versa. Range expansion is bounded
        // by the legacy ACK decoder (at most 512 sequence numbers).
        let (opposite, history) = if to_server {
            (&mut self.pending_server, &mut self.acknowledged_server)
        } else {
            (&mut self.pending_client, &mut self.acknowledged_client)
        };
        let mut new_acks = 0usize;
        let mut repeated_acks = 0usize;
        let mut unmatched_acks = 0usize;
        for range in &observed.acknowledgements {
            for seq in range.start..=range.end {
                if opposite.remove(&seq) {
                    history.remember(seq);
                    new_acks += 1;
                } else if history.contains(seq) {
                    repeated_acks += 1;
                } else {
                    unmatched_acks += 1;
                }
            }
        }
        if to_server {
            self.summary.server_confirmed += new_acks;
        } else {
            self.summary.client_confirmed += new_acks;
        }
        self.summary.repeated_acks += repeated_acks;
        self.summary.unmatched_acks += unmatched_acks;

        let (pending, history) = if to_server {
            (&mut self.pending_client, &self.acknowledged_client)
        } else {
            (&mut self.pending_server, &self.acknowledged_server)
        };
        let mut frames = 0usize;
        let mut retransmissions = 0usize;
        let mut after_ack = 0usize;
        let mut untracked = 0usize;
        for frame in &observed.sequences {
            if !frame.reliability.is_reliable() {
                continue;
            }
            frames += 1;
            if pending.contains(&frame.sequence) {
                retransmissions += 1;
            } else if history.contains(frame.sequence) {
                // Do not re-open an already ACKed sequence. An identical ID
                // could also be a new session/reuse after wrap; the report
                // deliberately avoids claiming an actual retransmission.
                after_ack += 1;
            } else if pending.len() >= MAX_PENDING_SEQUENCES {
                untracked += 1;
            } else {
                pending.insert(frame.sequence);
            }
        }
        if to_server {
            self.summary.client_frames += frames;
            self.summary.client_retransmissions += retransmissions;
            self.summary.client_reused_after_ack += after_ack;
        } else {
            self.summary.server_frames += frames;
            self.summary.server_retransmissions += retransmissions;
            self.summary.server_reused_after_ack += after_ack;
        }
        self.summary.untracked_frames += untracked;
    }
}

/// Analyze pairs of **exact** IPv4 endpoints at a known server port, with
/// separate client/server sequence spaces. Frames/ACKs seen outside the
/// capture interval cannot be reconstructed. Reusing a sequence after ACK
/// could also be a legitimate new session (no session ID is visible).
pub fn analyze_reliable_flows(
    report: &CaptureReport,
    server_port: u16,
) -> Result<ReliableTraceReport, ReliableTraceError> {
    if server_port == 0 {
        return Err(ReliableTraceError::InvalidServerPort);
    }
    let mut trackers: Vec<Tracker> = Vec::new();
    let mut indexes: HashMap<(SocketAddrV4, SocketAddrV4), usize> = HashMap::new();
    let mut ignored_events = 0;
    for event in &report.events {
        let Some(evidence) = event.reliable.as_ref() else { continue };
        // Ignore packets that contain neither reliable frames nor ACKs.
        if evidence.acknowledgements.is_empty()
            && !evidence.sequences.iter().any(|frame| frame.reliability.is_reliable())
        {
            continue;
        }
        let to_server = event.destination.port() == server_port
            && event.source.port() != server_port;
        let from_server = event.source.port() == server_port
            && event.destination.port() != server_port;
        if !to_server && !from_server {
            ignored_events += 1;
            continue;
        }
        let (client, server) = if to_server {
            (event.source, event.destination)
        } else {
            (event.destination, event.source)
        };
        let key = (client, server);
        let index = if let Some(&index) = indexes.get(&key) {
            index
        } else {
            if trackers.len() >= MAX_RELIABLE_FLOWS {
                return Err(ReliableTraceError::TooManyFlows);
            }
            let index = trackers.len();
            trackers.push(Tracker::new(client, server, event.record));
            indexes.insert(key, index);
            index
        };
        let tracker = &mut trackers[index];
        tracker.summary.last_record = event.record;
        tracker.record(evidence, to_server);
    }
    let flows = trackers.into_iter().map(|mut tracker| {
        tracker.summary.outstanding_client = tracker.pending_client.len();
        tracker.summary.outstanding_server = tracker.pending_server.len();
        tracker.summary
    }).collect();
    Ok(ReliableTraceReport {
        server_port, flows, ignored_events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ack::AckRange;
    use crate::capture::{CaptureReport, FrameKind, ReliableEvidence,
        SequenceEvidence, TimestampResolution};
    use crate::legacy_frame::Reliability;
    use std::net::Ipv4Addr;

    fn addr(ip:u8, port:u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192,0,2,ip),port)
    }
    fn record(n:usize, source:SocketAddrV4, destination:SocketAddrV4,
              sequences:&[(u16,Reliability)], acks:&[u16]) -> UdpEvent {
        UdpEvent {
            record:n, seconds:10, fraction:n as u32, source, destination,
            wire_bytes:16,
            kind:FrameKind::Reliable {
                ack_ranges:acks.len(), frames:sequences.len(), first:None,
            },
            reliable:Some(ReliableEvidence {
                acknowledgements:acks.iter().copied().map(|seq|AckRange {
                    start:seq,end:seq,
                }).collect(),
                sequences:sequences.iter().copied().map(|(sequence,reliability)|
                    SequenceEvidence{sequence,reliability}
                ).collect(),
            }),
        }
    }
    fn report(events:Vec<UdpEvent>)->CaptureReport {
        CaptureReport {
            resolution:TimestampResolution::Microseconds,
            records:events.len(),udp_seen:events.len(),events,
            skipped_ip_fragments:0,skipped_malformed_packets:0,
        }
    }

    #[test]
    fn bidirectional_ack_matches_only_the_opposite_sender() {
        let (client,server)=(addr(1,50000),addr(2,7777));
        let reliable=Reliability::Reliable;
        let input=report(vec![
            record(1,client,server,&[(1,reliable),(2,reliable)],&[]),
            record(2,server,client,&[(8,reliable)],&[1,2]),
            record(3,client,server,&[],&[8]),
        ]);
        let result=analyze_reliable_flows(&input,7777).unwrap();
        assert_eq!(result.flows.len(),1);
        let flow=&result.flows[0];
        assert_eq!((flow.client_frames,flow.server_frames),(2,1));
        assert_eq!((flow.client_confirmed,flow.server_confirmed),(2,1));
        assert_eq!((flow.outstanding_client,flow.outstanding_server),(0,0));
        assert_eq!(flow.unmatched_acks,0);
    }

    #[test]
    fn retransmit_in_same_direction_is_counted_without_double_outstanding() {
        let (client,server)=(addr(1,50001),addr(2,7777));
        let rel=Reliability::Reliable;
        let result=analyze_reliable_flows(&report(vec![
            record(1,client,server,&[(0,rel)],&[]),
            record(2,client,server,&[(0,rel)],&[]),
            record(3,server,client,&[],&[0]),
        ]),7777).unwrap();
        let flow=&result.flows[0];
        assert_eq!(flow.client_frames,2);
        assert_eq!(flow.client_retransmissions,1);
        assert_eq!(flow.client_confirmed,1);
        assert_eq!(flow.outstanding_client,0);
    }

    #[test]
    fn missing_ack_is_only_missing_in_the_observed_capture() {
        let (client,server)=(addr(1,50002),addr(2,7777));
        let result=analyze_reliable_flows(&report(vec![
            record(1,server,client,&[(9,Reliability::Reliable)],&[]),
        ]),7777).unwrap();
        assert_eq!(result.flows[0].outstanding_server,1);
        assert_eq!(result.flows[0].server_confirmed,0);
    }

    #[test]
    fn unreliable_frames_are_not_mistaken_for_missing_reliable_acks() {
        let (client,server)=(addr(1,50003),addr(2,7777));
        let result=analyze_reliable_flows(&report(vec![
            record(1,client,server,&[(3,Reliability::Unreliable)],&[]),
            record(2,client,server,&[(4,Reliability::Reliable)],&[]),
        ]),7777).unwrap();
        assert_eq!(result.flows.len(),1);
        assert_eq!(result.flows[0].client_frames,1);
        assert_eq!(result.flows[0].outstanding_client,1);
    }

    #[test]
    fn orphan_ack_is_not_evidence_of_spoofing_or_a_bug() {
        let (client,server)=(addr(1,50004),addr(2,7777));
        let result=analyze_reliable_flows(&report(vec![
            record(1,server,client,&[],&[2,3]),
        ]),7777).unwrap();
        assert_eq!(result.flows[0].unmatched_acks,2);
        assert_eq!(result.flows[0].outstanding_client,0);
    }

    #[test]
    fn acked_message_reappearing_does_not_reopen_outstanding_and_repeated_ack_is_known() {
        let (c,s)=(addr(1,51000),addr(2,7777));
        let rel=Reliability::Reliable;
        let result=analyze_reliable_flows(&report(vec![
            record(1,c,s,&[(17,rel)],&[]),
            record(2,s,c,&[],&[17]),
            record(3,c,s,&[(17,rel)],&[]),
            record(4,s,c,&[],&[17]),
        ]),7777).unwrap();
        let f=&result.flows[0];
        assert_eq!(f.client_frames,2);
        assert_eq!(f.client_confirmed,1);
        assert_eq!(f.client_retransmissions,0);
        assert_eq!(f.client_reused_after_ack,1);
        assert_eq!(f.repeated_acks,1);
        assert_eq!(f.unmatched_acks,0);
        assert_eq!(f.outstanding_client,0);
    }

    #[test]
    fn acknowledgements_and_reuse_are_direction_specific() {
        let (c,s)=(addr(1,51001),addr(2,7777));
        let rel=Reliability::Reliable;
        let result=analyze_reliable_flows(&report(vec![
            record(1,c,s,&[(4,rel)],&[]),
            record(2,s,c,&[(4,rel)],&[4]),
            record(3,c,s,&[(4,rel)],&[4]),
            record(4,s,c,&[(4,rel)],&[4]),
        ]),7777).unwrap();
        let f=&result.flows[0];
        assert_eq!(f.client_confirmed,1);
        assert_eq!(f.server_confirmed,1);
        assert_eq!(f.client_reused_after_ack,1);
        assert_eq!(f.server_reused_after_ack,1);
        assert_eq!(f.repeated_acks,1);
        assert_eq!(f.outstanding_client,0);
        assert_eq!(f.outstanding_server,0);
    }

    #[test]
    fn recent_ack_history_is_bounded_and_old_ids_cannot_force_memory_growth() {
        let mut h=AckHistory::default();
        for seq in 0..(MAX_RECENT_ACKNOWLEDGEMENTS as u16+25) {
            h.remember(seq);
        }
        assert_eq!(h.oldest_first.len(),MAX_RECENT_ACKNOWLEDGEMENTS);
        assert_eq!(h.remembered.len(),MAX_RECENT_ACKNOWLEDGEMENTS);
        assert!(!h.contains(0));
        assert!(!h.contains(24));
        assert!(h.contains(25));
        assert!(h.contains(MAX_RECENT_ACKNOWLEDGEMENTS as u16+24));
        h.remember(25); // Duplicates must not extend retention or grow state.
        assert_eq!(h.oldest_first.len(),MAX_RECENT_ACKNOWLEDGEMENTS);
    }

    #[test]
    fn source_ports_and_server_addresses_are_isolated() {
        let s=addr(2,7777);
        let rel=Reliability::Reliable;
        let result=analyze_reliable_flows(&report(vec![
            record(1,addr(1,50005),s,&[(0,rel)],&[]),
            record(2,addr(1,50006),s,&[(0,rel)],&[]),
            record(3,addr(1,50005),addr(3,7777),&[(0,rel)],&[]),
            record(4,s,addr(1,50005),&[],&[0]),
        ]),7777).unwrap();
        assert_eq!(result.flows.len(),3);
        assert_eq!(result.flows[0].outstanding_client,0);
        assert_eq!(result.flows[1].outstanding_client,1);
        assert_eq!(result.flows[2].outstanding_client,1);
    }

    #[test]
    fn bounded_tracking_does_not_allow_unlimited_unaudited_sequences() {
        let (c,s)=(addr(1,50007),addr(2,7777));
        let events=(0..MAX_PENDING_SEQUENCES+10)
            .map(|n|record(n+1,c,s,&[(n as u16,Reliability::Reliable)],&[]))
            .collect();
        let result=analyze_reliable_flows(&report(events),7777).unwrap();
        assert_eq!(result.flows[0].outstanding_client,MAX_PENDING_SEQUENCES);
        assert_eq!(result.flows[0].untracked_frames,10);
    }

    #[test]
    fn rejects_more_flows_than_bounded_cap_and_ambiguous_ports() {
        let s=addr(2,7777);
        let rel=Reliability::Reliable;
        let events=(0..=MAX_RELIABLE_FLOWS)
            .map(|n|record(n+1,addr((n/60000+1) as u8,10000+n as u16),
                s,&[(0,rel)],&[])).collect();
        assert_eq!(analyze_reliable_flows(&report(events),7777),
            Err(ReliableTraceError::TooManyFlows));
        let result=analyze_reliable_flows(&report(vec![
            record(1,addr(1,7777),s,&[(0,rel)],&[]),
        ]),7777).unwrap();
        assert_eq!(result.ignored_events,1);
        assert_eq!(analyze_reliable_flows(&report(vec![]),0),
            Err(ReliableTraceError::InvalidServerPort));
    }
}
