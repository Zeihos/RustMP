//! Isolated per-peer reliability session coordinator for the legacy SA-MP wire codec.
//!
//! This is NOT wired into the public UDP listener. Only an external, verified
//! connection-handshake implementation may call admit_verified. A RakNet offline
//! ping/open reply is NEVER evidence of an authenticated connection.
//!
//! Source-address equality alone is not authentication. Future production code
//! must verify handshake state, integrity and any encryption before admission.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use rustmp_protocol::ack::encode_ack_prefix;
use rustmp_protocol::legacy_frame::{decode_datagram, encode_datagram, Frame, FrameError, Reliability};
use crate::fragments::{SplitAssembler, SplitError, MAX_GROUP_BYTES};
use crate::reliability::{
    OutboundReliability, PendingAcks, ReceiveDecision, ReceiveWindow, ReliabilityError,
};

pub const MAX_SESSIONS: usize = 128;
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_ORDERED_QUEUE_BYTES: usize = 128 * 1024;
pub const MAX_ORDERED_QUEUE_ITEMS: usize = 128;
pub const MAX_DATAGRAM_EVENTS: usize = 32;
pub const ACKS_PER_FLUSH: usize = 64;
/// Per scheduler invocation, regardless of the number of verified sessions.
pub const MAX_SESSION_RETRIES_PER_POLL: usize = 64;
/// One sender cannot consume the entire retry budget.
pub const MAX_SESSION_RETRIES_PER_PEER: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    UnknownPeer,
    LimitReached,
    Malformed(FrameError),
    Reliability(ReliabilityError),
    Split(SplitError),
    OrderedBacklog,
}

impl From<FrameError> for SessionError {
    fn from(err: FrameError) -> Self { Self::Malformed(err) }
}
impl From<ReliabilityError> for SessionError {
    fn from(err: ReliabilityError) -> Self { Self::Reliability(err) }
}
impl From<SplitError> for SessionError {
    fn from(err: SplitError) -> Self { Self::Split(err) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredMessage {
    pub reliability: Reliability,
    pub ordering: Option<(u8, u16)>,
    pub payload_bits: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub delivered: Vec<DeliveredMessage>,
    pub newly_acknowledged: usize,
    pub duplicates: usize,
}

/// An encoded reliable retry destined for the exact explicitly verified
/// endpoint. The caller must still actually send the UDP datagram.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionRetryDatagram {
    pub peer: SocketAddr,
    pub sequence: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SessionRetryBatch {
    pub packets: Vec<SessionRetryDatagram>,
    /// Entire sessions dropped when any reliable message exhausts retries.
    pub disconnected: Vec<SocketAddr>,
}

#[derive(Clone, Default)]
struct OrderingChannel {
    expected: u16,
    pending: BTreeMap<u16, DeliveredMessage>,
    last_sequenced: Option<u16>,
}

#[derive(Clone)]
struct VerifiedSession {
    last_activity: Instant,
    receive: ReceiveWindow,
    resend: OutboundReliability,
    pending_acks: PendingAcks,
    splits: SplitAssembler,
    channels: Vec<OrderingChannel>,
    queued_bytes: usize,
    queued_items: usize,
}

impl VerifiedSession {
    fn new(now: Instant) -> Self {
        Self {
            last_activity: now,
            receive: ReceiveWindow::default(),
            resend: OutboundReliability::new(Duration::from_millis(250), 5),
            pending_acks: PendingAcks::default(),
            splits: SplitAssembler::new(),
            channels: (0..32).map(|_| OrderingChannel::default()).collect(),
            queued_bytes: 0,
            queued_items: 0,
        }
    }

    fn deliver(&mut self, msg: DeliveredMessage, out: &mut Vec<DeliveredMessage>)
        -> Result<(), SessionError>
    {
        if msg.payload.is_empty() || msg.payload.len() > MAX_GROUP_BYTES {
            return Err(SessionError::OrderedBacklog);
        }
        match msg.reliability {
            Reliability::ReliableOrdered => {
                let (channel_id, index) = msg.ordering.ok_or(SessionError::OrderedBacklog)?;
                let channel = self.channels.get_mut(channel_id as usize)
                    .ok_or(SessionError::OrderedBacklog)?;
                let distance = index.wrapping_sub(channel.expected);
                if distance >= 0x8000 { return Ok(()); } // too old
                if distance == 0 {
                    out.push(msg);
                    channel.expected = channel.expected.wrapping_add(1);
                    while let Some(next) = channel.pending.remove(&channel.expected) {
                        self.queued_bytes -= next.payload.len();
                        self.queued_items -= 1;
                        out.push(next);
                        channel.expected = channel.expected.wrapping_add(1);
                    }
                } else {
                    if distance > MAX_ORDERED_QUEUE_ITEMS as u16 {
                        return Err(SessionError::OrderedBacklog);
                    }
                    if channel.pending.contains_key(&index) { return Ok(()); }
                    if self.queued_items >= MAX_ORDERED_QUEUE_ITEMS
                        || self.queued_bytes + msg.payload.len() > MAX_ORDERED_QUEUE_BYTES
                    {
                        return Err(SessionError::OrderedBacklog);
                    }
                    self.queued_bytes += msg.payload.len();
                    self.queued_items += 1;
                    channel.pending.insert(index, msg);
                }
            }
            Reliability::UnreliableSequenced | Reliability::ReliableSequenced => {
                let (channel_id, index) = msg.ordering.ok_or(SessionError::OrderedBacklog)?;
                let channel = self.channels.get_mut(channel_id as usize)
                    .ok_or(SessionError::OrderedBacklog)?;
                if channel.last_sequenced.is_some_and(|last| {
                    index == last || index.wrapping_sub(last) >= 0x8000
                }) { return Ok(()); }
                channel.last_sequenced = Some(index);
                out.push(msg);
            }
            _ => out.push(msg),
        }
        Ok(())
    }

    fn apply_decoded_frame(&mut self, frame: Frame, now: Instant, output: &mut IngestResult)
        -> Result<(), SessionError>
    {
        if frame.reliability.is_reliable() {
            match self.receive.observe(frame.sequence) {
                ReceiveDecision::New => {
                    self.pending_acks.mark(frame.sequence)?;
                }
                ReceiveDecision::Duplicate | ReceiveDecision::Old => {
                    // Lost ACK may cause a resend. Re-ACK duplicates where space
                    // permits, without redelivering their payload.
                    self.pending_acks.mark(frame.sequence)?;
                    output.duplicates += 1;
                    return Ok(());
                }
                ReceiveDecision::TooFarAhead => {
                    return Err(SessionError::Reliability(ReliabilityError::TooFarAhead));
                }
            }
        }
        let (payload, payload_bits, reliability, ordering) = if frame.split.is_some() {
            match self.splits.insert(frame, now)? {
                Some(msg) => (msg.payload, msg.payload_bits, msg.reliability, msg.ordering),
                None => return Ok(()),
            }
        } else {
            (frame.payload, u32::from(frame.payload_bits), frame.reliability, frame.ordering)
        };
        let message = DeliveredMessage { payload, payload_bits, reliability, ordering };
        self.deliver(message, &mut output.delivered)
    }
}

/// Registry of *explicitly* verified per-peer states. The live RUSTMP UDP
/// listener never creates such sessions until a real handshake is implemented.
#[derive(Default)]
pub struct VerifiedSessions {
    peers: HashMap<SocketAddr, VerifiedSession>,
    /// Resume index into the sorted address snapshot for fair global budgets.
    retry_cursor: usize,
}

impl VerifiedSessions {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.peers.len() }
    pub fn contains(&self, peer: SocketAddr) -> bool { self.peers.contains_key(&peer) }

    /// Only call after a future handshake/integrity layer has verified the peer.
    /// An existing session is not reset on re-admission or retransmission.
    pub fn admit_verified(&mut self, peer: SocketAddr, now: Instant) -> Result<bool, SessionError> {
        if self.peers.contains_key(&peer) { return Ok(false); }
        if self.peers.len() >= MAX_SESSIONS { return Err(SessionError::LimitReached); }
        self.peers.insert(peer, VerifiedSession::new(now));
        Ok(true)
    }

    pub fn disconnect(&mut self, peer: SocketAddr) -> bool {
        self.peers.remove(&peer).is_some()
    }

    pub fn cleanup(&mut self, now: Instant) -> usize {
        let before = self.peers.len();
        self.peers.retain(|_, session| {
            if now.saturating_duration_since(session.last_activity) >= SESSION_IDLE_TIMEOUT {
                false
            } else {
                session.splits.cleanup(now);
                true
            }
        });
        before - self.peers.len()
    }

    pub fn pending_ack_count(&self, peer: SocketAddr) -> Option<usize> {
        self.peers.get(&peer).map(|s| s.pending_acks.len())
    }
    pub fn pending_reliable_count(&self, peer: SocketAddr) -> Option<usize> {
        self.peers.get(&peer).map(|s| s.resend.pending_count())
    }

    /// Track a payload that the caller has actually sent reliably. This is
    /// bookkeeping only, not a datagram encoder or UDP send function.
    pub fn track_sent(&mut self, peer: SocketAddr, bytes: &[u8], now: Instant)
        -> Result<u16, SessionError>
    {
        let session = self.peers.get_mut(&peer).ok_or(SessionError::UnknownPeer)?;
        Ok(session.resend.track_sent(bytes, now)?)
    }

    /// Schedule bounded reliable retransmissions for explicitly verified peers.
    ///
    /// This method DOES NOT admit clients, send sockets, authenticate messages
    /// or connect to the live experimental server. The external transport
    /// must send returned packets and retire disconnected endpoints.
    ///
    /// Work is transactional across the entire scheduler invocation: a wire
    /// encoding error does not consume retries or silently lose datagrams.
    /// A peer with exhausted reliable messages is disconnected (rather than
    /// emitting a partial response which can never complete).
    pub fn poll_retries(&mut self, now: Instant)
        -> Result<SessionRetryBatch, SessionError>
    {
        let mut addrs: Vec<_> = self.peers.keys().copied().collect();
        if addrs.is_empty() {
            self.retry_cursor = 0;
            return Ok(SessionRetryBatch::default());
        }
        addrs.sort_unstable();
        let start = self.retry_cursor % addrs.len();
        let mut visited = 0usize;
        let mut staged: Vec<(SocketAddr, OutboundReliability)> = Vec::new();
        let mut result = SessionRetryBatch::default();

        for offset in 0..addrs.len() {
            if result.packets.len() >= MAX_SESSION_RETRIES_PER_POLL { break; }
            visited += 1;
            let peer = addrs[(start + offset) % addrs.len()];
            let Some(session) = self.peers.get(&peer) else { continue };
            let remaining = MAX_SESSION_RETRIES_PER_POLL - result.packets.len();
            let mut outbound = session.resend.clone();
            let due = outbound.poll_retries(
                now, remaining.min(MAX_SESSION_RETRIES_PER_PEER));
            if !due.abandoned.is_empty() {
                result.disconnected.push(peer);
                continue;
            }
            for resend in due.resend {
                let frame = Frame {
                    sequence: resend.sequence,
                    reliability: Reliability::Reliable,
                    ordering: None,
                    payload_bits: (resend.bytes.len() * 8) as u16,
                    payload: resend.bytes,
                    split: None,
                };
                let bytes = encode_datagram(&[], &[frame])?;
                result.packets.push(SessionRetryDatagram {
                    peer, sequence: resend.sequence, bytes,
                });
            }
            staged.push((peer, outbound));
        }

        for (peer, outbound) in staged {
            if let Some(session) = self.peers.get_mut(&peer) {
                session.resend = outbound;
            }
        }
        for peer in &result.disconnected {
            self.peers.remove(peer);
        }
        self.retry_cursor = (start + visited) % addrs.len();
        Ok(result)
    }

    /// Apply a full datagram transactionally. Previously a late invalid
    /// frame could fail after earlier frames consumed ACKs, receive sequence
    /// numbers or split/ordering queue capacity. A bounded copy of the peer
    /// state is now committed only once every frame has succeeded.
    ///
    /// This is a correctness-first library implementation; cloning per-peer
    /// state costs memory/CPU and should be profiled before production use.
    /// The live UDP server never admits VerifiedSessions as game players.
    pub fn ingest(&mut self, peer: SocketAddr, bytes: &[u8], now: Instant)
        -> Result<IngestResult, SessionError>
    {
        let current = self.peers.get(&peer).ok_or(SessionError::UnknownPeer)?;
        let packet = decode_datagram(bytes)?;
        let mut pending = current.clone();
        let mut output = IngestResult::default();
        // Work exclusively against the private candidate; any error leaves
        // the original ACK queue, receive window and fragment state intact.
        for range in packet.acknowledgements {
            for number in range.start..=range.end {
                if pending.resend.acknowledge(number) { output.newly_acknowledged += 1; }
            }
        }
        for frame in packet.frames {
            pending.apply_decoded_frame(frame, now, &mut output)?;
        }
        pending.last_activity = now;
        self.peers.insert(peer, pending);
        Ok(output)
    }

    /// Serialize buffered ACKs. These should be emitted only by a verified
    /// session transport. On encode failure, keep queued ACKs unchanged.
    pub fn take_ack_prefix(&mut self, peer: SocketAddr) -> Result<Option<Vec<u8>>, SessionError> {
        let session = self.peers.get_mut(&peer).ok_or(SessionError::UnknownPeer)?;
        if session.pending_acks.is_empty() { return Ok(None); }
        let numbers = session.pending_acks.take(ACKS_PER_FLUSH);
        // ACKS_PER_FLUSH is always within the codec's upper bound.
        let encoded = encode_ack_prefix(&numbers).map_err(|e| SessionError::Malformed(FrameError::Ack(e)))?;
        Ok(Some(encoded.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmp_protocol::legacy_frame::{encode_datagram, SplitInfo};

    fn peer(port:u16)->SocketAddr { SocketAddr::from(([127,0,0,1], port)) }
    fn frame(seq:u16, reliability:Reliability, ordering:Option<(u8,u16)>, data:&[u8])->Frame {
        Frame { sequence:seq, reliability, ordering, payload:data.to_vec(),
            payload_bits:(data.len()*8) as u16, split:None }
    }

    #[test]
    fn unknown_peer_rejected_before_processing() {
        let mut sessions=VerifiedSessions::new();
        let raw=encode_datagram(&[], &[frame(0,Reliability::Reliable,None,b"hello")]).unwrap();
        assert_eq!(sessions.ingest(peer(9000),&raw,Instant::now()),Err(SessionError::UnknownPeer));
        assert_eq!(sessions.pending_ack_count(peer(9000)),None);
    }

    #[test]
    fn admission_is_explicit_and_repeated_admit_does_not_reset() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        assert_eq!(s.admit_verified(peer(1),now),Ok(true));
        assert_eq!(s.admit_verified(peer(1),now),Ok(false));
        assert_eq!(s.track_sent(peer(1),b"msg",now),Ok(0));
        assert_eq!(s.admit_verified(peer(1),now),Ok(false));
        assert_eq!(s.pending_reliable_count(peer(1)),Some(1));
        assert!(s.disconnect(peer(1)));
        assert_eq!(s.pending_reliable_count(peer(1)),None);
    }

    #[test]
    fn reliable_data_ack_and_duplicates() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        s.admit_verified(peer(2),now).unwrap();
        for _ in 0..4 { s.track_sent(peer(2),b"sent",now).unwrap(); }
        let datagram=encode_datagram(&[1,2],&[frame(0,Reliability::Reliable,None,b"hello")]).unwrap();
        let first=s.ingest(peer(2),&datagram,now).unwrap();
        assert_eq!(first.newly_acknowledged,2);
        assert_eq!(first.delivered[0].payload,b"hello");
        assert_eq!(s.pending_reliable_count(peer(2)),Some(2));
        assert_eq!(s.pending_ack_count(peer(2)),Some(1));
        let repeat=s.ingest(peer(2),&datagram,now).unwrap();
        assert_eq!(repeat.duplicates,1);
        assert!(repeat.delivered.is_empty());
        assert_eq!(repeat.newly_acknowledged,0);
        assert_eq!(s.take_ack_prefix(peer(2)).unwrap(),
            Some(encode_ack_prefix(&[0]).unwrap().bytes));
    }

    #[test]
    fn peer_state_is_isolated_and_spoofed_socket_cannot_ack() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        s.admit_verified(peer(3),now).unwrap();
        s.admit_verified(peer(4),now).unwrap();
        s.track_sent(peer(3),b"x",now).unwrap();
        s.track_sent(peer(4),b"y",now).unwrap();
        let ack=encode_datagram(&[0],&[]).unwrap();
        assert_eq!(s.ingest(peer(5),&ack,now),Err(SessionError::UnknownPeer));
        assert_eq!(s.ingest(peer(3),&ack,now).unwrap().newly_acknowledged,1);
        assert_eq!(s.pending_reliable_count(peer(4)),Some(1));
    }

    #[test]
    fn ordered_out_of_order_and_sequenced_drop_old() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        s.admit_verified(peer(5),now).unwrap();
        let f1=frame(1,Reliability::ReliableOrdered,Some((1,1)),b"second");
        let f0=frame(0,Reliability::ReliableOrdered,Some((1,0)),b"first");
        assert!(s.ingest(peer(5),&encode_datagram(&[],&[f1]).unwrap(),now).unwrap().delivered.is_empty());
        let result=s.ingest(peer(5),&encode_datagram(&[],&[f0]).unwrap(),now).unwrap();
        assert_eq!(result.delivered.len(),2);
        assert_eq!(result.delivered[0].payload,b"first");
        assert_eq!(result.delivered[1].payload,b"second");
        let f=frame(2,Reliability::UnreliableSequenced,Some((3,10)),b"new");
        assert_eq!(s.ingest(peer(5),&encode_datagram(&[],&[f]).unwrap(),now).unwrap().delivered.len(),1);
        let old=frame(3,Reliability::UnreliableSequenced,Some((3,9)),b"old");
        assert!(s.ingest(peer(5),&encode_datagram(&[],&[old]).unwrap(),now).unwrap().delivered.is_empty());
    }

    #[test]
    fn fragmented_message_is_delivered_only_when_complete() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        s.admit_verified(peer(6),now).unwrap();
        let mut first=frame(0,Reliability::ReliableOrdered,Some((0,0)),b"one");
        let mut last=frame(1,Reliability::ReliableOrdered,Some((0,0)),b"two");
        first.split=Some(SplitInfo{id:12,index:0,count:2});
        last.split=Some(SplitInfo{id:12,index:1,count:2});
        let x=s.ingest(peer(6),&encode_datagram(&[],&[last]).unwrap(),now).unwrap();
        assert!(x.delivered.is_empty());
        let x=s.ingest(peer(6),&encode_datagram(&[],&[first]).unwrap(),now).unwrap();
        assert_eq!(x.delivered.len(),1);
        assert_eq!(x.delivered[0].payload,b"onetwo");
    }

    #[test]
    fn invalid_datagram_does_not_mutate_outbound_ack_queue() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        s.admit_verified(peer(7),now).unwrap();
        s.track_sent(peer(7),b"hello",now).unwrap();
        let valid=encode_datagram(&[0],&[frame(0,Reliability::Reliable,None,b"ok")]).unwrap();
        let truncated=&valid[..valid.len()-1];
        assert!(s.ingest(peer(7),truncated,now).is_err());
        assert_eq!(s.pending_reliable_count(peer(7)),Some(1));
        assert_eq!(s.pending_ack_count(peer(7)),Some(0));
    }

    #[test]
    fn later_invalid_frame_rolls_back_ack_receive_window_and_delivery() {
        let now = Instant::now();
        let addr = peer(7000);
        let mut sessions = VerifiedSessions::new();
        sessions.admit_verified(addr, now).unwrap();
        sessions.track_sent(addr, b"server_response", now).unwrap();

        let first = frame(0, Reliability::Reliable, None, b"first");
        // Encodable on the wire, but unacceptable to the bounded ordered
        // delivery queue: index 129 is farther than its limit of 128.
        let invalid = frame(1, Reliability::ReliableOrdered,
            Some((0, (MAX_ORDERED_QUEUE_ITEMS + 1) as u16)), b"late");
        let combined = encode_datagram(&[0], &[first.clone(), invalid]).unwrap();

        assert_eq!(sessions.ingest(addr, &combined, now),
            Err(SessionError::OrderedBacklog));
        // Neither the valid first frame nor the piggyback ACK was committed.
        assert_eq!(sessions.pending_reliable_count(addr), Some(1));
        assert_eq!(sessions.pending_ack_count(addr), Some(0));

        let correct = encode_datagram(&[0], &[first]).unwrap();
        let delivered = sessions.ingest(addr, &correct, now).unwrap();
        assert_eq!(delivered.newly_acknowledged, 1);
        assert_eq!(delivered.duplicates, 0);
        assert_eq!(delivered.delivered.len(), 1);
        assert_eq!(delivered.delivered[0].payload, b"first");
        assert_eq!(sessions.pending_reliable_count(addr), Some(0));
        assert_eq!(sessions.pending_ack_count(addr), Some(1));
    }

    #[test]
    fn invalid_ordered_frame_does_not_change_last_activity_or_expire_window() {
        let now = Instant::now();
        let addr = peer(7001);
        let mut sessions = VerifiedSessions::new();
        sessions.admit_verified(addr, now).unwrap();
        let failing = encode_datagram(&[], &[frame(
            0, Reliability::ReliableOrdered,
            Some((1, (MAX_ORDERED_QUEUE_ITEMS + 1) as u16)), b"too-far",
        )]).unwrap();
        let later = now + Duration::from_secs(50);
        assert_eq!(sessions.ingest(addr, &failing, later),
            Err(SessionError::OrderedBacklog));
        assert_eq!(sessions.pending_ack_count(addr), Some(0));
        // A failed packet cannot artificially keep an idle session alive.
        assert_eq!(sessions.cleanup(now + SESSION_IDLE_TIMEOUT), 1);
    }

    #[test]
    fn verified_retry_encodes_same_sequence_and_ack_stops_future_retries() {
        let now = Instant::now();
        let addr = peer(7300);
        let mut sessions = VerifiedSessions::new();
        sessions.admit_verified(addr, now).unwrap();
        assert_eq!(sessions.track_sent(addr, b"reliable-response", now), Ok(0));
        assert!(sessions.poll_retries(now + Duration::from_millis(249))
            .unwrap().packets.is_empty());
        let result = sessions.poll_retries(now + Duration::from_millis(250)).unwrap();
        assert!(result.disconnected.is_empty());
        assert_eq!(result.packets.len(), 1);
        assert_eq!(result.packets[0].peer, addr);
        assert_eq!(result.packets[0].sequence, 0);
        let decoded = decode_datagram(&result.packets[0].bytes).unwrap();
        assert_eq!(decoded.frames.len(), 1);
        assert_eq!(decoded.frames[0].sequence, 0);
        assert_eq!(decoded.frames[0].payload, b"reliable-response");
        let ack = encode_datagram(&[0], &[]).unwrap();
        assert_eq!(sessions.ingest(addr, &ack, now + Duration::from_millis(260))
            .unwrap().newly_acknowledged, 1);
        assert_eq!(sessions.pending_reliable_count(addr), Some(0));
        assert!(sessions.poll_retries(now + Duration::from_secs(1))
            .unwrap().packets.is_empty());
    }

    #[test]
    fn verified_retry_global_limit_rotates_across_more_than_64_peers() {
        use std::collections::HashSet;
        let now = Instant::now();
        let mut sessions = VerifiedSessions::new();
        let count = MAX_SESSION_RETRIES_PER_POLL + 8;
        for n in 0..count {
            let addr = peer(13000 + n as u16);
            sessions.admit_verified(addr, now).unwrap();
            sessions.track_sent(addr, b"ping", now).unwrap();
        }
        let first = sessions.poll_retries(now + Duration::from_millis(250)).unwrap();
        assert_eq!(first.packets.len(), MAX_SESSION_RETRIES_PER_POLL);
        assert_eq!(first.packets.iter().map(|x|x.peer).collect::<HashSet<_>>().len(),
            MAX_SESSION_RETRIES_PER_POLL);
        let second = sessions.poll_retries(now + Duration::from_millis(500)).unwrap();
        assert_eq!(second.packets.len(), MAX_SESSION_RETRIES_PER_POLL);
        let seen: HashSet<_> = first.packets.iter().chain(second.packets.iter())
            .map(|p|p.peer).collect();
        assert_eq!(seen.len(), count);
        assert_eq!(sessions.len(), count);
        assert!(first.disconnected.is_empty() && second.disconnected.is_empty());
    }

    #[test]
    fn verified_retry_per_peer_budget_prioritizes_unretried_messages() {
        let now = Instant::now();
        let addr = peer(7301);
        let mut sessions = VerifiedSessions::new();
        sessions.admit_verified(addr, now).unwrap();
        for _ in 0..10 {
            sessions.track_sent(addr, b"payload", now).unwrap();
        }
        let first = sessions.poll_retries(now + Duration::from_millis(250)).unwrap();
        assert_eq!(first.packets.iter().map(|p|p.sequence).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]);
        let second = sessions.poll_retries(now + Duration::from_millis(500)).unwrap();
        assert_eq!(second.packets.iter().map(|p|p.sequence).collect::<Vec<_>>(),
            vec![4, 5, 6, 7]);
        let third = sessions.poll_retries(now + Duration::from_millis(750)).unwrap();
        assert_eq!(third.packets.iter().map(|p|p.sequence).collect::<Vec<_>>(),
            vec![8, 9, 0, 1]);
        assert_eq!(sessions.pending_reliable_count(addr), Some(10));
    }

    #[test]
    fn exhausted_verified_session_disconnects_without_starving_other_peer() {
        let now = Instant::now();
        let exhausted = peer(7302);
        let fresh = peer(7303);
        let mut sessions = VerifiedSessions::new();
        sessions.admit_verified(exhausted, now).unwrap();
        sessions.track_sent(exhausted, b"abandoned", now).unwrap();
        for attempt in 1..=5 {
            let batch = sessions.poll_retries(now + Duration::from_millis(250*attempt))
                .unwrap();
            assert_eq!(batch.packets.len(), 1);
            assert!(batch.disconnected.is_empty());
        }
        sessions.admit_verified(fresh, now + Duration::from_millis(1250)).unwrap();
        sessions.track_sent(fresh, b"new", now + Duration::from_millis(1250)).unwrap();
        let batch = sessions.poll_retries(now + Duration::from_millis(1500)).unwrap();
        assert_eq!(batch.disconnected, vec![exhausted]);
        assert_eq!(batch.packets.len(), 1);
        assert_eq!(batch.packets[0].peer, fresh);
        assert!(!sessions.contains(exhausted));
        assert!(sessions.contains(fresh));
    }

    #[test]
    fn retry_scheduler_does_not_refresh_peer_idle_lifetime() {
        let now = Instant::now();
        let addr = peer(7304);
        let mut sessions = VerifiedSessions::new();
        sessions.admit_verified(addr, now).unwrap();
        sessions.track_sent(addr, b"unacked", now).unwrap();
        assert_eq!(sessions.poll_retries(now + Duration::from_millis(250))
            .unwrap().packets.len(), 1);
        assert_eq!(sessions.cleanup(now + SESSION_IDLE_TIMEOUT), 1);
        assert!(sessions.poll_retries(now + SESSION_IDLE_TIMEOUT)
            .unwrap().packets.is_empty());
    }

    #[test]
    fn stale_session_eviction_and_caps() {
        let now=Instant::now();
        let mut s=VerifiedSessions::new();
        for n in 1..=MAX_SESSIONS {
            s.admit_verified(peer(n as u16),now).unwrap();
        }
        assert_eq!(s.admit_verified(peer(900),now),Err(SessionError::LimitReached));
        assert_eq!(s.cleanup(now+SESSION_IDLE_TIMEOUT),MAX_SESSIONS);
        assert_eq!(s.len(),0);
        assert_eq!(s.admit_verified(peer(900),now+SESSION_IDLE_TIMEOUT),Ok(true));
    }
}
