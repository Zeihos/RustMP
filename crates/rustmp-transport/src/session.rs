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
use rustmp_protocol::legacy_frame::{decode_datagram, Frame, FrameError, Reliability};
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

#[derive(Default)]
struct OrderingChannel {
    expected: u16,
    pending: BTreeMap<u16, DeliveredMessage>,
    last_sequenced: Option<u16>,
}

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

    /// Atomically decode the whole datagram before updating a verified peer.
    /// Rejects all unknown sources before parsing. This deliberately does
    /// NOT authenticate packets or imply that actual client login works.
    pub fn ingest(&mut self, peer: SocketAddr, bytes: &[u8], now: Instant)
        -> Result<IngestResult, SessionError>
    {
        if !self.peers.contains_key(&peer) { return Err(SessionError::UnknownPeer); }
        let packet = decode_datagram(bytes)?;
        let session = self.peers.get_mut(&peer).ok_or(SessionError::UnknownPeer)?;
        let mut output = IngestResult::default();
        // ACK range decoding validates total expansion before any removal.
        for range in packet.acknowledgements {
            for number in range.start..=range.end {
                if session.resend.acknowledge(number) { output.newly_acknowledged += 1; }
            }
        }
        for frame in packet.frames {
            session.apply_decoded_frame(frame, now, &mut output)?;
        }
        session.last_activity = now;
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
