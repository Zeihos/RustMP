//! Reliable pre-auth RakNet exchange (library-only).
//!
//! Composes the alpha.9 handshake transcript with alpha.3 retransmission,
//! ACK bookkeeping and the alpha.5 wire codec. A production UDP listener must
//! still implement verified cookie exchange, outbound scheduling, encryption,
//! authoritative peer identity and full game login before enabling this.
//! In particular, no pre-auth handshake result is automatically admitted to
//! VerifiedSessions or the gameplay World.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use rustmp_protocol::legacy_frame::{
    decode_datagram, encode_datagram, Frame, FrameError, Reliability,
};
use crate::handshake::{
    AuthPair, HandshakeCoordinator, HandshakeError, HandshakePhase,
};
use crate::reliability::{
    OutboundReliability, PendingAcks, ReceiveDecision, ReceiveWindow,
    ReliabilityError,
};
use crate::{LegacyWireProfile, OfflineGateway};

pub const MAX_RELIABLE_PREAUTH: usize = 128;
pub const MAX_RETRIES_PER_POLL: usize = 16;
pub const MAX_ACKS_PER_FRAME: usize = 64;
/// Global cap for a single scheduler poll; prevents one tick from emitting
/// thousands of datagrams during a connection flood.
pub const MAX_RESEND_DATAGRAMS_PER_POLL: usize = 64;
pub const PREAUTH_RETRY_DELAY: Duration = Duration::from_millis(300);
pub const PREAUTH_MAX_RETRIES: u8 = 5;
pub const PREAUTH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreAuthError {
    UnknownPeer,
    Capacity,
    Expired,
    UnexpectedFrame,
    Malformed(FrameError),
    Handshake(HandshakeError),
    Reliability(ReliabilityError),
}

impl From<FrameError> for PreAuthError {
    fn from(v: FrameError) -> Self { Self::Malformed(v) }
}
impl From<HandshakeError> for PreAuthError {
    fn from(v: HandshakeError) -> Self { Self::Handshake(v) }
}
impl From<ReliabilityError> for PreAuthError {
    fn from(v: ReliabilityError) -> Self { Self::Reliability(v) }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExchangeResult {
    /// Serialized reliable RakNet datagrams ready for a caller to send.
    pub outgoing: Vec<Vec<u8>>,
    /// Set only after final connection confirmation. This is not game login.
    pub transport_confirmed: bool,
    pub acknowledged: usize,
    pub duplicate_messages: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RetryDatagram {
    pub peer: SocketAddr,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetryResult {
    /// Each retransmission retains its original recipient and message number.
    pub packets: Vec<RetryDatagram>,
    /// Failed pre-auth peers whose retries have been exhausted.
    pub disconnected: Vec<SocketAddr>,
}

struct Peer {
    created: Instant,
    incoming: ReceiveWindow,
    outgoing: OutboundReliability,
    acks: PendingAcks,
}

impl Peer {
    fn new(now: Instant) -> Self {
        Self {
            created: now,
            incoming: ReceiveWindow::default(),
            outgoing: OutboundReliability::new(PREAUTH_RETRY_DELAY, PREAUTH_MAX_RETRIES),
            acks: PendingAcks::default(),
        }
    }

    fn encode_outbound(&mut self, payload: &[u8], now: Instant) -> Result<Vec<u8>, PreAuthError> {
        if payload.len() > 255 {
            return Err(PreAuthError::UnexpectedFrame);
        }
        // Keep ACKs queued until a datagram is successfully encoded.
        let ack_numbers = self.acks.take(MAX_ACKS_PER_FRAME);
        let id = match self.outgoing.track_sent(payload, now) {
            Ok(seq) => seq,
            Err(err) => {
                for ack in ack_numbers { self.acks.mark(ack)?; }
                return Err(PreAuthError::Reliability(err));
            }
        };
        let frame = Frame {
            sequence: id,
            reliability: Reliability::Reliable,
            ordering: None,
            payload_bits: (payload.len() * 8) as u16,
            payload: payload.to_vec(),
            split: None,
        };
        match encode_datagram(&ack_numbers, &[frame]) {
            Ok(packet) => Ok(packet),
            Err(err) => {
                self.outgoing.acknowledge(id);
                for ack in ack_numbers { self.acks.mark(ack)?; }
                Err(PreAuthError::Malformed(err))
            }
        }
    }

    fn ack_only(&mut self) -> Result<Option<Vec<u8>>, PreAuthError> {
        if self.acks.is_empty() { return Ok(None); }
        let numbers = self.acks.take(MAX_ACKS_PER_FRAME);
        match encode_datagram(&numbers, &[]) {
            Ok(packet) => Ok(Some(packet)),
            Err(err) => {
                for ack in numbers { self.acks.mark(ack)?; }
                Err(PreAuthError::Malformed(err))
            }
        }
    }
}

/// Bounded coordinator. It does NOT own a UDP socket, never marks players as
/// logged in, and cannot skip the offline gateway prerequisite.
#[derive(Default)]
pub struct PreAuthExchange {
    handshakes: HandshakeCoordinator,
    peers: HashMap<SocketAddr, Peer>,
}

impl PreAuthExchange {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.peers.len() }
    pub fn pending_retries(&self, peer: SocketAddr) -> Option<usize> {
        self.peers.get(&peer).map(|p| p.outgoing.pending_count())
    }
    pub fn phase(&self, peer: SocketAddr) -> Option<HandshakePhase> {
        self.handshakes.phase(peer)
    }
    pub fn disconnect(&mut self, peer: SocketAddr) -> bool {
        self.handshakes.discard(peer);
        self.peers.remove(&peer).is_some()
    }
    pub fn cleanup(&mut self, now: Instant) -> usize {
        self.handshakes.cleanup(now);
        let stale: Vec<_> = self.peers.iter()
            .filter(|(_,p)| now.saturating_duration_since(p.created) >= PREAUTH_TIMEOUT)
            .map(|(&addr,_)| addr).collect();
        for addr in &stale { self.disconnect(*addr); }
        stale.len()
    }

    /// Caller must have run offline.inspect_reliable_request on the exact peer
    /// and checked the actual reliable message. A challenge/response pair for
    /// open.mp must be sourced from a compatible authentication table.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self, offline: &OfflineGateway, peer: SocketAddr,
        request_payload: &[u8], expected_password: &[u8],
        advertised_server: SocketAddr, index: u16, token: u32,
        auth_pair: Option<AuthPair>, now: Instant,
    ) -> Result<Vec<u8>, PreAuthError> {
        self.cleanup(now);
        if self.peers.contains_key(&peer) {
            return Err(PreAuthError::Handshake(HandshakeError::InProgress));
        }
        if self.peers.len() >= MAX_RELIABLE_PREAUTH {
            return Err(PreAuthError::Capacity);
        }
        let response = self.handshakes.begin(
            offline, peer, request_payload, expected_password,
            advertised_server, index, token, auth_pair, now,
        )?;
        let mut state = Peer::new(now);
        // The connection request is already observed by OfflineGateway.
        // The first reliable sequence is normally 0 in this prototype.
        // This assumption must be confirmed against actual client captures.
        state.incoming.observe(0);
        // The offline gateway inspected reliable request #0, but did not
        // acknowledge it. Piggyback this ACK on the first server response:
        // otherwise a valid client keeps retransmitting its initial request.
        state.acks.mark(0)?;
        let packet = match state.encode_outbound(&response, now) {
            Ok(packet) => packet,
            Err(err) => {
                self.handshakes.discard(peer);
                return Err(err);
            }
        };
        self.peers.insert(peer, state);
        Ok(packet)
    }

    /// Parse a datagram *only* for an established pre-auth exchange.
    /// This is protocol-level delivery, not final player authentication.
    pub fn ingest(
        &mut self, peer: SocketAddr, bytes: &[u8], now: Instant,
    ) -> Result<ExchangeResult, PreAuthError> {
        let state = self.peers.get(&peer).ok_or(PreAuthError::UnknownPeer)?;
        if now.saturating_duration_since(state.created) >= PREAUTH_TIMEOUT {
            self.disconnect(peer);
            return Err(PreAuthError::Expired);
        }
        // Validate the entire wire packet before mutating reliable state.
        let packet = decode_datagram(bytes)?;
        if packet.frames.len() > 1
            || packet.frames.iter().any(|f| f.reliability != Reliability::Reliable
                || f.ordering.is_some() || f.split.is_some()
                || f.payload_bits % 8 != 0 || f.payload.is_empty())
        {
            return Err(PreAuthError::UnexpectedFrame);
        }
        // Validate impossible future sequences *before* accepting ACKs.
        // Otherwise a packet with a fake ACK and an invalid frame could
        // acknowledge our unconfirmed handshake response before failing.
        for frame in &packet.frames {
            let ahead = frame.sequence.wrapping_sub(state.incoming.next_expected());
            if ahead < 0x8000 && usize::from(ahead) >= crate::reliability::RECEIVE_WINDOW {
                return Err(PreAuthError::Reliability(ReliabilityError::TooFarAhead));
            }
        }
        let mut result = ExchangeResult::default();
        let state = self.peers.get_mut(&peer).ok_or(PreAuthError::UnknownPeer)?;
        for range in packet.acknowledgements {
            for sequence in range.start..=range.end {
                if state.outgoing.acknowledge(sequence) { result.acknowledged += 1; }
            }
        }
        for frame in packet.frames {
            let decision = state.incoming.observe(frame.sequence);
            match decision {
                ReceiveDecision::New => state.acks.mark(frame.sequence)?,
                ReceiveDecision::Duplicate | ReceiveDecision::Old => {
                    state.acks.mark(frame.sequence)?;
                    result.duplicate_messages += 1;
                    continue;
                }
                ReceiveDecision::TooFarAhead =>
                    return Err(PreAuthError::Reliability(ReliabilityError::TooFarAhead)),
            };
            let response = match self.handshakes.phase(peer) {
                Some(HandshakePhase::AwaitAuthResponse) =>
                    self.handshakes.receive_auth_response(peer, &frame.payload, now),
                Some(HandshakePhase::AwaitClientConfirmation) =>
                    match self.handshakes.receive_confirmation(peer, &frame.payload, now) {
                        Ok(_profile) => {
                            result.transport_confirmed = true;
                            continue;
                        }
                        Err(err) => Err(err),
                    },
                None => Err(HandshakeError::UnexpectedState),
            };
            match response {
                Ok(reply) => result.outgoing.push(state.encode_outbound(&reply, now)?),
                Err(err) => {
                    self.disconnect(peer);
                    return Err(PreAuthError::Handshake(err));
                }
            }
        }
        Ok(result)
    }

    pub fn flush_ack(&mut self, peer: SocketAddr) -> Result<Option<Vec<u8>>, PreAuthError> {
        let state = self.peers.get_mut(&peer).ok_or(PreAuthError::UnknownPeer)?;
        state.ack_only()
    }

    /// Re-transmit timed-out reliable handshake payloads with their original
    /// sequence numbers, respecting a per-poll limit. The caller must not
    /// re-add them as new messages, or reset the timeout.
    pub fn poll_retries(&mut self, now: Instant) -> RetryResult {
        let mut result = RetryResult::default();
        let stale: Vec<_> = self.peers.iter()
            .filter(|(_,p)| now.saturating_duration_since(p.created) >= PREAUTH_TIMEOUT)
            .map(|(&addr,_)| addr).collect();
        for addr in stale {
            self.disconnect(addr);
            result.disconnected.push(addr);
        }
        let addrs: Vec<_> = self.peers.keys().copied().collect();
        for addr in addrs {
            if result.packets.len() >= MAX_RESEND_DATAGRAMS_PER_POLL { break; }
            let Some(state) = self.peers.get_mut(&addr) else { continue };
            let available = MAX_RESEND_DATAGRAMS_PER_POLL - result.packets.len();
            let batch = state.outgoing.poll_retries(now, MAX_RETRIES_PER_POLL.min(available));
            if !batch.abandoned.is_empty() {
                self.disconnect(addr);
                result.disconnected.push(addr);
                continue;
            }
            for resend in batch.resend {
                let frame = Frame {
                    sequence: resend.sequence,
                    reliability: Reliability::Reliable,
                    ordering: None,
                    payload_bits: (resend.bytes.len() * 8) as u16,
                    payload: resend.bytes,
                    split: None,
                };
                if let Ok(bytes) = encode_datagram(&[], &[frame]) {
                    result.packets.push(RetryDatagram { peer: addr, bytes });
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{incoming_id, HandshakeError};
    use crate::LegacyWireProfile;

    fn peer(port:u16)->SocketAddr { SocketAddr::from(([127,0,0,1],port)) }
    fn server()->SocketAddr { peer(7777) }
    fn frame(sequence:u16,payload:&[u8])->Frame {
        Frame { sequence, reliability:Reliability::Reliable,
            ordering:None, payload_bits:(payload.len()*8) as u16,
            payload:payload.to_vec(), split:None }
    }

    fn open(offline:&mut OfflineGateway, peer:SocketAddr,
        profile:LegacyWireProfile, now:Instant)
    {
        let (id,request_id)=match profile {
            LegacyWireProfile::Samp037=>(16,8),
            LegacyWireProfile::OpenMpRakNet=>(24,11),
        };
        assert!(offline.handle(&[id,0,0],peer,now).is_some());
        let packet=encode_datagram(&[], &[frame(0,&[request_id])]).unwrap();
        assert_eq!(offline.inspect_reliable_request(&packet,peer,now),Some(profile));
    }

    fn packet(sequence:u16,payload:&[u8],acks:&[u16])->Vec<u8> {
        encode_datagram(acks,&[frame(sequence,payload)]).unwrap()
    }

    fn confirm(profile:LegacyWireProfile)->Vec<u8> {
        let mut data=vec![incoming_id(profile),127,0,0,1];
        data.extend_from_slice(&7777u16.to_le_bytes());
        data
    }

    #[test]
    fn initial_connection_request_is_acknowledged_in_first_response() {
        let now=Instant::now();
        let addr=peer(12101);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::Samp037,now);
        let mut e=PreAuthExchange::new();
        let packet=e.begin(&offline,addr,&[8],b"",server(),0,1,None,now).unwrap();
        let decoded=decode_datagram(&packet).unwrap();
        assert_eq!(decoded.acknowledgements.len(),1);
        assert_eq!(decoded.acknowledgements[0].start,0);
        assert_eq!(decoded.acknowledgements[0].end,0);
        assert_eq!(decoded.frames[0].sequence,0);
        assert_eq!(e.flush_ack(addr).unwrap(),None); // Already piggybacked.
    }

    #[test]
    fn retries_always_include_original_destination() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(2);
        let a=peer(12102);
        let b=peer(12103);
        open(&mut offline,a,LegacyWireProfile::Samp037,now);
        open(&mut offline,b,LegacyWireProfile::Samp037,now);
        let mut e=PreAuthExchange::new();
        e.begin(&offline,a,&[8],b"",server(),1,1,None,now).unwrap();
        e.begin(&offline,b,&[8],b"",server(),2,2,None,now).unwrap();
        let batch=e.poll_retries(now+PREAUTH_RETRY_DELAY).packets;
        assert_eq!(batch.len(),2);
        let peers: std::collections::HashSet<_>=batch.iter().map(|d|d.peer).collect();
        assert!(peers.contains(&a));
        assert!(peers.contains(&b));
        for datagram in batch {
            assert_eq!(decode_datagram(&datagram.bytes).unwrap().frames[0].sequence,0);
        }
    }

    #[test]
    fn original_samp_ack_handshake_and_final_confirmation() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(2);
        let addr=peer(12000);
        open(&mut offline,addr,LegacyWireProfile::Samp037,now);
        let mut exchange=PreAuthExchange::new();
        let accepted=exchange.begin(&offline,addr,&[8],b"",server(),1,7,None,now).unwrap();
        let decoded=decode_datagram(&accepted).unwrap();
        assert_eq!(decoded.frames.len(),1);
        assert_eq!(decoded.frames[0].payload[0],23);
        assert_eq!(decoded.frames[0].sequence,0);
        assert_eq!(exchange.pending_retries(addr),Some(1));
        let result=exchange.ingest(addr,&packet(1,&confirm(LegacyWireProfile::Samp037),&[0]),now).unwrap();
        assert_eq!(result.acknowledged,1);
        assert!(result.transport_confirmed);
        assert_eq!(exchange.pending_retries(addr),Some(0));
        assert_eq!(decode_datagram(&exchange.flush_ack(addr).unwrap().unwrap()).unwrap()
            .acknowledgements[0].start,1);
    }

    #[test]
    fn openmp_auth_challenge_ack_and_acceptance() {
        let now=Instant::now();
        let addr=peer(12001);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::OpenMpRakNet,now);
        let mut exchange=PreAuthExchange::new();
        let data=exchange.begin(&offline,addr,&[11],b"",server(),1,7,
            Some(AuthPair{challenge:b"AAA".to_vec(), expected_response:b"BBB".to_vec()}),now).unwrap();
        assert_eq!(decode_datagram(&data).unwrap().frames[0].payload,b"\x0c\x04AAA\x00");
        let result=exchange.ingest(addr,&packet(1,b"\x0c\x03BBB",&[0]),now).unwrap();
        assert_eq!(result.acknowledged,1);
        assert_eq!(result.outgoing.len(),1);
        let parsed=decode_datagram(&result.outgoing[0]).unwrap();
        assert_eq!(parsed.frames[0].payload[0],34);
        assert_eq!(parsed.acknowledgements[0].start,1);
        let completed=exchange.ingest(addr,&packet(2,&confirm(LegacyWireProfile::OpenMpRakNet),&[1]),now).unwrap();
        assert!(completed.transport_confirmed);
        assert_eq!(completed.acknowledged,1);
    }

    #[test]
    fn duplicates_do_not_redeliver_auth_response() {
        let now=Instant::now();
        let addr=peer(12002);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::OpenMpRakNet,now);
        let mut e=PreAuthExchange::new();
        e.begin(&offline,addr,&[11],b"",server(),0,0,
            Some(AuthPair{challenge:b"C".to_vec(),expected_response:b"R".to_vec()}),now).unwrap();
        let payload=packet(1,b"\x0c\x01R",&[0]);
        assert_eq!(e.ingest(addr,&payload,now).unwrap().outgoing.len(),1);
        let repeated=e.ingest(addr,&payload,now).unwrap();
        assert_eq!(repeated.duplicate_messages,1);
        assert!(repeated.outgoing.is_empty());
        assert_eq!(e.pending_retries(addr),Some(1));
    }

    #[test]
    fn bad_auth_drops_attempt_without_authorizing() {
        let now=Instant::now();
        let addr=peer(12003);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::OpenMpRakNet,now);
        let mut e=PreAuthExchange::new();
        e.begin(&offline,addr,&[11],b"",server(),0,0,
            Some(AuthPair{challenge:b"C".to_vec(),expected_response:b"RIGHT".to_vec()}),now).unwrap();
        assert_eq!(e.ingest(addr,&packet(1,b"\x0c\x05WRONG",&[]),now),
            Err(PreAuthError::Handshake(HandshakeError::InvalidAuthResponse)));
        assert_eq!(e.len(),0);
    }

    #[test]
    fn reliable_resend_uses_original_sequence_then_times_out() {
        let now=Instant::now();
        let addr=peer(12004);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::Samp037,now);
        let mut e=PreAuthExchange::new();
        e.begin(&offline,addr,&[8],b"",server(),0,0,None,now).unwrap();
        assert!(e.poll_retries(now+PREAUTH_RETRY_DELAY/2).packets.is_empty());
        let resent=e.poll_retries(now+PREAUTH_RETRY_DELAY).packets;
        assert_eq!(resent.len(),1);
        assert_eq!(resent[0].peer,addr);
        assert_eq!(decode_datagram(&resent[0].bytes).unwrap().frames[0].sequence,0);
        assert_eq!(e.pending_retries(addr),Some(1));
        assert_eq!(e.poll_retries(now+PREAUTH_TIMEOUT).disconnected,vec![addr]);
        assert_eq!(e.len(),0);
    }

    #[test]
    fn invalid_future_sequence_does_not_acknowledge_outgoing_response() {
        let now=Instant::now();
        let addr=peer(12201);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::Samp037,now);
        let mut e=PreAuthExchange::new();
        e.begin(&offline,addr,&[8],b"",server(),0,0,None,now).unwrap();
        assert_eq!(e.pending_retries(addr),Some(1));
        let adversarial=packet(900,&[26,127,0,0,1,0x61,0x1e],&[0]);
        assert_eq!(e.ingest(addr,&adversarial,now),
            Err(PreAuthError::Reliability(ReliabilityError::TooFarAhead)));
        assert_eq!(e.pending_retries(addr),Some(1)); // ACK had NO effect.
        assert_eq!(e.phase(addr),Some(HandshakePhase::AwaitClientConfirmation));
        assert!(e.ingest(addr,&packet(1,&confirm(LegacyWireProfile::Samp037),&[0]),now)
            .unwrap().transport_confirmed);
    }

    #[test]
    fn duplicate_initial_request_reacknowledged_without_restarting_handshake() {
        let now=Instant::now();
        let addr=peer(12202);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::Samp037,now);
        let mut e=PreAuthExchange::new();
        let first=e.begin(&offline,addr,&[8],b"",server(),0,0,None,now).unwrap();
        let duplicate=e.ingest(addr,&packet(0,&[8],&[]),now).unwrap();
        assert_eq!(duplicate.duplicate_messages,1);
        assert!(duplicate.outgoing.is_empty());
        assert_eq!(e.pending_retries(addr),Some(1));
        let ack=e.flush_ack(addr).unwrap().unwrap();
        assert_eq!(decode_datagram(&ack).unwrap().acknowledgements[0].start,0);
        let retry=e.poll_retries(now+PREAUTH_RETRY_DELAY).packets;
        assert_eq!(retry.len(),1);
        assert_eq!(decode_datagram(&retry[0].bytes).unwrap().frames[0].payload,
            decode_datagram(&first).unwrap().frames[0].payload);
    }

    #[test]
    fn malformed_and_unknown_packets_cannot_remove_pending_reliable_data() {
        let now=Instant::now();
        let addr=peer(12005);
        let mut offline=OfflineGateway::new(2);
        open(&mut offline,addr,LegacyWireProfile::Samp037,now);
        let mut e=PreAuthExchange::new();
        e.begin(&offline,addr,&[8],b"",server(),0,0,None,now).unwrap();
        let ack=encode_datagram(&[0],&[]).unwrap();
        assert_eq!(e.ingest(peer(12006),&ack,now),Err(PreAuthError::UnknownPeer));
        assert_eq!(e.ingest(addr,&[0xff,0xee,0xdd],now).is_err(),true);
        assert_eq!(e.pending_retries(addr),Some(1));
        assert_eq!(e.ingest(addr,&ack,now).unwrap().acknowledged,1);
    }
}
