//! Opt-in localhost-only transport probe for pre-auth RakNet exchange.
//!
//! This dispatcher is intentionally *not* a game login implementation.
//! Only the original SA-MP legacy profile is enabled: the open.mp profile
//! requires a verified authentication table and an offline cookie exchange.
//! The server's runtime refuses to enable this probe outside IPv4 loopback.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rustmp_protocol::legacy_frame::{decode_datagram, Reliability};
use rustmp_transport::preauth::{PreAuthExchange, RetryResult};
use rustmp_transport::cookie::{CookieGate, CookieVerdict, ID_OPEN_CONNECTION_REQUEST};
use rustmp_transport::{LegacyWireProfile, OfflineGateway};

const BEGINS_PER_IP_PER_SECOND: u16 = 4;
const MAX_RATE_ENTRIES: usize = 1024;
/// Short-lived ACK replay, only for completed localhost diagnostic sessions.
const COMPLETED_ACK_TTL: Duration = Duration::from_secs(3);
const MAX_COMPLETED_ACKS: usize = 128;

/// An exact final reliable handshake message and its previous ACK-only reply.
/// Never stores game sessions or grants any authenticated player privileges.
struct CompletedAck {
    created: Instant,
    sequence: u16,
    payload: Vec<u8>,
    reply: Vec<u8>,
}

impl CompletedAck {
    fn matches(&self, incoming: &[u8], now: Instant) -> bool {
        if now.saturating_duration_since(self.created) >= COMPLETED_ACK_TTL {
            return false;
        }
        let Ok(datagram) = decode_datagram(incoming) else { return false };
        if datagram.frames.len() != 1 { return false; }
        let frame = &datagram.frames[0];
        frame.sequence == self.sequence
            && frame.reliability == Reliability::Reliable
            && frame.ordering.is_none()
            && frame.split.is_none()
            && frame.payload_bits == (self.payload.len() * 8) as u16
            && frame.payload == self.payload
    }
}


#[derive(Clone, Copy)]
struct Rate {
    start: Instant,
    count: u16,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStats {
    pub cookie_challenges: u64,
    pub cookie_validations: u64,
    /// Replied again to a lost offline open reply, without allocating a slot.
    pub cookie_retransmissions: u64,
    pub starts: u64,
    pub transport_confirmations: u64,
    pub rejected: u64,
    pub throttled: u64,
    /// Exact final ACKs repeated after a completed localhost handshake.
    pub completed_ack_replays: u64,
}

/// No public constructor accepts a configuration switch for open.mp auth.
/// Live pre-auth remains a localhost test-only mechanism.
#[derive(Default)]
pub struct ExperimentalPreAuth {
    exchange: PreAuthExchange,
    cookie: CookieGate,
    rates: HashMap<IpAddr, Rate>,
    stats: ProbeStats,
    next_index: u16,
    completed_acks: HashMap<SocketAddr, CompletedAck>,
}

impl ExperimentalPreAuth {
    pub fn new() -> Self { Self::default() }
    pub fn pending_count(&self) -> usize { self.exchange.len() }
    pub fn stats(&self) -> ProbeStats { self.stats }
    pub fn completed_ack_count(&self) -> usize { self.completed_acks.len() }

    /// A fresh offline open from this same endpoint starts a NEW diagnostic
    /// attempt. Never allow the old final ACK to mask its new confirmation.
    /// Called by the dispatcher before the OfflineGateway handles SA-MP open.
    pub fn on_samp_offline_open(&mut self, peer: SocketAddr) {
        self.completed_acks.remove(&peer);
    }

    fn cache_completed_ack(&mut self, incoming: &[u8],
        outbound: &[Vec<u8>], peer: SocketAddr, now: Instant)
    {
        let Ok(packet) = decode_datagram(incoming) else { return };
        if packet.frames.len() != 1 { return; }
        let frame = &packet.frames[0];
        if frame.reliability != Reliability::Reliable
            || frame.ordering.is_some() || frame.split.is_some()
            || frame.payload_bits % 8 != 0
            || frame.payload.is_empty() || frame.payload.len() > 256
        {
            return;
        }
        let Some(reply) = outbound.iter().find(|bytes| {
            let Ok(ack) = decode_datagram(bytes) else { return false };
            ack.frames.is_empty()
                && ack.acknowledgements.iter().any(|r|
                    r.start <= frame.sequence && frame.sequence <= r.end)
        }) else { return };
        self.completed_acks.retain(|_,v|
            now.saturating_duration_since(v.created) < COMPLETED_ACK_TTL);
        if !self.completed_acks.contains_key(&peer)
            && self.completed_acks.len() >= MAX_COMPLETED_ACKS
        {
            // Bounded memory: preserving an existing ACK cache is better
            // than evicting it because of an unrelated new endpoint.
            return;
        }
        self.completed_acks.insert(peer, CompletedAck {
            created: now, sequence: frame.sequence,
            payload: frame.payload.clone(), reply: reply.clone(),
        });
    }

    /// Intercept open.mp fork's three-byte offline open before OfflineGateway
    /// can allocate any pending slot. This diagnostic token is bound to
    /// the *whole* SocketAddr and may be redeemed once before expiry.
    /// This strengthens replay checks but intentionally differs from the
    /// upstream fork's per-IPv4 cookie. It is NOT cryptographic login.
    ///
    /// Ok(()) lets the normal offline gateway process the packet.
    /// Err(bytes) means it was consumed; empty bytes indicate silent denial.
    pub fn check_cookie(
        &mut self, bytes: &[u8], peer: SocketAddr, now: Instant,
        offline: &OfflineGateway,
    ) -> Result<(), Vec<u8>> {
        if bytes.len() != 3 || bytes[0] != ID_OPEN_CONNECTION_REQUEST {
            return Ok(());
        }
        if !peer.ip().is_loopback() || !peer.is_ipv4() {
            self.stats.rejected += 1;
            return Err(Vec::new());
        }
        if offline.pending_profile(peer, now)
            .is_some_and(|profile| profile != LegacyWireProfile::OpenMpRakNet)
        {
            self.stats.rejected += 1;
            return Err(Vec::new());
        }
        match self.cookie.check(peer, bytes, now) {
            Some(CookieVerdict::Challenge(bytes)) => {
                self.stats.cookie_challenges += 1;
                Err(bytes.to_vec())
            }
            Some(CookieVerdict::Valid(_)) => {
                self.stats.cookie_validations += 1;
                Ok(())
            }
            Some(CookieVerdict::Retransmission(_)) => {
                // Allow the existing OfflineGateway pending peer to resend
                // its open reply. This is NOT another cookie acceptance:
                // absent/expired/released slots cannot be recreated.
                if offline.pending_profile(peer, now) == Some(LegacyWireProfile::OpenMpRakNet) {
                    self.stats.cookie_retransmissions += 1;
                    Ok(())
                } else {
                    self.stats.rejected += 1;
                    Err(Vec::new())
                }
            }
            Some(CookieVerdict::Rejected) => {
                self.stats.rejected += 1;
                Err(Vec::new())
            }
            None => Err(Vec::new()),
        }
    }

    fn allowed(&mut self, peer: SocketAddr, now: Instant) -> bool {
        let ip = peer.ip();
        if !self.rates.contains_key(&ip) && self.rates.len() >= MAX_RATE_ENTRIES {
            self.stats.throttled += 1;
            return false;
        }
        let entry = self.rates.entry(ip).or_insert(Rate {start:now, count:0});
        if now.saturating_duration_since(entry.start) >= Duration::from_secs(1) {
            entry.start = now;
            entry.count = 0;
        }
        if entry.count >= BEGINS_PER_IP_PER_SECOND {
            self.stats.throttled += 1;
            return false;
        }
        entry.count += 1;
        true
    }

    /// Called after the normal query/offline gateway had a chance to respond.
    /// Returns outbound packets for this same client only. No game player is
    /// ever added, even when the transport reports a completed transcript.
    pub fn handle(
        &mut self,
        incoming: &[u8], peer: SocketAddr, server: SocketAddr,
        offline: &mut OfflineGateway, expected_password: &[u8], now: Instant,
    ) -> Vec<Vec<u8>> {
        if !peer.ip().is_loopback() || !server.ip().is_loopback()
            || !server.is_ipv4() || !peer.is_ipv4()
        {
            self.stats.rejected += 1;
            return Vec::new();
        }

        // If the server's LAST ACK was lost, a client may legitimately retry
        // the same final frame after its diagnostic exchange was removed.
        // Only the exact prior source and reliable frame receive its prior
        // ACK-only reply; never a new game session or transport acceptance.
        if let Some(saved) = self.completed_acks.get(&peer) {
            if saved.matches(incoming, now) {
                self.stats.completed_ack_replays += 1;
                return vec![saved.reply.clone()];
            }
        }

        // A known pre-auth peer must never be reset by a repeated initial
        // connection request. ACK deduplication lives in PreAuthExchange.
        if self.exchange.pending_retries(peer).is_some() {
            match self.exchange.ingest(peer, incoming, now) {
                Ok(mut result) => {
                    if let Ok(Some(ack)) = self.exchange.flush_ack(peer) {
                        result.outgoing.push(ack);
                    }
                    if result.transport_confirmed {
                        // Save ONLY an exact ACK-only response briefly.
                        // This permits a lost final ACK to be retransmitted
                        // without re-opening pre-auth or admitting players.
                        self.cache_completed_ack(incoming, &result.outgoing, peer, now);
                        self.exchange.disconnect(peer);
                        offline.release_pending(peer);
                        self.stats.transport_confirmations += 1;
                    }
                    return result.outgoing;
                }
                Err(err) => {
                    self.stats.rejected += 1;
                    // A corrupted or out-of-window datagram must not tear
                    // down an otherwise valid in-flight handshake. The
                    // pre-auth codec rejects these before accepting ACKs.
                    if !matches!(err,
                        rustmp_transport::preauth::PreAuthError::Malformed(_)
                        | rustmp_transport::preauth::PreAuthError::UnexpectedFrame
                        | rustmp_transport::preauth::PreAuthError::Reliability(_))
                    {
                        self.exchange.disconnect(peer);
                        offline.release_pending(peer);
                    }
                    return Vec::new();
                }
            }
        }

        // The public open.mp fork needs the real auth-table and cookie path.
        // Do not emit fake challenges or grant fallback auth.
        if offline.pending_profile(peer, now) != Some(LegacyWireProfile::Samp037) {
            return Vec::new();
        }

        let Ok(packet) = decode_datagram(incoming) else { return Vec::new() };
        if !packet.acknowledgements.is_empty() || packet.frames.len() != 1 {
            return Vec::new();
        }
        let frame = &packet.frames[0];
        if frame.sequence != 0
            || frame.reliability != Reliability::Reliable
            || frame.split.is_some() || frame.ordering.is_some()
            || frame.payload_bits % 8 != 0 || frame.payload.is_empty()
            || frame.payload.len() > 256
            || frame.payload[0] != LegacyWireProfile::Samp037.connection_request_id()
        {
            return Vec::new();
        }

        if !self.allowed(peer, now) { return Vec::new(); }
        if offline.inspect_reliable_request(incoming, peer, now).is_none() {
            return Vec::new();
        }

        // The token is deliberately an inert test value; this opt-in-only
        // loopback probe cannot be used for game authentication.
        let id = self.next_index;
        match self.exchange.begin(
            offline, peer, &frame.payload, expected_password,
            server, id, 0, None, now,
        ) {
            Ok(response) => {
                self.next_index = self.next_index.wrapping_add(1);
                self.stats.starts += 1;
                vec![response]
            }
            Err(_) => {
                offline.release_pending(peer);
                self.stats.rejected += 1;
                Vec::new()
            }
        }
    }

    /// Poll reliable retries and immediately release gateway slots when
    /// a peer exhausts its retries or pre-auth lifetime. Otherwise a dead
    /// exchange could occupy the offline gateway until its separate TTL.
    pub fn poll_retries(&mut self, now: Instant, offline: &mut OfflineGateway) -> RetryResult {
        let result = self.exchange.poll_retries(now);
        for peer in &result.disconnected {
            offline.release_pending(*peer);
        }
        result
    }

    pub fn cleanup(&mut self, now: Instant) {
        self.exchange.cleanup(now);
        self.cookie.cleanup(now);
        self.completed_acks.retain(|_,v|
            now.saturating_duration_since(v.created) < COMPLETED_ACK_TTL);
        self.rates.retain(|_,rate| now.saturating_duration_since(rate.start) < Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmp_protocol::legacy_frame::{encode_datagram, Frame};

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127,0,0,1],port))
    }
    fn packet(number:u16, payload:&[u8],acks:&[u16]) -> Vec<u8> {
        let frame=Frame{
            sequence:number, reliability:Reliability::Reliable,
            ordering:None,payload_bits:(payload.len()*8) as u16,
            payload:payload.to_vec(),split:None,
        };
        encode_datagram(acks,&[frame]).unwrap()
    }

    #[test]
    fn live_probe_samp_ack_then_confirmation_but_no_game_session() {
        let now=Instant::now();
        let client=peer(52000);
        let mut gateway=OfflineGateway::new(5);
        assert_eq!(gateway.handle(&[16,0,0],client,now),Some(vec![17,0]));
        let mut router=ExperimentalPreAuth::new();
        let out=router.handle(&packet(0,&[8],&[]),client,peer(7777),&mut gateway,b"",now);
        assert_eq!(out.len(),1);
        let accepted=decode_datagram(&out[0]).unwrap();
        assert_eq!(accepted.acknowledgements[0].start,0);
        assert_eq!(accepted.frames[0].payload[0],23);
        assert_eq!(router.pending_count(),1);
        let final_payload=[26u8,127,0,0,1,0x61,0x1e];
        let done=router.handle(&packet(1,&final_payload,&[0]),client,peer(7777),&mut gateway,b"",now);
        assert_eq!(done.len(),1); // ACK for final reliable frame
        assert_eq!(decode_datagram(&done[0]).unwrap().acknowledgements[0].start,1);
        assert_eq!(router.pending_count(),0);
        assert_eq!(router.stats().transport_confirmations,1);
        assert_eq!(gateway.pending_count(),0);
    }

    #[test]
    fn cookie_gate_requires_valid_openmp_retry_before_offline_slot() {
        use rustmp_transport::cookie::{CookieFlavor, ID_OPEN_CONNECTION_COOKIE};
        let now=Instant::now();
        let client=peer(52010);
        let mut gateway=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        let wrong=router.check_cookie(&[24,0,0],client,now,&gateway).unwrap_err();
        assert_eq!(wrong.len(),3);
        assert_eq!(wrong[0],ID_OPEN_CONNECTION_COOKIE);
        assert_eq!(gateway.pending_count(),0);
        let token=u16::from_le_bytes([wrong[1],wrong[2]]);
        let [lo,hi]=(token ^ 0x6D70).to_le_bytes();
        assert_eq!(router.check_cookie(&[24,lo,hi],client,now,&gateway),Ok(()));
        let reply=gateway.handle(&[24,lo,hi],client,now);
        assert_eq!(reply,Some(vec![25,0]));
        assert_eq!(gateway.pending_count(),1);
        assert_eq!(router.stats().cookie_challenges,1);
        assert_eq!(router.stats().cookie_validations,1);

        let replay=router.cookie.encode_request(client,CookieFlavor::OriginalSamp).unwrap();
        assert!(router.check_cookie(&replay,client,now,&gateway).is_err());
        // A fresh port must first receive its OWN cookie challenge.
        let second=peer(52011);
        let challenge=router.check_cookie(&[24,0,0],second,now,&gateway).unwrap_err();
        assert_eq!(challenge.len(),3);
        let samp=router.cookie.encode_request(second,CookieFlavor::OriginalSamp).unwrap();
        assert_eq!(router.check_cookie(&samp,second,now,&gateway),Ok(()));
        assert_eq!(router.handle(&packet(0,&[11],&[]),client,peer(7777),
            &mut gateway,b"",now),Vec::<Vec<u8>>::new());
        assert_eq!(router.pending_count(),0); // open.mp game auth still disabled
    }


    #[test]
    fn replay_after_success_cannot_reopen_offline_slot() {
        let now=Instant::now();
        let sender=peer(52120);
        let mut gateway=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        let challenge=router.check_cookie(&[24,0,0],sender,now,&gateway).unwrap_err();
        let cookie=u16::from_le_bytes([challenge[1],challenge[2]]);
        let [lo,hi]=(cookie ^ 0x6d70).to_le_bytes();
        assert_eq!(router.check_cookie(&[24,lo,hi],sender,now,&gateway),Ok(()));
        assert_eq!(gateway.handle(&[24,lo,hi],sender,now),Some(vec![25,0]));
        // A lost open-reply can now be resent by the original peer.
        assert_eq!(router.check_cookie(&[24,lo,hi],sender,now,&gateway),Ok(()));
        assert_eq!(gateway.handle(&[24,lo,hi],sender,now),Some(vec![25,0]));
        assert_eq!(router.stats().cookie_validations,1);
        assert_eq!(router.stats().cookie_retransmissions,1);
        assert_eq!(gateway.pending_count(),1);
        let other_port=peer(52121);
        // The copied response is NOT valid for another source port.
        let answer=router.check_cookie(&[24,lo,hi],other_port,now,&gateway).unwrap_err();
        assert_eq!(answer[0],26);
        assert_eq!(gateway.pending_count(),1);
    }


    #[test]
    fn redeemed_cookie_rejected_if_offline_slot_was_released() {
        let now=Instant::now();
        let sender=peer(52122);
        let mut gateway=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        router.check_cookie(&[24,0,0],sender,now,&gateway).unwrap_err();
        let packet=router.cookie.encode_request(
            sender,rustmp_transport::cookie::CookieFlavor::OpenMp).unwrap();
        assert_eq!(router.check_cookie(&packet,sender,now,&gateway),Ok(()));
        assert_eq!(gateway.handle(&packet,sender,now),Some(vec![25,0]));
        assert!(gateway.release_pending(sender));
        assert!(router.check_cookie(&packet,sender,now,&gateway).is_err());
        assert_eq!(router.stats().cookie_validations,1);
        assert_eq!(router.stats().cookie_retransmissions,0);
        assert_eq!(gateway.pending_count(),0);
    }

    #[test]
    fn lost_open_reply_retries_do_not_extend_slot_lifetime() {
        use rustmp_transport::HANDSHAKE_TIMEOUT;
        let now=Instant::now();
        let sender=peer(52123);
        let mut gateway=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        router.check_cookie(&[24,0,0],sender,now,&gateway).unwrap_err();
        let packet=router.cookie.encode_request(
            sender,rustmp_transport::cookie::CookieFlavor::OpenMp).unwrap();
        assert_eq!(router.check_cookie(&packet,sender,now,&gateway),Ok(()));
        assert_eq!(gateway.handle(&packet,sender,now),Some(vec![25,0]));
        for step in 1..4 {
            let later=now+Duration::from_secs(step);
            assert_eq!(router.check_cookie(&packet,sender,later,&gateway),Ok(()));
            assert_eq!(gateway.handle(&packet,sender,later),Some(vec![25,0]));
        }
        assert_eq!(router.stats().cookie_retransmissions,3);
        assert_eq!(gateway.pending_profile(sender,now+HANDSHAKE_TIMEOUT),None);
        // Cookie TTL is shorter than offline slot lifetime.
        assert_eq!(router.cookie.pending_count(),1);
        router.cleanup(now+Duration::from_secs(4));
        assert_eq!(router.cookie.pending_count(),0);
    }

    #[test]
    fn consumed_cookie_tombstone_expires_and_frees_memory() {
        use rustmp_transport::cookie::COOKIE_TTL;
        let now=Instant::now();
        let sender=peer(52130);
        let mut gateway=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        router.check_cookie(&[24,0,0],sender,now,&gateway).unwrap_err();
        let retry=router.cookie.encode_request(sender,rustmp_transport::cookie::CookieFlavor::OpenMp)
            .unwrap();
        assert_eq!(router.check_cookie(&retry,sender,now,&gateway),Ok(()));
        assert!(router.check_cookie(&retry,sender,now,&gateway).is_err());
        assert_eq!(router.cookie.pending_count(),1);
        router.cleanup(now+COOKIE_TTL);
        assert_eq!(router.cookie.pending_count(),0);
        let challenge=router.check_cookie(&retry,sender,now+COOKIE_TTL,&gateway).unwrap_err();
        assert_eq!(challenge.len(),3);
        assert_eq!(challenge[0],26);
    }
    #[test]
    fn openmp_and_untrusted_peers_never_get_fake_handshake_response() {
        let now=Instant::now();
        let mut gateway=OfflineGateway::new(5);
        let client=peer(52001);
        let stranger=peer(52002);
        gateway.handle(&[24,0,0],client,now);
        let mut router=ExperimentalPreAuth::new();
        assert!(router.handle(&packet(0,&[11],&[]),client,peer(7777),&mut gateway,b"",now).is_empty());
        assert!(router.handle(&packet(0,&[8],&[]),stranger,peer(7777),&mut gateway,b"",now).is_empty());
        assert!(router.handle(&packet(0,&[8],&[]),peer(9000),
            SocketAddr::from(([192,0,2,10],7777)),&mut gateway,b"",now).is_empty());
        assert_eq!(router.pending_count(),0);
    }

    #[test]
    fn wrong_password_and_bad_seq_never_allocate() {
        let now=Instant::now();
        let client=peer(52003);
        let mut gateway=OfflineGateway::new(5);
        gateway.handle(&[16,0,0],client,now);
        let mut router=ExperimentalPreAuth::new();
        assert!(router.handle(&packet(3,&[8],&[]),client,peer(7777),&mut gateway,b"yes",now).is_empty());
        assert_eq!(gateway.stats().reliable_requests_observed,0);
        assert!(router.handle(&packet(0,b"\x08bad",&[]),client,peer(7777),&mut gateway,b"yes",now).is_empty());
        assert_eq!(router.pending_count(),0);
        assert_eq!(router.stats().rejected,1);
    }

    #[test]
    fn rate_limit_is_bounded_even_when_offline_peer_changes_port() {
        let now=Instant::now();
        let mut router=ExperimentalPreAuth::new();
        for i in 0..BEGINS_PER_IP_PER_SECOND {
            assert!(router.allowed(peer(10000+i),now));
        }
        assert!(!router.allowed(peer(20000),now));
        assert!(router.allowed(peer(20000),now+Duration::from_secs(1)));
    }


    #[test]
    fn damaged_datagram_does_not_cancel_valid_local_handshake() {
        let now=Instant::now();
        let sender=peer(52200);
        let mut gateway=OfflineGateway::new(5);
        gateway.handle(&[16,0,0],sender,now);
        let mut router=ExperimentalPreAuth::new();
        let accepted=router.handle(&packet(0,&[8],&[]),sender,peer(7777),
            &mut gateway,b"",now);
        assert_eq!(accepted.len(),1);
        assert_eq!(router.pending_count(),1);
        // Invalid frame + an ACK for our first response must not cancel
        // the session or release our retry state.
        let bad=packet(900,&[26,127,0,0,1,0x61,0x1e],&[0]);
        assert!(router.handle(&bad,sender,peer(7777),&mut gateway,b"",now).is_empty());
        assert_eq!(router.pending_count(),1);
        assert_eq!(gateway.pending_count(),1);
        assert_eq!(router.poll_retries(now+Duration::from_millis(300),&mut gateway).packets.len(),1);

        let good=router.handle(&packet(1,&[26,127,0,0,1,0x61,0x1e],&[0]),
            sender,peer(7777),&mut gateway,b"",now);
        assert_eq!(good.len(),1);
        assert_eq!(router.pending_count(),0);
        assert_eq!(router.stats().transport_confirmations,1);
    }
    #[test]
    fn retry_exhaustion_releases_offline_and_reliable_slots_together() {
        let now=Instant::now();
        let address=peer(52440);
        let mut gateway=OfflineGateway::new(2);
        gateway.handle(&[16,0,0],address,now);
        let mut router=ExperimentalPreAuth::new();
        assert_eq!(router.handle(&packet(0,&[8],&[]),address,peer(7777),
            &mut gateway,b"",now).len(),1);
        for attempt in 1..=5 {
            let poll=router.poll_retries(
                now+Duration::from_millis(300 * attempt),&mut gateway);
            assert_eq!(poll.packets.len(),1);
            assert!(poll.disconnected.is_empty());
            assert_eq!(router.pending_count(),1);
            assert_eq!(gateway.pending_count(),1);
        }
        let exhausted=router.poll_retries(
            now+Duration::from_millis(1800),&mut gateway);
        assert!(exhausted.packets.is_empty());
        assert_eq!(exhausted.disconnected,vec![address]);
        assert_eq!(router.pending_count(),0);
        assert_eq!(gateway.pending_count(),0);
        // A second offline request is now able to reuse the released slot.
        assert_eq!(gateway.handle(&[16,0,0],address,
            now+Duration::from_millis(1801)),Some(vec![17,0]));
    }

    #[test]
    fn completed_confirmation_replays_only_exact_ack_for_same_peer() {
        let now=Instant::now();
        let sender=peer(52500);
        let mut offline=OfflineGateway::new(5);
        assert_eq!(offline.handle(&[16,0,0],sender,now),Some(vec![17,0]));
        let mut router=ExperimentalPreAuth::new();
        assert_eq!(router.handle(&packet(0,&[8],&[]),sender,peer(7777),
            &mut offline,b"",now).len(),1);
        let final_payload=[26,127,0,0,1,0x61,0x1e];
        let confirmation=packet(1,&final_payload,&[0]);
        let first=router.handle(&confirmation,sender,peer(7777),
            &mut offline,b"",now);
        assert_eq!(first.len(),1);
        assert_eq!(decode_datagram(&first[0]).unwrap().acknowledgements[0].start,1);
        assert_eq!(router.pending_count(),0);
        assert_eq!(offline.pending_count(),0);
        assert_eq!(router.completed_ack_count(),1);

        // A genuine retransmission can have DIFFERENT piggybacked ACKs.
        let resent=packet(1,&final_payload,&[]);
        assert_eq!(router.handle(&resent,sender,peer(7777),
            &mut offline,b"",now+Duration::from_millis(100)),first);
        assert_eq!(router.stats().completed_ack_replays,1);
        assert_eq!(router.stats().transport_confirmations,1);
        assert_eq!(router.pending_count(),0);
        assert_eq!(offline.pending_count(),0);

        // Same sequence but modified bytes or another UDP source port must
        // never inherit a previous client's final handshake ACK.
        let mut wrong=final_payload;
        wrong[5]=0x62;
        assert!(router.handle(&packet(1,&wrong,&[]),sender,peer(7777),
            &mut offline,b"",now+Duration::from_millis(110)).is_empty());
        assert!(router.handle(&resent,peer(52501),peer(7777),
            &mut offline,b"",now+Duration::from_millis(110)).is_empty());

        router.cleanup(now+COMPLETED_ACK_TTL);
        assert_eq!(router.completed_ack_count(),0);
        assert!(router.handle(&resent,sender,peer(7777),
            &mut offline,b"",now+COMPLETED_ACK_TTL).is_empty());
    }

    #[test]
    fn new_offline_open_clears_previous_completion_ack_without_new_game_login() {
        let now=Instant::now();
        let sender=peer(52510);
        let mut offline=OfflineGateway::new(5);
        offline.handle(&[16,0,0],sender,now);
        let mut router=ExperimentalPreAuth::new();
        router.handle(&packet(0,&[8],&[]),sender,peer(7777),
            &mut offline,b"",now);
        let final_payload=[26,127,0,0,1,0x61,0x1e];
        let final_wire=packet(1,&final_payload,&[0]);
        assert_eq!(router.handle(&final_wire,sender,peer(7777),
            &mut offline,b"",now).len(),1);
        assert_eq!(router.completed_ack_count(),1);
        router.on_samp_offline_open(sender);
        assert_eq!(router.completed_ack_count(),0);
        assert_eq!(offline.handle(&[16,0,0],sender,now+Duration::from_millis(150)),
            Some(vec![17,0]));
        assert!(router.handle(&final_wire,sender,peer(7777),
            &mut offline,b"",now+Duration::from_millis(150)).is_empty());
        assert_eq!(router.stats().completed_ack_replays,0);
        assert_eq!(router.pending_count(),0);
        assert_eq!(offline.pending_count(),1);
        // A fresh initial request still starts a NEW diagnostic transcript.
        assert_eq!(router.handle(&packet(0,&[8],&[]),sender,peer(7777),
            &mut offline,b"",now+Duration::from_millis(150)).len(),1);
        assert_eq!(router.pending_count(),1);
    }

    #[test]
    fn completion_ack_cache_has_fixed_capacity() {
        let now=Instant::now();
        let mut router=ExperimentalPreAuth::new();
        let final_payload=[26,127,0,0,1,0x61,0x1e];
        let final_wire=packet(1,&final_payload,&[]);
        let reply=encode_datagram(&[1],&[]).unwrap();
        for n in 0..MAX_COMPLETED_ACKS {
            router.cache_completed_ack(&final_wire,&[reply.clone()],
                peer(30000+n as u16),now);
        }
        assert_eq!(router.completed_ack_count(),MAX_COMPLETED_ACKS);
        router.cache_completed_ack(&final_wire,&[reply.clone()],peer(50000),now);
        assert_eq!(router.completed_ack_count(),MAX_COMPLETED_ACKS);
        router.cleanup(now+COMPLETED_ACK_TTL);
        assert_eq!(router.completed_ack_count(),0);
        router.cache_completed_ack(&final_wire,&[reply],peer(50000),
            now+COMPLETED_ACK_TTL);
        assert_eq!(router.completed_ack_count(),1);
    }

    #[test]
    fn retry_packets_preserve_destination_for_udp_send_to() {
        let now=Instant::now();
        let client=peer(52004);
        let mut gateway=OfflineGateway::new(5);
        gateway.handle(&[16,0,0],client,now);
        let mut router=ExperimentalPreAuth::new();
        router.handle(&packet(0,&[8],&[]),client,peer(7777),&mut gateway,b"",now);
        let retry=router.poll_retries(now+Duration::from_millis(300),&mut gateway);
        assert_eq!(retry.packets.len(),1);
        assert_eq!(retry.packets[0].peer,client);
        assert_eq!(decode_datagram(&retry.packets[0].bytes).unwrap().frames[0].sequence,0);
        assert_eq!(router.pending_count(),1);
    }
}
