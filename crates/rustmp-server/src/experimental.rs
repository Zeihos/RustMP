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
}

impl ExperimentalPreAuth {
    pub fn new() -> Self { Self::default() }
    pub fn pending_count(&self) -> usize { self.exchange.len() }
    pub fn stats(&self) -> ProbeStats { self.stats }

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

        // A known pre-auth peer must never be reset by a repeated initial
        // connection request. ACK deduplication lives in PreAuthExchange.
        if self.exchange.pending_retries(peer).is_some() {
            match self.exchange.ingest(peer, incoming, now) {
                Ok(mut result) => {
                    if let Ok(Some(ack)) = self.exchange.flush_ack(peer) {
                        result.outgoing.push(ack);
                    }
                    if result.transport_confirmed {
                        // Transport transcript completed, but there is no
                        // game-auth. Free the state without admitting a player.
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

    pub fn poll_retries(&mut self, now: Instant) -> RetryResult {
        self.exchange.poll_retries(now)
    }

    pub fn cleanup(&mut self, now: Instant) {
        self.exchange.cleanup(now);
        self.cookie.cleanup(now);
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
        assert_eq!(router.poll_retries(now+Duration::from_millis(300)).packets.len(),1);

        let good=router.handle(&packet(1,&[26,127,0,0,1,0x61,0x1e],&[0]),
            sender,peer(7777),&mut gateway,b"",now);
        assert_eq!(good.len(),1);
        assert_eq!(router.pending_count(),0);
        assert_eq!(router.stats().transport_confirmations,1);
    }
    #[test]
    fn retry_packets_preserve_destination_for_udp_send_to() {
        let now=Instant::now();
        let client=peer(52004);
        let mut gateway=OfflineGateway::new(5);
        gateway.handle(&[16,0,0],client,now);
        let mut router=ExperimentalPreAuth::new();
        router.handle(&packet(0,&[8],&[]),client,peer(7777),&mut gateway,b"",now);
        let retry=router.poll_retries(now+Duration::from_millis(300));
        assert_eq!(retry.packets.len(),1);
        assert_eq!(retry.packets[0].peer,client);
        assert_eq!(decode_datagram(&retry.packets[0].bytes).unwrap().frames[0].sequence,0);
        assert_eq!(router.pending_count(),1);
    }
}
