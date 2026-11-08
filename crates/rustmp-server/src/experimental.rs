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
    rates: HashMap<IpAddr, Rate>,
    stats: ProbeStats,
    next_index: u16,
}

impl ExperimentalPreAuth {
    pub fn new() -> Self { Self::default() }
    pub fn pending_count(&self) -> usize { self.exchange.len() }
    pub fn stats(&self) -> ProbeStats { self.stats }

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
                Err(_) => {
                    self.exchange.disconnect(peer);
                    offline.release_pending(peer);
                    self.stats.rejected += 1;
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
