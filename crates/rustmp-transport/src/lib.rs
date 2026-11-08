//! Initial offline UDP stage for the legacy RakNet fork used by SA-MP/open.mp.
//!
//! IMPORTANT: These wire IDs and fixed-length offline messages are NOT the
//! modern RakNet 0x05/0x06/0x07/0x08 + offline magic sequence.
//! This crate implements only *pre-connection* replies. It does NOT establish
//! RakNet reliable sessions or accept a GTA game client yet.
//!
//! Wire references:
//! - https://github.com/openmultiplayer/RakNet/blob/master/Source/RakPeer.cpp
//! - https://github.com/Alf21/samp/blob/master/raknet/PacketEnumerations.h

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Numeric IDs follow the `PacketEnumerations.h` enum (including dummy slots),
/// not the human-readable ordinal comments within it.
pub mod legacy_id {
    pub const PING: u8 = 3;
    pub const PING_OPEN_CONNECTIONS: u8 = 4;
    pub const OPEN_CONNECTION_REQUEST: u8 = 16;
    pub const OPEN_CONNECTION_REPLY: u8 = 17;
    pub const CONNECTION_ATTEMPT_FAILED: u8 = 24;
    pub const NO_FREE_INCOMING_CONNECTIONS: u8 = 27;
    pub const PONG: u8 = 37;
}

/// Packet identifiers for the RAKNET_LEGACY branch of openmultiplayer/RakNet.
/// Unlike the original SA-MP 0.3.7 enum, the fork contains reserved slots.
pub mod openmp_legacy_id {
    pub const PING: u8 = 7;
    pub const PING_OPEN_CONNECTIONS: u8 = 8;
    pub const CONNECTION_REQUEST: u8 = 11;
    pub const AUTH_KEY: u8 = 12;
    pub const OPEN_CONNECTION_REQUEST: u8 = 24;
    pub const OPEN_CONNECTION_REPLY: u8 = 25;
    pub const OPEN_CONNECTION_COOKIE: u8 = 26;
    pub const CONNECTION_ATTEMPT_FAILED: u8 = 29;
    pub const NO_FREE_INCOMING_CONNECTIONS: u8 = 31;
    pub const PONG: u8 = 39;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyWireProfile {
    Samp037,
    OpenMpRakNet,
}

impl LegacyWireProfile {
    pub fn connection_request_id(self) -> u8 {
        match self {
            Self::Samp037 => 8, // Alf21/samp PacketEnumerations.h
            Self::OpenMpRakNet => openmp_legacy_id::CONNECTION_REQUEST,
        }
    }

    fn open_reply(self) -> u8 {
        match self {
            Self::Samp037 => legacy_id::OPEN_CONNECTION_REPLY,
            Self::OpenMpRakNet => openmp_legacy_id::OPEN_CONNECTION_REPLY,
        }
    }

    fn pong(self) -> u8 {
        match self {
            Self::Samp037 => legacy_id::PONG,
            Self::OpenMpRakNet => openmp_legacy_id::PONG,
        }
    }

    fn full(self) -> u8 {
        match self {
            Self::Samp037 => legacy_id::NO_FREE_INCOMING_CONNECTIONS,
            Self::OpenMpRakNet => openmp_legacy_id::NO_FREE_INCOMING_CONNECTIONS,
        }
    }
}

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const OFFLINE_LIMIT_PER_IP_PER_SEC: u16 = 24;
pub const DEFAULT_PENDING_PER_IP: usize = 8;
pub const MAX_TRACKED_IPS: usize = 4096;

/// The legacy RakNet fork expects exactly 3 bytes for the initial request.
/// Padding is not checked: the original RakNet client does not initialize the
/// last padding byte consistently (see `RakPeer.cpp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineRequest {
    ConnectionStart,
    Ping { timestamp: [u8; 4], only_if_open: bool },
}

pub fn decode_offline(bytes: &[u8]) -> Option<OfflineRequest> {
    decode_offline_profiled(bytes).map(|(message, _)| message)
}

/// Detect original SA-MP vs the open.mp RakNet fork by the exact-length
/// offline datagram. Do not interpret these messages as verified sessions.
pub fn decode_offline_profiled(bytes: &[u8]) -> Option<(OfflineRequest, LegacyWireProfile)> {
    use LegacyWireProfile::{OpenMpRakNet, Samp037};
    match bytes {
        [legacy_id::OPEN_CONNECTION_REQUEST, _, _] => Some((OfflineRequest::ConnectionStart, Samp037)),
        [openmp_legacy_id::OPEN_CONNECTION_REQUEST, _, _] => Some((OfflineRequest::ConnectionStart, OpenMpRakNet)),
        [legacy_id::PING, a, b, c, d] => Some((OfflineRequest::Ping {
            timestamp: [*a, *b, *c, *d], only_if_open: false,
        }, Samp037)),
        [openmp_legacy_id::PING, a, b, c, d] => Some((OfflineRequest::Ping {
            timestamp: [*a, *b, *c, *d], only_if_open: false,
        }, OpenMpRakNet)),
        [legacy_id::PING_OPEN_CONNECTIONS, a, b, c, d] => Some((OfflineRequest::Ping {
            timestamp: [*a, *b, *c, *d], only_if_open: true,
        }, Samp037)),
        [openmp_legacy_id::PING_OPEN_CONNECTIONS, a, b, c, d] => Some((OfflineRequest::Ping {
            timestamp: [*a, *b, *c, *d], only_if_open: true,
        }, OpenMpRakNet)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
struct IpRate {
    start: Instant,
    count: u16,
}

#[derive(Clone, Copy, Debug)]
struct PendingPeer {
    created: Instant,
    profile: LegacyWireProfile,
    saw_connection_request: bool,
}

/// Stats count messages and pre-handshake requests, **never** connected players.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OfflineStats {
    pub pings_replied: u64,
    pub opens_replied: u64,
    pub denied_full: u64,
    pub rate_limited: u64,
    pub expired_pending: u64,
    /// Observed reliable connection requests; NOT accepted/authenticated peers.
    pub reliable_requests_observed: u64,
}

/// Minimal state machine for offline probes only.
/// A pending peer must NOT be treated as a connected player.
pub struct OfflineGateway {
    pending: HashMap<SocketAddr, PendingPeer>,
    rates: HashMap<IpAddr, IpRate>,
    max_pending: usize,
    max_per_ip: usize,
    stats: OfflineStats,
}

impl OfflineGateway {
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: HashMap::new(), rates: HashMap::new(),
            max_pending, max_per_ip: DEFAULT_PENDING_PER_IP,
            stats: OfflineStats::default(),
        }
    }

    pub fn stats(&self) -> OfflineStats { self.stats }
    pub fn pending_count(&self) -> usize { self.pending.len() }
    pub fn is_pending(&self, peer: SocketAddr) -> bool { self.pending.contains_key(&peer) }
    pub fn pending_profile(&self, peer: SocketAddr, now: Instant) -> Option<LegacyWireProfile> {
        let p = self.pending.get(&peer)?;
        if now.saturating_duration_since(p.created) < HANDSHAKE_TIMEOUT { Some(p.profile) } else { None }
    }


    /// Release a pre-connection slot after a future reliability layer accepts
    /// or rejects the client. This alone never creates a connected player.
    pub fn release_pending(&mut self, peer: SocketAddr) -> bool {
        self.pending.remove(&peer).is_some()
    }

    /// Process a single raw UDP payload and optionally produce a tiny reply.
    /// Unknown/truncated datagrams are silently ignored. Called after query
    /// dispatch; query and legacy RakNet use the same UDP socket.
    pub fn handle(&mut self, bytes: &[u8], peer: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        let (request, profile) = decode_offline_profiled(bytes)?;
        if !self.allowed(peer.ip(), now) {
            self.stats.rate_limited += 1;
            return None;
        }
        match request {
            OfflineRequest::Ping { timestamp, only_if_open } => {
                if only_if_open && self.pending.len() >= self.max_pending {
                    return None;
                }
                self.stats.pings_replied += 1;
                // The upstream server can attach offline ping data; it is
                // deliberately empty until the exact format is ported.
                let mut reply = vec![profile.pong()];
                reply.extend_from_slice(&timestamp);
                Some(reply)
            }
            OfflineRequest::ConnectionStart => {
                if let Some(existing) = self.pending.get(&peer) {
                    // A pending address has one wire profile. Do not switch it
                    // during retransmissions, which could mix handshake IDs.
                    if existing.profile != profile { return None; }
                    // Retransmission must NOT extend original expiry.
                    return Some(vec![profile.open_reply(), 0]);
                }
                if self.pending.len() >= self.max_pending
                    || self.pending.keys().filter(|addr| addr.ip() == peer.ip()).count() >= self.max_per_ip {
                    self.stats.denied_full += 1;
                    return Some(vec![profile.full(), 0]);
                }
                self.pending.insert(peer, PendingPeer {
                    created: now, profile, saw_connection_request: false,
                });
                self.stats.opens_replied += 1;
                Some(vec![profile.open_reply(), 0])
            }
        }
    }

    /// Inspect the *first* reliable connection-request payload sent after
    /// a matching offline open. In legacy RakNet the request is a reliable
    /// one-byte ID followed by an optional password. Alpha.8 records only
    /// its presence; it NEVER answers with a fake auth challenge or admits
    /// the sender to a gameplay/VerifiedSessions state.
    pub fn inspect_reliable_request(
        &mut self, bytes: &[u8], peer: SocketAddr, now: Instant,
    ) -> Option<LegacyWireProfile> {
        use rustmp_protocol::legacy_frame::{decode_datagram, Reliability};
        let slot = self.pending.get_mut(&peer)?;
        if now.saturating_duration_since(slot.created) >= HANDSHAKE_TIMEOUT
            || slot.saw_connection_request
        {
            return None;
        }
        let packet = decode_datagram(bytes).ok()?;
        if packet.frames.len() != 1 { return None; }
        let frame = &packet.frames[0];
        if frame.reliability != Reliability::Reliable
            || frame.split.is_some()
            || frame.ordering.is_some()
            || frame.payload_bits % 8 != 0
            || frame.payload.is_empty()
            || frame.payload.len() > 256
            || frame.payload[0] != slot.profile.connection_request_id()
        {
            return None;
        }
        slot.saw_connection_request = true;
        self.stats.reliable_requests_observed += 1;
        Some(slot.profile)
    }

    pub fn saw_reliable_request(&self, peer: SocketAddr) -> bool {
        self.pending.get(&peer).is_some_and(|p| p.saw_connection_request)
    }

    fn allowed(&mut self, ip: IpAddr, now: Instant) -> bool {
        // Bound memory even if an attacker spoofs many distinct source IPs.
        if self.rates.len() >= MAX_TRACKED_IPS && !self.rates.contains_key(&ip) {
            return false;
        }
        let rate = self.rates.entry(ip).or_insert(IpRate { start: now, count: 0 });
        if now.saturating_duration_since(rate.start) >= Duration::from_secs(1) {
            rate.start = now;
            rate.count = 0;
        }
        if rate.count >= OFFLINE_LIMIT_PER_IP_PER_SEC { return false; }
        rate.count += 1;
        true
    }

    /// Periodically delete unfinished requests and old rate-limit entries.
    pub fn cleanup(&mut self, now: Instant) {
        let old = self.pending.len();
        self.pending.retain(|_, slot| now.saturating_duration_since(slot.created) < HANDSHAKE_TIMEOUT);
        self.stats.expired_pending += (old - self.pending.len()) as u64;
        self.rates.retain(|_, rate| now.saturating_duration_since(rate.start) < Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr { SocketAddr::from(([127, 0, 0, 1], port)) }
    fn start() -> [u8; 3] { [legacy_id::OPEN_CONNECTION_REQUEST, 0, 0xFE] }

    #[test]
    fn exact_wire_shapes() {
        assert_eq!(decode_offline(&start()), Some(OfflineRequest::ConnectionStart));
        assert_eq!(decode_offline(&start()[..2]), None);
        assert_eq!(decode_offline(&[legacy_id::OPEN_CONNECTION_REQUEST, 0, 0, 0]), None);
        assert_eq!(decode_offline(&[legacy_id::PING, 1, 2, 3, 4]), Some(OfflineRequest::Ping {
            timestamp: [1, 2, 3, 4], only_if_open: false,
        }));
        assert!(decode_offline(&[0x05, 0, 0]).is_none()); // modern RakNet must not match
        assert!(decode_offline(&[0u8; 1500]).is_none());
    }

    #[test]
    fn reply_to_legacy_open_without_claiming_game_connection() {
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(2);
        assert_eq!(gateway.handle(&start(), peer(1234), t), Some(vec![legacy_id::OPEN_CONNECTION_REPLY, 0]));
        assert!(gateway.is_pending(peer(1234)));
        assert_eq!(gateway.pending_count(), 1);
        assert_eq!(gateway.handle(&start(), peer(1234), t), Some(vec![legacy_id::OPEN_CONNECTION_REPLY, 0]));
        assert_eq!(gateway.pending_count(), 1);
        assert_eq!(gateway.handle(&start(), peer(2345), t), Some(vec![legacy_id::OPEN_CONNECTION_REPLY, 0]));
        assert_eq!(gateway.handle(&start(), peer(3456), t), Some(vec![legacy_id::NO_FREE_INCOMING_CONNECTIONS, 0]));
        assert_eq!(gateway.pending_count(), 2);
        assert!(gateway.release_pending(peer(1234)));
        assert!(!gateway.release_pending(peer(1234)));
        assert_eq!(gateway.pending_count(), 1);
    }

    #[test]
    fn echo_ping_and_open_only_on_available_slots() {
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(1);
        let request = [legacy_id::PING, 1, 2, 3, 4];
        assert_eq!(gateway.handle(&request, peer(1234), t), Some(vec![legacy_id::PONG, 1, 2, 3, 4]));
        let request = [legacy_id::PING_OPEN_CONNECTIONS, 5, 6, 7, 8];
        assert_eq!(gateway.handle(&request, peer(1234), t), Some(vec![legacy_id::PONG, 5, 6, 7, 8]));
        gateway.handle(&start(), peer(1234), t);
        assert_eq!(gateway.handle(&request, peer(1234), t), None);
    }

    #[test]
    fn timeout_is_not_extended_by_retransmission() {
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(1);
        gateway.handle(&start(), peer(1234), t);
        gateway.handle(&start(), peer(1234), t + Duration::from_secs(8));
        gateway.cleanup(t + HANDSHAKE_TIMEOUT);
        assert!(!gateway.is_pending(peer(1234)));
        assert_eq!(gateway.stats().expired_pending, 1);
    }

    #[test]
    fn rate_limit_and_state_capacity_remain_bounded() {
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(100);
        for _ in 0..OFFLINE_LIMIT_PER_IP_PER_SEC {
            assert!(gateway.handle(&[legacy_id::PING, 0, 0, 0, 0], peer(1234), t).is_some());
        }
        assert_eq!(gateway.handle(&start(), peer(1234), t), None);
        assert_eq!(gateway.stats().rate_limited, 1);
        assert_eq!(gateway.handle(&start(), peer(1234), t + Duration::from_secs(1)), Some(vec![legacy_id::OPEN_CONNECTION_REPLY, 0]));
        for p in 1235..1242 {
            gateway.handle(&start(), peer(p), t + Duration::from_secs(1));
        }
        assert_eq!(gateway.pending_count(), 8);
        assert_eq!(gateway.handle(&start(), peer(1242), t + Duration::from_secs(1)), Some(vec![legacy_id::NO_FREE_INCOMING_CONNECTIONS, 0]));
    }

    #[test]
    fn profiles_use_distinct_verified_source_enum_ids() {
        assert_eq!(legacy_id::OPEN_CONNECTION_REQUEST, 16);
        assert_eq!(openmp_legacy_id::OPEN_CONNECTION_REQUEST, 24);
        assert_eq!(LegacyWireProfile::Samp037.connection_request_id(), 8);
        assert_eq!(LegacyWireProfile::OpenMpRakNet.connection_request_id(), 11);
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(2);
        assert_eq!(gateway.handle(&[16, 0, 0], peer(1234), t), Some(vec![17, 0]));
        assert_eq!(gateway.handle(&[24, 0, 0], peer(5678), t), Some(vec![25, 0]));
        assert_eq!(gateway.handle(&[24, 0, 0], peer(1234), t), None);
        assert_eq!(gateway.handle(&[3, 1, 2, 3, 4], peer(2000), t), Some(vec![37,1,2,3,4]));
        assert_eq!(gateway.handle(&[7, 1, 2, 3, 4], peer(2000), t), Some(vec![39,1,2,3,4]));
    }

    #[test]
    fn reliable_request_requires_original_offline_source_and_is_not_admission() {
        use rustmp_protocol::legacy_frame::{encode_datagram, Frame, Reliability};
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(5);
        let request = |id| encode_datagram(&[], &[Frame {
            sequence: 0, reliability: Reliability::Reliable,
            ordering: None, payload_bits: 8, payload: vec![id], split: None,
        }]).unwrap();
        let samp = request(8);
        let omp = request(11);
        assert_eq!(gateway.inspect_reliable_request(&samp, peer(1000), t), None);
        gateway.handle(&[16,0,0], peer(1000), t);
        gateway.handle(&[24,0,0], peer(2000), t);
        assert_eq!(gateway.inspect_reliable_request(&omp, peer(1000), t), None);
        assert_eq!(gateway.inspect_reliable_request(&samp, peer(1000), t),
            Some(LegacyWireProfile::Samp037));
        assert_eq!(gateway.inspect_reliable_request(&samp, peer(1000), t), None);
        assert_eq!(gateway.inspect_reliable_request(&omp, peer(2000), t),
            Some(LegacyWireProfile::OpenMpRakNet));
        assert!(gateway.saw_reliable_request(peer(2000)));
        assert_eq!(gateway.stats().reliable_requests_observed, 2);
        assert_eq!(gateway.pending_count(), 2); // Never converted into authenticated players.
        gateway.cleanup(t + HANDSHAKE_TIMEOUT);
        assert_eq!(gateway.pending_count(), 0);
    }

    #[test]
    fn malformed_or_non_reliable_request_never_advances_state() {
        use rustmp_protocol::legacy_frame::{encode_datagram, Frame, Reliability};
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(5);
        gateway.handle(&[16,0,0], peer(1000), t);
        assert_eq!(gateway.inspect_reliable_request(&[0xff;12], peer(1000), t), None);
        let raw = encode_datagram(&[], &[Frame {
            sequence: 0, reliability: Reliability::Unreliable,
            ordering: None, payload_bits: 8, payload: vec![8], split: None,
        }]).unwrap();
        assert_eq!(gateway.inspect_reliable_request(&raw, peer(1000), t), None);
        assert!(!gateway.saw_reliable_request(peer(1000)));
    }

    #[test]
    fn unknown_fuzzlike_lengths_do_not_panic_or_change_state() {
        let t = Instant::now();
        let mut gateway = OfflineGateway::new(5);
        for len in 0..1400usize {
            let data = vec![0xffu8; len];
            assert_eq!(gateway.handle(&data, peer(1234), t), None);
        }
        assert_eq!(gateway.pending_count(), 0);
    }
}

/// Bookkeeping for reliable message delivery; not yet the wire protocol.
pub mod reliability;

/// Per-session bounded legacy RakNet split-message reassembly.
pub mod fragments;

/// Isolated per-peer verified-session coordinator (not yet live UDP admission).
pub mod session;

/// Offline-to-reliable handshake codec and gated state machine (library-only).
pub mod handshake;

/// Bounded reliable handshake exchange, library-only pending client capture.
pub mod preauth;

/// Local-only legacy cookie wire challenge; NOT game authentication.
pub mod cookie;
