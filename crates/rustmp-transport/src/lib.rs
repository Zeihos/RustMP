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
    match bytes {
        [legacy_id::OPEN_CONNECTION_REQUEST, _, _] => Some(OfflineRequest::ConnectionStart),
        [legacy_id::PING, a, b, c, d] => Some(OfflineRequest::Ping {
            timestamp: [*a, *b, *c, *d], only_if_open: false,
        }),
        [legacy_id::PING_OPEN_CONNECTIONS, a, b, c, d] => Some(OfflineRequest::Ping {
            timestamp: [*a, *b, *c, *d], only_if_open: true,
        }),
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
}

/// Stats count messages and pre-handshake requests, **never** connected players.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OfflineStats {
    pub pings_replied: u64,
    pub opens_replied: u64,
    pub denied_full: u64,
    pub rate_limited: u64,
    pub expired_pending: u64,
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

    /// Release a pre-connection slot after a future reliability layer accepts
    /// or rejects the client. This alone never creates a connected player.
    pub fn release_pending(&mut self, peer: SocketAddr) -> bool {
        self.pending.remove(&peer).is_some()
    }

    /// Process a single raw UDP payload and optionally produce a tiny reply.
    /// Unknown/truncated datagrams are silently ignored. Called after query
    /// dispatch; query and legacy RakNet use the same UDP socket.
    pub fn handle(&mut self, bytes: &[u8], peer: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        let request = decode_offline(bytes)?;
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
                let mut reply = vec![legacy_id::PONG];
                reply.extend_from_slice(&timestamp);
                Some(reply)
            }
            OfflineRequest::ConnectionStart => {
                if self.pending.contains_key(&peer) {
                    // Retransmission: preserve original expiry, don't consume a
                    // second slot or keep half-open peers alive forever.
                    return Some(vec![legacy_id::OPEN_CONNECTION_REPLY, 0]);
                }
                if self.pending.len() >= self.max_pending
                    || self.pending.keys().filter(|addr| addr.ip() == peer.ip()).count() >= self.max_per_ip {
                    self.stats.denied_full += 1;
                    return Some(vec![legacy_id::NO_FREE_INCOMING_CONNECTIONS, 0]);
                }
                self.pending.insert(peer, PendingPeer { created: now });
                self.stats.opens_replied += 1;
                Some(vec![legacy_id::OPEN_CONNECTION_REPLY, 0])
            }
        }
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
