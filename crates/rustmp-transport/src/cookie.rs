//! Bounded one-time legacy open.mp cookie challenge for LOCAL LOOPBACK TESTS.
//!
//! Source for wire IDs, XOR markers and 3-byte shape:
//! openmultiplayer/RakNet SAMPRakNet.cpp / SAMPRakNet.hpp.
//!
//! The reference fork derives the cookie from the IPv4 address. This local
//! diagnostic strengthens replay isolation by tying *pending* cookie state
//! to the complete source SocketAddr, consuming each challenge once and
//! expiring it quickly. This stronger stateful behavior is not claimed to
//! match every real client retransmission and must be tested against traces.
//!
//! Only 16 bits are on the wire. RandomState is not a cryptographic MAC.
//! This must NEVER be exposed as game authentication or a public-facing gate.

use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const ID_OPEN_CONNECTION_REQUEST: u8 = 24;
pub const ID_OPEN_CONNECTION_REPLY: u8 = 25;
pub const ID_OPEN_CONNECTION_COOKIE: u8 = 26;
pub const SAMP_COOKIE_XOR: u16 = 0x6969;
pub const OMP_COOKIE_XOR: u16 = 0x6D70;

pub const COOKIE_TTL: Duration = Duration::from_secs(4);
pub const MAX_COOKIE_SLOTS: usize = 128;
pub const MAX_COOKIE_SLOTS_PER_IP: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieFlavor { OriginalSamp, OpenMp }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieVerdict {
    Challenge([u8; 3]),
    Valid(CookieFlavor),
    /// Already consumed or resource-limited. No datagram should be sent.
    Rejected,
}

#[derive(Clone, Copy)]
struct PendingCookie {
    created: Instant,
    value: u16,
    consumed: bool,
}

/// Fixed-size, per-endpoint cookie state. No session or player is admitted.
pub struct CookieGate {
    state: RandomState,
    nonce: u64,
    pending: HashMap<SocketAddr, PendingCookie>,
}

impl Default for CookieGate {
    fn default() -> Self { Self::new() }
}

impl CookieGate {
    pub fn new() -> Self {
        Self { state: RandomState::new(), nonce: 0, pending: HashMap::new() }
    }
    pub fn pending_count(&self) -> usize { self.pending.len() }

    /// Clear both expired challenges and consumed replay tombstones.
    /// Bad traffic never extends a challenge's original lifetime.
    pub fn cleanup(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, challenge| {
            now.saturating_duration_since(challenge.created) < COOKIE_TTL
        });
        before - self.pending.len()
    }

    fn next_cookie(&mut self, peer: SocketAddr) -> u16 {
        self.nonce = self.nonce.wrapping_add(1);
        let mut h = self.state.build_hasher();
        "RUSTMP loopback one-time cookie".hash(&mut h);
        peer.hash(&mut h);
        self.nonce.hash(&mut h);
        let n = h.finish();
        let mut cookie = ((n >> 48) ^ (n >> 32) ^ (n >> 16) ^ n) as u16;
        // Prevent zero-filled requests being mistaken for a client response.
        while cookie == OMP_COOKIE_XOR || cookie == SAMP_COOKIE_XOR {
            cookie = cookie.wrapping_add(1);
        }
        cookie
    }

    /// Validate an exact three-byte open request or challenge the peer.
    /// A complete endpoint may redeem a token once, while it is unexpired.
    /// A replay from another source port cannot redeem that token.
    pub fn check(&mut self, peer: SocketAddr, request: &[u8], now: Instant)
        -> Option<CookieVerdict>
    {
        if request.len() != 3 || request[0] != ID_OPEN_CONNECTION_REQUEST
            || !peer.is_ipv4()
        {
            return None;
        }
        self.cleanup(now);
        if let Some(challenge) = self.pending.get_mut(&peer) {
            if challenge.consumed {
                return Some(CookieVerdict::Rejected);
            }
            let received = u16::from_le_bytes([request[1], request[2]]);
            if received ^ OMP_COOKIE_XOR == challenge.value {
                challenge.consumed = true;
                return Some(CookieVerdict::Valid(CookieFlavor::OpenMp));
            }
            if received ^ SAMP_COOKIE_XOR == challenge.value {
                challenge.consumed = true;
                return Some(CookieVerdict::Valid(CookieFlavor::OriginalSamp));
            }
            let [lo, hi] = challenge.value.to_le_bytes();
            return Some(CookieVerdict::Challenge([ID_OPEN_CONNECTION_COOKIE, lo, hi]));
        }
        if self.pending.len() >= MAX_COOKIE_SLOTS
            || self.pending.keys().filter(|p| p.ip() == peer.ip()).count()
                >= MAX_COOKIE_SLOTS_PER_IP
        {
            return Some(CookieVerdict::Rejected);
        }
        let value = self.next_cookie(peer);
        self.pending.insert(peer, PendingCookie { created: now, value, consumed: false });
        let [lo, hi] = value.to_le_bytes();
        Some(CookieVerdict::Challenge([ID_OPEN_CONNECTION_COOKIE, lo, hi]))
    }

    /// Helper for constructing the *client* retry packet in tests.
    /// Does not consume server-side state.
    pub fn encode_request(&self, peer: SocketAddr, flavor: CookieFlavor)
        -> Option<[u8; 3]>
    {
        let token = self.pending.get(&peer)?.value;
        let marker = match flavor {
            CookieFlavor::OriginalSamp => SAMP_COOKIE_XOR,
            CookieFlavor::OpenMp => OMP_COOKIE_XOR,
        };
        let [lo, hi] = (token ^ marker).to_le_bytes();
        Some([ID_OPEN_CONNECTION_REQUEST, lo, hi])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127,0,0,1], port))
    }
    fn start(gate: &mut CookieGate, p: SocketAddr, now: Instant) -> [u8; 3] {
        match gate.check(p, &[24,0,0], now) {
            Some(CookieVerdict::Challenge(challenge)) => challenge,
            other => panic!("expected challenge, received {other:?}"),
        }
    }

    #[test]
    fn challenge_then_one_time_openmp_retry() {
        let now = Instant::now();
        let mut gate = CookieGate::new();
        let p = peer(9000);
        let challenge = start(&mut gate, p, now);
        assert_eq!(challenge[0], ID_OPEN_CONNECTION_COOKIE);
        let retry = gate.encode_request(p, CookieFlavor::OpenMp).unwrap();
        assert_eq!(gate.check(p,&retry,now),
            Some(CookieVerdict::Valid(CookieFlavor::OpenMp)));
        assert_eq!(gate.check(p,&retry,now),
            Some(CookieVerdict::Rejected));
        assert_eq!(gate.pending_count(),1); // consumed tombstone, no re-admission
    }

    #[test]
    fn challenge_is_bound_to_udp_endpoint_and_cannot_be_replayed_to_other_port() {
        let now=Instant::now();
        let mut gate=CookieGate::new();
        let a=peer(32000);
        let b=peer(32001);
        start(&mut gate,a,now);
        let retry=gate.encode_request(a,CookieFlavor::OriginalSamp).unwrap();
        assert!(matches!(gate.check(b,&retry,now),Some(CookieVerdict::Challenge(_))));
        assert_eq!(gate.check(a,&retry,now),
            Some(CookieVerdict::Valid(CookieFlavor::OriginalSamp)));
        assert_eq!(gate.check(a,&retry,now),
            Some(CookieVerdict::Rejected));
    }

    #[test]
    fn wrong_cookie_does_not_reset_expiry() {
        let now=Instant::now();
        let mut gate=CookieGate::new();
        let p=peer(32002);
        let first=start(&mut gate,p,now);
        assert_eq!(gate.check(p,&[24,0,0],now+COOKIE_TTL/2),
            Some(CookieVerdict::Challenge(first)));
        assert_eq!(gate.cleanup(now+COOKIE_TTL),1);
        assert_eq!(gate.pending_count(),0);
        // Stale response never validates: without a new outstanding challenge,
        // the gate issues a fresh challenge, regardless of supplied bytes.
        let old=gate.encode_request(p,CookieFlavor::OpenMp);
        assert_eq!(old,None);
        assert!(matches!(gate.check(p,&[24,0,0],now+COOKIE_TTL),
            Some(CookieVerdict::Challenge(_))));
    }

    #[test]
    fn malformed_headers_and_ipv6_never_allocate() {
        let mut gate=CookieGate::new();
        let now=Instant::now();
        assert_eq!(gate.check(peer(1),&[],now),None);
        assert_eq!(gate.check(peer(1),&[24],now),None);
        assert_eq!(gate.check(peer(1),&[24,0,0,0],now),None);
        assert_eq!(gate.check(peer(1),&[16,0,0],now),None);
        assert_eq!(gate.check("[::1]:9000".parse().unwrap(),&[24,0,0],now),None);
        assert_eq!(gate.pending_count(),0);
    }

    #[test]
    fn per_ip_capacity_is_bounded_and_recovers_after_expiration() {
        let now=Instant::now();
        let mut gate=CookieGate::new();
        for port in 10000..10000+MAX_COOKIE_SLOTS_PER_IP as u16 {
            start(&mut gate,peer(port),now);
        }
        assert_eq!(gate.pending_count(),MAX_COOKIE_SLOTS_PER_IP);
        assert_eq!(gate.check(peer(20000),&[24,0,0],now),
            Some(CookieVerdict::Rejected));
        assert_eq!(gate.cleanup(now+COOKIE_TTL),MAX_COOKIE_SLOTS_PER_IP);
        assert!(matches!(gate.check(peer(20000),&[24,0,0],now+COOKIE_TTL),
            Some(CookieVerdict::Challenge(_))));
    }

    #[test]
    fn global_capacity_limited_across_different_ipv4_addresses() {
        let now=Instant::now();
        let mut gate=CookieGate::new();
        for idx in 0..MAX_COOKIE_SLOTS {
            let a=SocketAddr::from(([127,0,(idx/256) as u8,(idx%256) as u8],30000));
            assert!(matches!(gate.check(a,&[24,0,0],now),Some(CookieVerdict::Challenge(_))));
        }
        assert_eq!(gate.pending_count(),MAX_COOKIE_SLOTS);
        let extra=SocketAddr::from(([127,1,1,1],30000));
        assert_eq!(gate.check(extra,&[24,0,0],now),Some(CookieVerdict::Rejected));
        assert_eq!(gate.cleanup(now+COOKIE_TTL),MAX_COOKIE_SLOTS);
    }

    #[test]
    fn repeat_wrong_cookie_retains_single_challenge_without_memory_growth() {
        let now=Instant::now();
        let mut gate=CookieGate::new();
        let p=peer(7777);
        let initial=start(&mut gate,p,now);
        for _ in 0..100 {
            assert_eq!(gate.check(p,&[24,0,0],now),Some(CookieVerdict::Challenge(initial)));
        }
        assert_eq!(gate.pending_count(),1);
    }
}
