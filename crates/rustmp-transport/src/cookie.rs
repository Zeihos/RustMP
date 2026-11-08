//! Legacy open.mp offline cookie wire exchange.
//!
//! Reference: openmultiplayer/RakNet, SAMPRakNet.cpp OnConnectionRequest,
//! SAMPRakNet.hpp markers, PacketEnumerations.h RAKNET_LEGACY.
//!
//! Cookie replies are three bytes: ID_OPEN_CONNECTION_COOKIE (26), then
//! little-endian u16 cookie. A client retries ID_OPEN_CONNECTION_REQUEST (24)
//! with the cookie XORed with its protocol marker (0x6969 or 0x6D70).
//!
//! This implementation is deliberately limited to the opt-in LOOPBACK
//! diagnostic. 16-bit cookies are a weak off-path check, NOT authentication,
//! encryption, or proof of client identity. The standard-library RandomState
//! seeds this process-local table, but its hash is not a cryptographic MAC.
//! Do not enable this gate for untrusted public traffic.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const ID_OPEN_CONNECTION_REQUEST: u8 = 24;
pub const ID_OPEN_CONNECTION_REPLY: u8 = 25;
pub const ID_OPEN_CONNECTION_COOKIE: u8 = 26;
pub const SAMP_COOKIE_XOR: u16 = 0x6969;
pub const OMP_COOKIE_XOR: u16 = 0x6D70;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieFlavor { OriginalSamp, OpenMp }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieVerdict {
    Challenge([u8; 3]),
    Valid(CookieFlavor),
}

pub struct CookieGate {
    state: RandomState,
}

impl Default for CookieGate {
    fn default() -> Self { Self::new() }
}

impl CookieGate {
    pub fn new() -> Self { Self { state: RandomState::new() } }

    /// Deterministic per-IP token for the lifetime of this gate, regardless
    /// of the client's UDP source port. Does not grant a session on its own.
    pub fn cookie_for(&self, ip: Ipv4Addr) -> u16 {
        let mut h = self.state.build_hasher();
        "RUSTMP local cookie probe".hash(&mut h);
        ip.hash(&mut h);
        let n = h.finish();
        let mut cookie = ((n >> 48) ^ (n >> 32) ^ (n >> 16) ^ n) as u16;
        // Keep the common all-zero offline request from *accidentally*
        // satisfying either recognized marker after a rare collision.
        if cookie == OMP_COOKIE_XOR || cookie == SAMP_COOKIE_XOR {
            cookie = cookie.wrapping_add(1);
        }
        cookie
    }

    pub fn check(
        &self, peer: SocketAddr, request: &[u8],
    ) -> Option<CookieVerdict> {
        if request.len() != 3 || request[0] != ID_OPEN_CONNECTION_REQUEST {
            return None;
        }
        let IpAddr::V4(ip) = peer.ip() else { return None };
        let cookie = self.cookie_for(ip);
        let received = u16::from_le_bytes([request[1], request[2]]);
        if received ^ OMP_COOKIE_XOR == cookie {
            return Some(CookieVerdict::Valid(CookieFlavor::OpenMp));
        }
        if received ^ SAMP_COOKIE_XOR == cookie {
            return Some(CookieVerdict::Valid(CookieFlavor::OriginalSamp));
        }
        let [lo, hi] = cookie.to_le_bytes();
        Some(CookieVerdict::Challenge([ID_OPEN_CONNECTION_COOKIE, lo, hi]))
    }

    pub fn encode_request(&self, peer: SocketAddr, flavor: CookieFlavor) -> Option<[u8; 3]> {
        let IpAddr::V4(ip) = peer.ip() else { return None };
        let marker = match flavor {
            CookieFlavor::OriginalSamp => SAMP_COOKIE_XOR,
            CookieFlavor::OpenMp => OMP_COOKIE_XOR,
        };
        let [lo,hi] = (self.cookie_for(ip) ^ marker).to_le_bytes();
        Some([ID_OPEN_CONNECTION_REQUEST, lo, hi])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port:u16)->SocketAddr {
        SocketAddr::from(([127,0,0,1],port))
    }

    #[test]
    fn challenge_then_valid_openmp_retry() {
        let gate=CookieGate::new();
        let client=peer(9000);
        let challenge=gate.check(client,&[24,0,0]).unwrap();
        let CookieVerdict::Challenge(bytes)=challenge else { panic!("expected challenge") };
        assert_eq!(bytes[0],26);
        assert_eq!(u16::from_le_bytes([bytes[1],bytes[2]]),
            gate.cookie_for(Ipv4Addr::LOCALHOST));
        let xored=u16::from_le_bytes([bytes[1],bytes[2]]) ^ OMP_COOKIE_XOR;
        let [lo,hi]=xored.to_le_bytes();
        assert_eq!(gate.check(client,&[24,lo,hi]),
            Some(CookieVerdict::Valid(CookieFlavor::OpenMp)));
    }

    #[test]
    fn original_samp_marker_is_supported_on_openmp_fork() {
        let gate=CookieGate::new();
        let p=peer(32000);
        let retry=gate.encode_request(p,CookieFlavor::OriginalSamp).unwrap();
        assert_eq!(gate.check(p,&retry),
            Some(CookieVerdict::Valid(CookieFlavor::OriginalSamp)));
        // The cookie is IP-bound, not per UDP port.
        assert_eq!(gate.check(peer(32001),&retry),
            Some(CookieVerdict::Valid(CookieFlavor::OriginalSamp)));
    }

    #[test]
    fn malformed_and_wrong_tokens_never_pass() {
        let gate=CookieGate::new();
        let p=peer(1);
        assert_eq!(gate.check(p,&[]),None);
        assert_eq!(gate.check(p,&[24]),None);
        assert_eq!(gate.check(p,&[24,0,0,0]),None);
        assert_eq!(gate.check(p,&[16,0,0]),None);
        assert_eq!(gate.check("[::1]:9999".parse().unwrap(),&[24,0,0]),None);
        let valid=gate.encode_request(p,CookieFlavor::OpenMp).unwrap();
        let mut wrong=valid;
        wrong[1]^=0xff;
        wrong[2]^=0xff;
        assert!(matches!(gate.check(p,&wrong),Some(CookieVerdict::Challenge(_))));
        assert!(matches!(gate.check(p,&[24,0,0]),Some(CookieVerdict::Challenge(_))));
    }

    #[test]
    fn no_peer_state_or_external_secrets_in_wire_values() {
        let gate=CookieGate::new();
        let p=peer(7777);
        for _ in 0..100 {
            assert!(matches!(gate.check(p,&[24,0,0]),Some(CookieVerdict::Challenge(_))));
        }
        // No per-packet heap state and no auth table is stored by this gate.
        assert_eq!(gate.encode_request(p,CookieFlavor::OpenMp).unwrap()[0],24);
    }
}
