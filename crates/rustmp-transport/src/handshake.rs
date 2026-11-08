//! Server-side legacy RakNet connection handshake state machine.
//!
//! STATUS: library-only compatibility milestone. NOT connected to the live UDP
//! listener and NOT a proof of SA-MP/open.mp game client compatibility.
//! The fork in openmultiplayer/RakNet uses a per-connection static auth table;
//! this crate deliberately does not ship hard-coded challenge credentials.
//! Production must supply valid table pairs and independently authenticate,
//! rate-limit and integrity-check the incoming reliable transport.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use crate::{LegacyWireProfile, OfflineGateway};

pub const MAX_HANDSHAKES: usize = 128;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_AUTH_RESPONSE_LEN: usize = 63;
pub const MAX_AUTH_CHALLENGE_LEN: usize = 62;
pub const MAX_RAKNET_PASSWORD_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    NoOfflineRequest,
    NotObserved,
    InProgress,
    Capacity,
    InvalidRequest,
    InvalidPassword,
    UnsupportedAddress,
    MissingChallengeSource,
    InvalidAuthPair,
    InvalidAuthResponse,
    UnexpectedState,
    InvalidConfirmation,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    AwaitAuthResponse,
    AwaitClientConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPair {
    /// The printable challenge string (without trailing NUL).
    pub challenge: Vec<u8>,
    /// Response from a compatible client, without trailing NUL.
    pub expected_response: Vec<u8>,
}

impl AuthPair {
    fn valid(&self) -> bool {
        !self.challenge.is_empty()
            && self.challenge.len() <= MAX_AUTH_CHALLENGE_LEN
            && !self.expected_response.is_empty()
            && self.expected_response.len() <= MAX_AUTH_RESPONSE_LEN
            && self.challenge.iter().all(u8::is_ascii_graphic)
            && self.expected_response.iter().all(u8::is_ascii_graphic)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acceptance {
    pub client_ipv4: [u8; 4],
    pub client_port: u16,
    pub player_index: u16,
    pub token: u32,
}

#[derive(Debug, Clone)]
struct Attempt {
    started: Instant,
    profile: LegacyWireProfile,
    phase: HandshakePhase,
    advertised_server: SocketAddr,
    acceptance: Acceptance,
    expected_auth: Option<Vec<u8>>,
}

/// Packet IDs verified against the original SA-MP enum (including dummy
/// entries) and the open.mp RakNet RAKNET_LEGACY enum.
pub fn auth_key_id(profile: LegacyWireProfile) -> Option<u8> {
    match profile {
        LegacyWireProfile::Samp037 => None,
        LegacyWireProfile::OpenMpRakNet => Some(12),
    }
}
pub fn accepted_id(profile: LegacyWireProfile) -> u8 {
    match profile {
        LegacyWireProfile::Samp037 => 23,
        LegacyWireProfile::OpenMpRakNet => 34,
    }
}
pub fn incoming_id(profile: LegacyWireProfile) -> u8 {
    match profile {
        LegacyWireProfile::Samp037 => 26,
        LegacyWireProfile::OpenMpRakNet => 30,
    }
}

/// The old RakNet connection request is ID_CONNECTION_REQUEST followed by
/// raw password bytes (possibly empty), without an extra length prefix.
pub fn validate_connection_request(
    profile: LegacyWireProfile,
    payload: &[u8],
    password: &[u8],
) -> Result<(), HandshakeError> {
    if password.len() > MAX_RAKNET_PASSWORD_LEN
        || payload.is_empty()
        || payload[0] != profile.connection_request_id()
        || payload.len() != password.len() + 1
    {
        return Err(HandshakeError::InvalidRequest);
    }
    if &payload[1..] != password {
        return Err(HandshakeError::InvalidPassword);
    }
    Ok(())
}

/// open.mp sends ID_AUTH_KEY, one-byte length INCLUDING NUL, then a
/// NUL-terminated ASCII challenge. This is a reliable payload, not a UDP
/// datagram; an outside transport must wrap it with the verified codec.
pub fn encode_auth_challenge(pair: &AuthPair) -> Result<Vec<u8>, HandshakeError> {
    if !pair.valid() { return Err(HandshakeError::InvalidAuthPair); }
    let mut output = Vec::with_capacity(3 + pair.challenge.len());
    output.push(12);
    output.push((pair.challenge.len() + 1) as u8);
    output.extend_from_slice(&pair.challenge);
    output.push(0);
    Ok(output)
}

/// Response is ID_AUTH_KEY, response length excluding NUL, raw ASCII data.
/// Unlike the challenge, the response is not NUL-terminated on the wire.
pub fn decode_auth_response(data: &[u8]) -> Result<&[u8], HandshakeError> {
    if data.len() < 3 || data[0] != 12 { return Err(HandshakeError::InvalidAuthResponse); }
    let len = data[1] as usize;
    if len == 0 || len > MAX_AUTH_RESPONSE_LEN || data.len() != 2 + len
        || !data[2..].iter().all(u8::is_ascii_graphic)
    {
        return Err(HandshakeError::InvalidAuthResponse);
    }
    Ok(&data[2..])
}

/// RakNet acceptance: ID + IPv4 octets + little-endian port + little-endian
/// PlayerIndex (u16) + little-endian 32-bit server token.
/// Both original SA-MP and open.mp branches carry the trailing u32.
pub fn encode_acceptance(
    profile: LegacyWireProfile, acceptance: Acceptance,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(13);
    data.push(accepted_id(profile));
    data.extend_from_slice(&acceptance.client_ipv4);
    data.extend_from_slice(&acceptance.client_port.to_le_bytes());
    data.extend_from_slice(&acceptance.player_index.to_le_bytes());
    data.extend_from_slice(&acceptance.token.to_le_bytes());
    data
}

/// ID_NEW_INCOMING_CONNECTION is ID + IPv4 octets + LE port, 7 bytes.
pub fn decode_new_incoming(
    profile: LegacyWireProfile, payload: &[u8],
) -> Result<SocketAddr, HandshakeError> {
    if payload.len() != 7 || payload[0] != incoming_id(profile) {
        return Err(HandshakeError::InvalidConfirmation);
    }
    let addr = IpAddr::from([payload[1],payload[2],payload[3],payload[4]]);
    let port = u16::from_le_bytes([payload[5],payload[6]]);
    Ok(SocketAddr::new(addr,port))
}

#[derive(Default)]
pub struct HandshakeCoordinator {
    pending: HashMap<SocketAddr, Attempt>,
}

impl HandshakeCoordinator {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.pending.len() }
    pub fn phase(&self, peer: SocketAddr) -> Option<HandshakePhase> {
        self.pending.get(&peer).map(|a| a.phase)
    }
    pub fn discard(&mut self, peer: SocketAddr) -> bool {
        self.pending.remove(&peer).is_some()
    }
    pub fn cleanup(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, a| now.saturating_duration_since(a.started) < HANDSHAKE_TIMEOUT);
        before - self.pending.len()
    }

    /// Begin only for a previously observed, matching OfflineGateway slot.
    /// For original SA-MP, return the connection-accepted payload directly.
    /// For open.mp, return an auth challenge, requiring an externally supplied
    /// compatible challenge/response pair. Never invent placeholder pairs.
    ///
    /// The resulting bytes are *reliable payloads*, NOT raw UDP datagrams.
    pub fn begin(
        &mut self,
        offline: &OfflineGateway,
        peer: SocketAddr,
        request: &[u8],
        expected_password: &[u8],
        advertised_server: SocketAddr,
        player_index: u16,
        token: u32,
        auth_pair: Option<AuthPair>,
        now: Instant,
    ) -> Result<Vec<u8>, HandshakeError> {
        self.cleanup(now);
        if self.pending.contains_key(&peer) { return Err(HandshakeError::InProgress); }
        if self.pending.len() >= MAX_HANDSHAKES { return Err(HandshakeError::Capacity); }
        let profile = offline.pending_profile(peer, now)
            .ok_or(HandshakeError::NoOfflineRequest)?;
        if !offline.saw_reliable_request(peer) { return Err(HandshakeError::NotObserved); }
        let ipv4 = match peer.ip() {
            IpAddr::V4(address) => address.octets(),
            IpAddr::V6(_) => return Err(HandshakeError::UnsupportedAddress),
        };
        if !advertised_server.is_ipv4() || advertised_server.port() == 0 {
            return Err(HandshakeError::UnsupportedAddress);
        }
        validate_connection_request(profile, request, expected_password)?;
        let acceptance = Acceptance {
            client_ipv4: ipv4, client_port: peer.port(), player_index, token,
        };
        let (phase, response, expected_auth) = match profile {
            LegacyWireProfile::Samp037 =>
                (HandshakePhase::AwaitClientConfirmation,
                 encode_acceptance(profile, acceptance), None),
            LegacyWireProfile::OpenMpRakNet => {
                let pair = auth_pair.ok_or(HandshakeError::MissingChallengeSource)?;
                let challenge = encode_auth_challenge(&pair)?;
                (HandshakePhase::AwaitAuthResponse, challenge, Some(pair.expected_response))
            }
        };
        self.pending.insert(peer, Attempt {
            started: now, profile, phase, acceptance, advertised_server,
            expected_auth,
        });
        Ok(response)
    }

    /// Verify a response with this attempt's expected pair. Malformed or
    /// incorrect responses abort the attempt; the live transport must also
    /// enforce rate limits and reliability-layer duplicate suppression.
    pub fn receive_auth_response(
        &mut self, peer: SocketAddr, payload: &[u8], now: Instant,
    ) -> Result<Vec<u8>, HandshakeError> {
        let attempt = self.pending.get(&peer).ok_or(HandshakeError::NoOfflineRequest)?;
        if now.saturating_duration_since(attempt.started) >= HANDSHAKE_TIMEOUT {
            self.discard(peer);
            return Err(HandshakeError::Expired);
        }
        if attempt.phase != HandshakePhase::AwaitAuthResponse {
            return Err(HandshakeError::UnexpectedState);
        }
        let matches = match decode_auth_response(payload) {
            Ok(response) => attempt.expected_auth.as_deref() == Some(response),
            Err(_) => false,
        };
        if !matches {
            self.discard(peer);
            return Err(HandshakeError::InvalidAuthResponse);
        }
        let attempt = self.pending.get_mut(&peer).expect("attempt checked");
        attempt.phase = HandshakePhase::AwaitClientConfirmation;
        attempt.expected_auth = None;
        Ok(encode_acceptance(attempt.profile, attempt.acceptance))
    }

    /// A correctly formatted final confirmation is NOT cryptographic proof
    /// of client identity. It only completes the RakNet transport transcript.
    /// Game auth, RPC and client version checks must be implemented separately
    /// before granting a real player slot.
    pub fn receive_confirmation(
        &mut self, peer: SocketAddr, payload: &[u8], now: Instant,
    ) -> Result<LegacyWireProfile, HandshakeError> {
        let attempt = self.pending.get(&peer).ok_or(HandshakeError::NoOfflineRequest)?;
        if now.saturating_duration_since(attempt.started) >= HANDSHAKE_TIMEOUT {
            self.discard(peer);
            return Err(HandshakeError::Expired);
        }
        if attempt.phase != HandshakePhase::AwaitClientConfirmation {
            return Err(HandshakeError::UnexpectedState);
        }
        let target = decode_new_incoming(attempt.profile, payload)?;
        if target != attempt.advertised_server {
            return Err(HandshakeError::InvalidConfirmation);
        }
        let profile = attempt.profile;
        self.pending.remove(&peer);
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OfflineGateway;
    use rustmp_protocol::legacy_frame::{encode_datagram, Frame, Reliability};

    fn peer(port: u16) -> SocketAddr { SocketAddr::from(([127,0,0,1],port)) }
    fn server() -> SocketAddr { peer(7777) }

    fn reliable_request(profile: LegacyWireProfile, password: &[u8]) -> Vec<u8> {
        let mut data = vec![profile.connection_request_id()];
        data.extend_from_slice(password);
        data
    }

    fn prepare(offline: &mut OfflineGateway, address: SocketAddr,
        profile: LegacyWireProfile, password: &[u8], now: Instant)
    {
        let start = match profile {
            LegacyWireProfile::Samp037 => [16, 0, 0],
            LegacyWireProfile::OpenMpRakNet => [24, 0, 0],
        };
        assert!(offline.handle(&start, address, now).is_some());
        let payload = reliable_request(profile, password);
        let wire = encode_datagram(&[], &[Frame {
            sequence: 0, reliability: Reliability::Reliable,
            ordering: None, payload_bits: (payload.len()*8) as u16,
            payload, split: None,
        }]).unwrap();
        assert_eq!(offline.inspect_reliable_request(&wire,address,now),Some(profile));
    }

    fn confirmation(profile:LegacyWireProfile, target:SocketAddr)->Vec<u8>{
        let mut v=vec![incoming_id(profile)];
        let IpAddr::V4(ip)=target.ip() else {panic!("test IPv4")};
        v.extend_from_slice(&ip.octets());
        v.extend_from_slice(&target.port().to_le_bytes());
        v
    }

    #[test]
    fn original_samp_no_auth_key_and_complete_transcript() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        prepare(&mut offline,peer(20001),LegacyWireProfile::Samp037,b"",now);
        let mut h=HandshakeCoordinator::new();
        let reply=h.begin(&offline,peer(20001),&[8],b"",server(),7,0x12345678,None,now).unwrap();
        assert_eq!(reply,vec![23,127,0,0,1,0x21,0x4e,7,0,0x78,0x56,0x34,0x12]);
        assert_eq!(h.phase(peer(20001)),Some(HandshakePhase::AwaitClientConfirmation));
        assert_eq!(h.receive_confirmation(peer(20001),&confirmation(LegacyWireProfile::Samp037,server()),now),
            Ok(LegacyWireProfile::Samp037));
        assert_eq!(h.len(),0);
    }

    #[test]
    fn openmp_challenge_must_match_supplied_pair() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        prepare(&mut offline,peer(20002),LegacyWireProfile::OpenMpRakNet,b"pass",now);
        let pair=AuthPair {challenge:b"CHALLENGE".to_vec(),expected_response:b"ANSWER".to_vec()};
        let mut h=HandshakeCoordinator::new();
        assert_eq!(h.begin(&offline,peer(20002),&[11,b'p',b'a',b's',b's'],b"pass",
            server(),1,99,None,now),Err(HandshakeError::MissingChallengeSource));
        let challenge=h.begin(&offline,peer(20002),&[11,b'p',b'a',b's',b's'],b"pass",
            server(),1,99,Some(pair),now).unwrap();
        assert_eq!(challenge.as_slice(), b"\x0c\x0aCHALLENGE\x00");
        assert_eq!(h.phase(peer(20002)),Some(HandshakePhase::AwaitAuthResponse));
        let accepted=h.receive_auth_response(peer(20002),b"\x0c\x06ANSWER",now).unwrap();
        assert_eq!(accepted,vec![34,127,0,0,1,0x22,0x4e,1,0,99,0,0,0]);
        assert_eq!(h.phase(peer(20002)),Some(HandshakePhase::AwaitClientConfirmation));
        assert_eq!(h.receive_confirmation(peer(20002),
            &confirmation(LegacyWireProfile::OpenMpRakNet,server()),now),
            Ok(LegacyWireProfile::OpenMpRakNet));
    }

    #[test]
    fn wrong_password_blocks_without_creating_state() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        prepare(&mut offline,peer(20003),LegacyWireProfile::Samp037,b"bad",now);
        let mut h=HandshakeCoordinator::new();
        assert_eq!(h.begin(&offline,peer(20003),&[8,b'b',b'a',b'd'],b"good",
            server(),0,0,None,now),Err(HandshakeError::InvalidPassword));
        assert_eq!(h.len(),0);
    }

    #[test]
    fn no_offline_slot_or_observed_request_is_denied() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        let mut h=HandshakeCoordinator::new();
        assert_eq!(h.begin(&offline,peer(20001),&[8],b"",server(),0,0,None,now),
            Err(HandshakeError::NoOfflineRequest));
        offline.handle(&[16,0,0],peer(20001),now);
        assert_eq!(h.begin(&offline,peer(20001),&[8],b"",server(),0,0,None,now),
            Err(HandshakeError::NotObserved));
    }

    #[test]
    fn invalid_auth_aborts_and_cannot_be_replayed() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        prepare(&mut offline,peer(20002),LegacyWireProfile::OpenMpRakNet,b"",now);
        let mut h=HandshakeCoordinator::new();
        let pair=AuthPair{challenge:b"C".to_vec(),expected_response:b"RIGHT".to_vec()};
        h.begin(&offline,peer(20002),&[11],b"",server(),0,0,Some(pair),now).unwrap();
        assert_eq!(h.receive_auth_response(peer(20002),b"\x0c\x05WRONG",now),
            Err(HandshakeError::InvalidAuthResponse));
        assert_eq!(h.phase(peer(20002)),None);
        assert_eq!(h.receive_auth_response(peer(20002),b"\x0c\x05RIGHT",now),
            Err(HandshakeError::NoOfflineRequest));
    }

    #[test]
    fn confirmation_not_accepted_before_auth_or_from_wrong_address() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        prepare(&mut offline,peer(20002),LegacyWireProfile::OpenMpRakNet,b"",now);
        let mut h=HandshakeCoordinator::new();
        h.begin(&offline,peer(20002),&[11],b"",server(),0,0,
            Some(AuthPair{challenge:b"C".to_vec(),expected_response:b"R".to_vec()}),now).unwrap();
        let valid_confirmation=confirmation(LegacyWireProfile::OpenMpRakNet,server());
        assert_eq!(h.receive_confirmation(peer(20002),&valid_confirmation,now),
            Err(HandshakeError::UnexpectedState));
        h.receive_auth_response(peer(20002),b"\x0c\x01R",now).unwrap();
        assert_eq!(h.receive_confirmation(peer(20003),&valid_confirmation,now),
            Err(HandshakeError::NoOfflineRequest));
        assert_eq!(h.receive_confirmation(peer(20002),
            &confirmation(LegacyWireProfile::OpenMpRakNet,peer(8888)),now),
            Err(HandshakeError::InvalidConfirmation));
        assert_eq!(h.len(),1);
    }

    #[test]
    fn malformed_lengths_and_payload_ids_rejected() {
        assert_eq!(decode_auth_response(&[]),Err(HandshakeError::InvalidAuthResponse));
        assert_eq!(decode_auth_response(&[12,2,b'A']),Err(HandshakeError::InvalidAuthResponse));
        assert_eq!(decode_auth_response(&[12,1,0]),Err(HandshakeError::InvalidAuthResponse));
        assert_eq!(decode_auth_response(&[11,1,b'A']),Err(HandshakeError::InvalidAuthResponse));
        assert_eq!(decode_new_incoming(LegacyWireProfile::Samp037,&[26;6]),
            Err(HandshakeError::InvalidConfirmation));
        assert_eq!(encode_auth_challenge(&AuthPair{
            challenge:vec![b'X';63],expected_response:b"OK".to_vec()}),
            Err(HandshakeError::InvalidAuthPair));
    }

    #[test]
    fn expiration_and_non_extending_timeout() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(4);
        prepare(&mut offline,peer(20001),LegacyWireProfile::Samp037,b"",now);
        let mut h=HandshakeCoordinator::new();
        h.begin(&offline,peer(20001),&[8],b"",server(),0,0,None,now).unwrap();
        assert_eq!(h.cleanup(now + HANDSHAKE_TIMEOUT/2),0);
        assert_eq!(h.cleanup(now + HANDSHAKE_TIMEOUT),1);
        assert_eq!(h.receive_confirmation(peer(20001),
            &confirmation(LegacyWireProfile::Samp037,server()),now+HANDSHAKE_TIMEOUT),
            Err(HandshakeError::NoOfflineRequest));
    }

    #[test]
    fn bounds_and_isolation_for_public_server_usage() {
        let now=Instant::now();
        let mut offline=OfflineGateway::new(MAX_HANDSHAKES+1);
        let mut h=HandshakeCoordinator::new();
        for i in 0..MAX_HANDSHAKES {
            let p=SocketAddr::from(([10,0,0,(i+1) as u8], 30000 + i as u16));
            prepare(&mut offline,p,LegacyWireProfile::Samp037,b"",now);
            h.begin(&offline,p,&[8],b"",server(),i as u16,0,None,now).unwrap();
        }
        let p=SocketAddr::from(([10,0,1,1],32000));
        prepare(&mut offline,p,LegacyWireProfile::Samp037,b"",now);
        assert_eq!(h.begin(&offline,p,&[8],b"",server(),0,0,None,now),
            Err(HandshakeError::Capacity));
        assert_eq!(h.len(),MAX_HANDSHAKES);
    }
}
