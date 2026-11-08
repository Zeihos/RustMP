//! Legacy SA-MP UDP query packet codec.
//! Spec: https://open.mp/docs/tutorials/QueryMechanism
//! Queries are NOT the RakNet gameplay transport.
use encoding_rs::{WINDOWS_1251, WINDOWS_1252};

pub const QUERY_HEADER_LEN: usize = 11;
pub const MAX_DATAGRAM: usize = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextEncoding {
    Windows1251,
    Windows1252,
}

impl TextEncoding {
    fn encode(self, text: &str) -> Vec<u8> {
        let codec = match self {
            Self::Windows1251 => WINDOWS_1251,
            Self::Windows1252 => WINDOWS_1252,
        };
        let (bytes, _, _) = codec.encode(text);
        bytes.into_owned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPlayer {
    pub id: u16,
    pub name: String,
    pub score: i32,
    pub ping: u32,
}

#[derive(Clone, Debug)]
pub struct QuerySnapshot {
    pub hostname: String,
    pub gamemode: String,
    pub language: String,
    pub passworded: bool,
    pub max_players: u16,
    pub players: Vec<QueryPlayer>,
    pub rules: Vec<(String, String)>,
    pub encoding: TextEncoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    Info,
    Rules,
    Clients,
    DetailedClients,
    Ping,
}

impl Opcode {
    fn parse(value: u8) -> Option<Self> {
        match value {
            b'i' => Some(Self::Info),
            b'r' => Some(Self::Rules),
            b'c' => Some(Self::Clients),
            b'd' => Some(Self::DetailedClients),
            b'p' => Some(Self::Ping),
            _ => None, // In particular, remote RCON 'x' is deliberately disabled.
        }
    }
}

#[derive(Debug)]
pub struct Request<'a> {
    pub header: [u8; QUERY_HEADER_LEN],
    pub opcode: Opcode,
    pub payload: &'a [u8],
}

pub fn parse_request(data: &[u8]) -> Option<Request<'_>> {
    if !(QUERY_HEADER_LEN..=512).contains(&data.len()) || !data.starts_with(b"SAMP") {
        return None;
    }
    let opcode = Opcode::parse(data[10])?;
    // Ping requires 4 bytes of challenge; other queries have no payload.
    match opcode {
        Opcode::Ping if data.len() != QUERY_HEADER_LEN + 4 => return None,
        Opcode::Ping => {}
        _ if data.len() != QUERY_HEADER_LEN => return None,
        _ => {}
    }
    let mut header = [0u8; QUERY_HEADER_LEN];
    header.copy_from_slice(&data[..QUERY_HEADER_LEN]);
    Some(Request { header, opcode, payload: &data[QUERY_HEADER_LEN..] })
}

fn add_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn add_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn add_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_short_string(out: &mut Vec<u8>, text: &str, encoding: TextEncoding) -> bool {
    let bytes = encoding.encode(text);
    if bytes.len() > u8::MAX as usize || out.len() + 1 + bytes.len() > MAX_DATAGRAM {
        return false;
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(&bytes);
    true
}

fn push_long_string(out: &mut Vec<u8>, text: &str, encoding: TextEncoding) -> bool {
    let bytes = encoding.encode(text);
    if bytes.len() > u32::MAX as usize || out.len() + 4 + bytes.len() > MAX_DATAGRAM {
        return false;
    }
    add_u32(out, bytes.len() as u32);
    out.extend_from_slice(&bytes);
    true
}

/// Build a query response. Never responds to unknown packets or legacy RCON.
/// Datagram size is bounded to avoid fragmentation and unnecessary amplification.
pub fn respond(req: &Request<'_>, snapshot: &QuerySnapshot) -> Option<Vec<u8>> {
    let mut response = Vec::with_capacity(256);
    response.extend_from_slice(&req.header);
    let encoding = snapshot.encoding;
    match req.opcode {
        Opcode::Info => {
            response.push(u8::from(snapshot.passworded));
            add_u16(&mut response, snapshot.players.len().min(u16::MAX as usize) as u16);
            add_u16(&mut response, snapshot.max_players);
            if !push_long_string(&mut response, &snapshot.hostname, encoding)
                || !push_long_string(&mut response, &snapshot.gamemode, encoding)
                || !push_long_string(&mut response, &snapshot.language, encoding) {
                return None;
            }
        }
        Opcode::Rules => {
            let count_pos = response.len();
            add_u16(&mut response, 0);
            let mut count = 0u16;
            for (key, value) in &snapshot.rules {
                let checkpoint = response.len();
                if !push_short_string(&mut response, key, encoding)
                    || !push_short_string(&mut response, value, encoding) {
                    response.truncate(checkpoint);
                    continue;
                }
                count += 1;
                if count == u16::MAX { break; }
            }
            response[count_pos..count_pos + 2].copy_from_slice(&count.to_le_bytes());
        }
        Opcode::Clients | Opcode::DetailedClients => {
            let detailed = req.opcode == Opcode::DetailedClients;
            let count_pos = response.len();
            add_u16(&mut response, 0);
            let mut count = 0u16;
            for player in &snapshot.players {
                if detailed && player.id > u8::MAX as u16 { continue; }
                let checkpoint = response.len();
                if detailed { response.push(player.id as u8); }
                if !push_short_string(&mut response, &player.name, encoding) {
                    response.truncate(checkpoint);
                    continue;
                }
                if response.len() + 4 + (if detailed { 4 } else { 0 }) > MAX_DATAGRAM {
                    response.truncate(checkpoint);
                    break;
                }
                add_i32(&mut response, player.score);
                if detailed { add_u32(&mut response, player.ping); }
                count += 1;
                if count == u16::MAX { break; }
            }
            response[count_pos..count_pos + 2].copy_from_slice(&count.to_le_bytes());
        }
        Opcode::Ping => response.extend_from_slice(req.payload),
    }
    if response.len() > MAX_DATAGRAM { return None; }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(opcode: u8) -> Vec<u8> {
        let mut bytes = b"SAMP\x7f\0\0\x01\x61\x1e".to_vec(); // 127.0.0.1:7777
        bytes.push(opcode);
        bytes
    }

    fn snapshot() -> QuerySnapshot {
        QuerySnapshot {
            hostname: "Тестовый сервер".into(),
            gamemode: "Rust Test".into(),
            language: "Русский".into(),
            passworded: false,
            max_players: 50,
            players: vec![QueryPlayer { id: 7, name: "Player_1".into(), score: 42, ping: 55 }],
            rules: vec![("version".into(), "0.1".into())],
            encoding: TextEncoding::Windows1251,
        }
    }

    #[test]
    fn info_packet_has_legacy_fields_in_correct_order() {
        let bytes = request(b'i');
        let reply = respond(&parse_request(&bytes).unwrap(), &snapshot()).unwrap();
        assert_eq!(&reply[..11], &bytes);
        assert_eq!(reply[11], 0); // password
        assert_eq!(&reply[12..14], &1u16.to_le_bytes());
        assert_eq!(&reply[14..16], &50u16.to_le_bytes());
        let len = u32::from_le_bytes(reply[16..20].try_into().unwrap()) as usize;
        assert_eq!(len, "Тестовый сервер".chars().count()); // CP1251 has 1 byte per letter
        let (hostname, _, errors) = WINDOWS_1251.decode(&reply[20..20 + len]);
        assert!(!errors);
        assert_eq!(hostname, "Тестовый сервер");
    }

    #[test]
    fn ping_echo_and_bad_packets() {
        let mut bytes = request(b'p');
        bytes.extend_from_slice(&[0, 1, 254, 255]);
        let reply = respond(&parse_request(&bytes).unwrap(), &snapshot()).unwrap();
        assert_eq!(reply, bytes);
        assert!(parse_request(&request(b'x')).is_none());
        assert!(parse_request(&request(b'p')).is_none());
        assert!(parse_request(b"SAMP").is_none());
        let mut malformed = request(b'i');
        malformed.push(1);
        assert!(parse_request(&malformed).is_none());
    }

    #[test]
    fn client_and_detailed_lists() {
        let players = snapshot();
        let clients = request(b'c');
        let reply = respond(&parse_request(&clients).unwrap(), &players).unwrap();
        assert_eq!(&reply[11..13], &1u16.to_le_bytes());
        assert_eq!(reply[13], 8);
        assert_eq!(&reply[14..22], b"Player_1");
        assert_eq!(&reply[22..26], &42i32.to_le_bytes());

        let detailed = request(b'd');
        let reply = respond(&parse_request(&detailed).unwrap(), &players).unwrap();
        assert_eq!(&reply[11..13], &1u16.to_le_bytes());
        assert_eq!(reply[13], 7);
        assert_eq!(&reply[23..27], &42i32.to_le_bytes());
        assert_eq!(&reply[27..31], &55u32.to_le_bytes());
    }

    #[test]
    fn outputs_are_bounded_and_rule_count_is_consistent() {
        let mut state = snapshot();
        state.players = (0..1000).map(|i| QueryPlayer {
            id: i,
            name: "a_long_test_player_name".into(),
            score: i as i32,
            ping: 30,
        }).collect();
        state.rules = (0..200).map(|i| (format!("key{i}"), "v".repeat(100))).collect();
        for opcode in [b'r', b'c', b'd'] {
            let datagram = request(opcode);
            let reply = respond(&parse_request(&datagram).unwrap(), &state).unwrap();
            assert!(reply.len() <= MAX_DATAGRAM);
            let count = u16::from_le_bytes([reply[11], reply[12]]);
            assert!(count > 0);
            assert!(count <= 200 || opcode != b'r');
        }
    }
}
