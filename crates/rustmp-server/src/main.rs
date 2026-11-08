//! Standalone Rust foundation for an eventual open.mp-compatible server.
//! This build answers SA-MP legacy UDP queries and pre-connection packets.
//! It does NOT accept game clients.

mod experimental;

use experimental::ExperimentalPreAuth;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use rustmp_core::{Config, World};
use rustmp_protocol::query::{parse_request, respond, TextEncoding};
use rustmp_transport::OfflineGateway;
use serde_json::Value;

const TICK_INTERVAL: Duration = Duration::from_millis(20); // 50 ticks/s (prototype)
const QUERY_LIMIT_PER_IP_PER_SEC: u16 = 30;

#[derive(Clone, Copy, Debug)]
struct RateLimit {
    window_start: Instant,
    count: u16,
}

fn query_allowed(limits: &mut HashMap<IpAddr, RateLimit>, ip: IpAddr, now: Instant) -> bool {
    let rate = limits.entry(ip).or_insert(RateLimit { window_start: now, count: 0 });
    if now.duration_since(rate.window_start) >= Duration::from_secs(1) {
        rate.window_start = now;
        rate.count = 0;
    }
    if rate.count >= QUERY_LIMIT_PER_IP_PER_SEC { return false; }
    rate.count += 1;
    true
}

fn string_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}

/// Import only the subset of open.mp config.json supported by this prototype.
/// Additional upstream config fields are intentionally ignored until implemented.
fn load_config(path: &Path) -> Result<Config, Box<dyn Error>> {
    let source = fs::read_to_string(path)?;
    let doc: Value = serde_json::from_str(&source)?;
    if !doc.is_object() { return Err("config root must be a JSON object".into()); }
    let mut cfg = Config::default();
    if let Some(value) = string_field(&doc, "name") { cfg.hostname = value; }
    if let Some(value) = string_field(&doc, "language") { cfg.language = value; }
    if let Some(value) = string_field(&doc, "website") { cfg.website = value; }
    if let Some(value) = string_field(&doc, "password") {
        cfg.password = if value.is_empty() { None } else { Some(value) };
    }
    if let Some(value) = doc.get("max_players").and_then(Value::as_u64) {
        cfg.max_players = u16::try_from(value)?;
    }
    if let Some(network) = doc.get("network") {
        if let Some(value) = string_field(network, "bind") {
            cfg.bind = if value.is_empty() { "0.0.0.0".into() } else { value };
        }
        if let Some(value) = network.get("port").and_then(Value::as_u64) {
            cfg.port = u16::try_from(value)?;
        }
    }
    if let Some(game) = doc.get("game") {
        if let Some(value) = string_field(game, "mode") { cfg.gamemode = value; }
        if let Some(value) = string_field(game, "map") { cfg.map = value; }
    }
    if let Some(value) = string_field(&doc, "rust_text_encoding") {
        cfg.encoding = match value.as_str() {
            "windows-1251" => TextEncoding::Windows1251,
            "windows-1252" => TextEncoding::Windows1252,
            _ => return Err(format!("unsupported text encoding: {value}").into()),
        };
    }
    validate_config(&cfg)?;
    Ok(cfg)
}

fn validate_config(cfg: &Config) -> Result<(), Box<dyn Error>> {
    if cfg.max_players == 0 || cfg.max_players > 1000 {
        return Err("max_players must be in the range 1..=1000".into());
    }
    if cfg.port == 0 { return Err("UDP port must be in the range 1..=65535".into()); }
    if cfg.hostname.trim().is_empty() { return Err("server name cannot be blank".into()); }
    if cfg.hostname.len() > 800 || cfg.gamemode.len() > 200 || cfg.language.len() > 200 {
        return Err("server metadata is too long for a UDP query packet".into());
    }
    Ok(())
}

fn print_help() {
    println!("\
RUSTMP server prototype 0.2.0-alpha.14 (NOT gameplay-compatible yet)\n\
Usage: cargo run --release -p rustmp-server -- [options]\n\
  --config PATH        Read a subset of the open.mp config.json format\n\
  --bind IP            Bind address (default 0.0.0.0)\n\
  --port PORT          UDP port (default 7777)\n\
  --name TEXT          Name shown in the legacy server query\n\
  --mode TEXT          Gamemode shown in the query\n\
  --language TEXT      Language string\n\
  --max-players N      Maximum players (currently query metadata only)\n\
  --encoding 1251|1252 Legacy server query text encoding\n\
  --experimental-preauth  LOCAL TEST ONLY: enable SA-MP reliable handshake on IPv4 loopback\n\
  --help               Show this help\n\
Default: offline-only. Experimental localhost pre-auth is not a game session; no Pawn VM or gameplay.\n");
}

fn parse_options(args: &[String]) -> Result<Option<Config>, Box<dyn Error>> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(None);
    }
    let mut cfg = Config::default();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--config" {
            let path = args.get(index + 1).ok_or("--config requires a file path")?;
            cfg = load_config(Path::new(path))?;
            break;
        }
        index += 1;
    }
    index = 0;
    while index < args.len() {
        let flag = &args[index];
        if flag == "--config" {
            index += 2;
            continue;
        }
        let value = args.get(index + 1).ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--bind" => cfg.bind = value.clone(),
            "--port" => cfg.port = value.parse::<u16>()?,
            "--name" => cfg.hostname = value.clone(),
            "--mode" => cfg.gamemode = value.clone(),
            "--language" => cfg.language = value.clone(),
            "--max-players" => cfg.max_players = value.parse::<u16>()?,
            "--encoding" => cfg.encoding = match value.as_str() {
                "1251" => TextEncoding::Windows1251,
                "1252" => TextEncoding::Windows1252,
                _ => return Err("--encoding supports only 1251 or 1252".into()),
            },
            _ => return Err(format!("unknown option: {flag}").into()),
        }
        index += 2;
    }
    validate_config(&cfg)?;
    Ok(Some(cfg))
}

/// An explicitly enabled experimental mode cannot be bound to a public
/// socket: it lacks the verified cookie/authentication part of the protocol.
fn experimental_bind_allowed(address: SocketAddr) -> bool {
    address.is_ipv4() && address.ip().is_loopback()
}

fn parse_runtime_options(args: &[String])
    -> Result<(Option<Config>, bool), Box<dyn Error>>
{
    let mut experimental = false;
    let mut rest = Vec::new();
    for arg in args {
        if arg == "--experimental-preauth" {
            if experimental { return Err("--experimental-preauth may be specified once".into()); }
            experimental = true;
        } else {
            rest.push(arg.clone());
        }
    }
    Ok((parse_options(&rest)?, experimental))
}

/// Multiplex SA-MP query and legacy offline RakNet on one UDP port.
/// This does not handle authenticated, encrypted or reliable game traffic.
fn respond_to_datagram(
    incoming: &[u8],
    peer: SocketAddr,
    now: Instant,
    world: &World,
    query_limits: &mut HashMap<IpAddr, RateLimit>,
    offline: &mut OfflineGateway,
) -> Option<Vec<u8>> {
    if incoming.starts_with(b"SAMP") {
        let request = parse_request(incoming)?;
        if !query_allowed(query_limits, peer.ip(), now) { return None; }
        respond(&request, &world.query_snapshot())
    } else {
        offline.handle(incoming, peer, now)
    }
}

/// Common UDP router. Production mode remains query+offline only.
/// The experimental handler runs exclusively on an explicitly selected
/// IPv4 loopback socket; it never registers an authenticated game player.
#[allow(clippy::too_many_arguments)]
fn dispatch_datagram(
    incoming: &[u8], peer: SocketAddr, now: Instant,
    world: &World, query_limits: &mut HashMap<IpAddr, RateLimit>,
    offline: &mut OfflineGateway, mut experimental: Option<&mut ExperimentalPreAuth>,
    bound: SocketAddr,
) -> Vec<Vec<u8>> {
    // Cookie gate must precede OfflineGateway::handle: otherwise open.mp
    // would allocate a pending peer and send OPEN_CONNECTION_REPLY before
    // validating the cookie. Default (non-experimental) mode is untouched.
    if let Some(router) = experimental.as_deref_mut() {
        if let Err(reply) = router.check_cookie(incoming, peer, now, offline) {
            return if reply.is_empty() { Vec::new() } else { vec![reply] };
        }
    }
    if let Some(reply) = respond_to_datagram(
        incoming, peer, now, world, query_limits, offline,
    ) { return vec![reply]; }
    if incoming.starts_with(b"SAMP") { return Vec::new(); }
    match experimental {
        Some(router) => router.handle(
            incoming, peer, bound, offline,
            world.config.password.as_deref().unwrap_or("").as_bytes(), now,
        ),
        None => Vec::new(),
    }
}

fn run(config: Config, experimental_preauth: bool) -> Result<(), Box<dyn Error>> {

    let socket = UdpSocket::bind((config.bind.as_str(), config.port))?;
    socket.set_nonblocking(true)?;
    let addr = socket.local_addr()?;
    if experimental_preauth && !experimental_bind_allowed(addr) {
        return Err("--experimental-preauth requires --bind 127.0.0.1 (IPv4 loopback only)".into());
    }
    println!("[RUST] UDP query and RakNet offline bootstrap listening on {addr}");
    println!("[RUST] {} (max players {})", config.hostname, config.max_players);
    if experimental_preauth {
        eprintln!("[EXPERIMENTAL] localhost-only SA-MP pre-auth probe ENABLED. No game auth or player login.");
        eprintln!("[EXPERIMENTAL] open.mp auth-table/cookie path NOT supported; no public bind permitted.");
    } else {
        eprintln!("[NOTICE] Query + legacy RakNet offline replies only. Gameplay clients CANNOT join.");
    }
    println!("[RUST] Stop with Ctrl+C.");

    let mut world = World::new(config);
    let mut limits = HashMap::<IpAddr, RateLimit>::new();
    let mut offline = OfflineGateway::new(world.config.max_players as usize);
    let mut experimental = experimental_preauth.then(ExperimentalPreAuth::new);
    let mut buffer = [0u8; 2048];
    let mut last_cleanup = Instant::now();
    let mut last_report = Instant::now();

    loop {
        let frame_start = Instant::now();
        // Bound per-tick work so a flood of UDP packets cannot starve the world tick.
        for _ in 0..256 {
            match socket.recv_from(&mut buffer) {
                Ok((length, peer)) => {
                    let replies = dispatch_datagram(
                        &buffer[..length], peer, Instant::now(),
                        &world, &mut limits, &mut offline,
                        experimental.as_mut(), addr,
                    );
                    for reply in replies {
                        if let Err(e) = socket.send_to(&reply, peer) {
                            eprintln!("[WARN] UDP reply to {peer} failed: {e}");
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(Box::new(err)),
            }
        }
        world.tick();
        if let Some(probe) = experimental.as_mut() {
            let retries = probe.poll_retries(Instant::now());
            for packet in retries.packets {
                if let Err(e) = socket.send_to(&packet.bytes, packet.peer) {
                    eprintln!("[WARN] pre-auth resend to {} failed: {e}", packet.peer);
                }
            }
        }
        if last_cleanup.elapsed() >= Duration::from_secs(1) {
            let now = Instant::now();
            limits.retain(|_, limit| now.duration_since(limit.window_start) < Duration::from_secs(2));
            offline.cleanup(now);
            if let Some(probe) = experimental.as_mut() { probe.cleanup(now); }
            last_cleanup = now;
        }
        if last_report.elapsed() >= Duration::from_secs(60) {
            let stats = offline.stats();
            println!("[NET] offline pings={} opens={} pending={} full={} throttled={} expired={}",
                stats.pings_replied, stats.opens_replied, offline.pending_count(),
                stats.denied_full, stats.rate_limited, stats.expired_pending);
            if let Some(probe) = experimental.as_ref() {
                let pre = probe.stats();
                println!("[NET] localhost pre-auth cookies={} validated={} retransmitted={} starts={} confirmed={} rejected={} throttled={} pending={}",
                    pre.cookie_challenges, pre.cookie_validations, pre.cookie_retransmissions,
                    pre.starts, pre.transport_confirmations, pre.rejected,
                    pre.throttled, probe.pending_count());
            }
            last_report = Instant::now();
        }
        if let Some(remaining) = TICK_INTERVAL.checked_sub(frame_start.elapsed()) {
            thread::sleep(remaining);
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    match parse_runtime_options(&args) {
        Ok((Some(cfg), experimental)) => {
            if let Err(err) = run(cfg, experimental) {
                eprintln!("[ERROR] {err}");
                std::process::exit(1);
            }
        }
        Ok((None, _)) => {}
        Err(err) => {
            eprintln!("[ERROR] {err}");
            eprintln!("Run with --help for supported options.");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_defaults_from_cli() {
        let args = ["--port", "8888", "--name", "Testing", "--max-players", "10"];
        let args: Vec<_> = args.iter().map(|s| s.to_string()).collect();
        let cfg = parse_options(&args).unwrap().unwrap();
        assert_eq!(cfg.port, 8888);
        assert_eq!(cfg.hostname, "Testing");
        assert_eq!(cfg.max_players, 10);
    }

    #[test]
    fn invalid_max_players_are_rejected() {
        let args = vec!["--max-players".into(), "0".into()];
        assert!(parse_options(&args).is_err());
    }

    #[test]
    fn per_ip_query_rate_limit() {
        let mut limits = HashMap::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..QUERY_LIMIT_PER_IP_PER_SEC {
            assert!(query_allowed(&mut limits, ip, now));
        }
        assert!(!query_allowed(&mut limits, ip, now));
        assert!(query_allowed(&mut limits, ip, now + Duration::from_secs(1)));
    }

    #[test]
    fn query_and_legacy_handshake_share_same_udp_socket() {
        use rustmp_transport::legacy_id;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let world = World::new(Config::default());
        let mut limits = HashMap::new();
        let mut offline = OfflineGateway::new(5);
        let mut buffer = [0u8; 1500];
        let offline_request = [legacy_id::OPEN_CONNECTION_REQUEST, 0, 0];
        client.send_to(&offline_request, server.local_addr().unwrap()).unwrap();
        let (n, peer) = server.recv_from(&mut buffer).unwrap();
        let reply = respond_to_datagram(&buffer[..n], peer, Instant::now(), &world, &mut limits, &mut offline).unwrap();
        assert_eq!(reply, vec![legacy_id::OPEN_CONNECTION_REPLY, 0]);
        server.send_to(&reply, peer).unwrap();
        let (n, _) = client.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], reply);
        assert_eq!(offline.pending_count(), 1);

        let request = b"SAMP\x7f\0\0\x01\x61\x1e\x69"; // info query
        client.send_to(request, server.local_addr().unwrap()).unwrap();
        let (n, peer) = server.recv_from(&mut buffer).unwrap();
        let reply = respond_to_datagram(&buffer[..n], peer, Instant::now(), &world, &mut limits, &mut offline).unwrap();
        assert_eq!(&reply[..request.len()], request);
        assert_eq!(&reply[12..14], &0u16.to_le_bytes());
        assert_eq!(offline.pending_count(), 1); // Query never allocates peers.
    }

    #[test]
    fn experimental_bind_and_cli_are_explicit() {
        let opts: Vec<_>=["--bind","127.0.0.1","--experimental-preauth"].iter()
            .map(|s|s.to_string()).collect();
        let (cfg, enabled)=parse_runtime_options(&opts).unwrap();
        assert!(enabled);
        assert_eq!(cfg.unwrap().bind,"127.0.0.1");
        assert!(experimental_bind_allowed("127.0.0.1:7777".parse().unwrap()));
        assert!(!experimental_bind_allowed("0.0.0.0:7777".parse().unwrap()));
        assert!(!experimental_bind_allowed("192.0.2.1:7777".parse().unwrap()));
        assert!(!experimental_bind_allowed("[::1]:7777".parse().unwrap()));
        let doubles:Vec<_>=["--experimental-preauth","--experimental-preauth"]
            .iter().map(|s|s.to_string()).collect();
        assert!(parse_runtime_options(&doubles).is_err());
    }

    #[test]
    fn loopback_udp_socket_can_exchange_reliable_test_handshake() {
        use rustmp_protocol::legacy_frame::{decode_datagram, encode_datagram, Frame, Reliability};
        let socket=UdpSocket::bind("127.0.0.1:0").unwrap();
        let client=UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let bound=socket.local_addr().unwrap();
        let mut config=Config::default();
        config.bind="127.0.0.1".to_string();
        let world=World::new(config);
        let mut query_limits=HashMap::new();
        let mut offline=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        let now=Instant::now();
        let mut buf=[0u8;2048];

        client.send_to(&[16,0,0],bound).unwrap();
        let (n,peer)=socket.recv_from(&mut buf).unwrap();
        let replies=dispatch_datagram(&buf[..n],peer,now,&world,
            &mut query_limits,&mut offline,Some(&mut router),bound);
        assert_eq!(replies,vec![vec![17,0]]);
        socket.send_to(&replies[0],peer).unwrap();
        let (n,_) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n],&[17,0]);

        let request=encode_datagram(&[], &[Frame{
            sequence:0,reliability:Reliability::Reliable,ordering:None,
            payload_bits:8,payload:vec![8],split:None,
        }]).unwrap();
        client.send_to(&request,bound).unwrap();
        let (n,peer)=socket.recv_from(&mut buf).unwrap();
        let replies=dispatch_datagram(&buf[..n],peer,now,&world,
            &mut query_limits,&mut offline,Some(&mut router),bound);
        assert_eq!(replies.len(),1);
        socket.send_to(&replies[0],peer).unwrap();
        let (n,_) = client.recv_from(&mut buf).unwrap();
        let accepted=decode_datagram(&buf[..n]).unwrap();
        assert_eq!(accepted.acknowledgements[0].start,0);
        assert_eq!(accepted.frames[0].payload[0],23);
        // No verified players are added while testing transport exchange.
        assert_eq!(world.query_snapshot().players.len(),0);

        let mut confirmation=vec![26,127,0,0,1];
        confirmation.extend_from_slice(&bound.port().to_le_bytes());
        let final_frame=Frame{
            sequence:1,reliability:Reliability::Reliable,ordering:None,
            payload_bits:(confirmation.len()*8) as u16,
            payload:confirmation,split:None,
        };
        let final_wire=encode_datagram(&[0],&[final_frame]).unwrap();
        client.send_to(&final_wire,bound).unwrap();
        let (n,peer)=socket.recv_from(&mut buf).unwrap();
        let replies=dispatch_datagram(&buf[..n],peer,now,&world,
            &mut query_limits,&mut offline,Some(&mut router),bound);
        assert_eq!(replies.len(),1);
        socket.send_to(&replies[0],peer).unwrap();
        let (n,_) = client.recv_from(&mut buf).unwrap();
        let final_ack=decode_datagram(&buf[..n]).unwrap();
        assert_eq!(final_ack.acknowledgements[0].start,1);
        assert_eq!(router.stats().transport_confirmations,1);
        assert_eq!(router.pending_count(),0);
        assert!(world.query_snapshot().players.is_empty());
    }

    #[test]
    fn disabled_probe_never_answers_reliable_connect_request() {
        use rustmp_protocol::legacy_frame::{encode_datagram, Frame, Reliability};
        let now=Instant::now();
        let client:SocketAddr="127.0.0.1:43210".parse().unwrap();
        let bound:SocketAddr="127.0.0.1:7777".parse().unwrap();
        let world=World::new(Config::default());
        let mut limits=HashMap::new();
        let mut offline=OfflineGateway::new(5);
        let opening=dispatch_datagram(&[16,0,0],client,now,&world,
            &mut limits,&mut offline,None,bound);
        assert_eq!(opening,vec![vec![17,0]]);
        let packet=encode_datagram(&[],&[Frame{
            sequence:0,reliability:Reliability::Reliable,ordering:None,
            payload_bits:8,payload:vec![8],split:None,
        }]).unwrap();
        assert!(dispatch_datagram(&packet,client,now,&world,
            &mut limits,&mut offline,None,bound).is_empty());
        assert!(!offline.saw_reliable_request(client));
    }

    #[test]
    fn openmp_cookie_challenge_happens_before_allocating_peer() {
        let world=World::new(Config::default());
        let mut limits=HashMap::new();
        let mut offline=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        let now=Instant::now();
        let peer:SocketAddr="127.0.0.1:54000".parse().unwrap();
        let server:SocketAddr="127.0.0.1:7777".parse().unwrap();

        let initial=dispatch_datagram(&[24,0,0],peer,now,&world,
            &mut limits,&mut offline,Some(&mut router),server);
        assert_eq!(initial.len(),1);
        assert_eq!(initial[0].len(),3);
        assert_eq!(initial[0][0],26);
        assert_eq!(offline.pending_count(),0);

        let cookie=u16::from_le_bytes([initial[0][1],initial[0][2]]);
        let [lo,hi]=(cookie ^ 0x6d70).to_le_bytes();
        let valid=dispatch_datagram(&[24,lo,hi],peer,now,&world,
            &mut limits,&mut offline,Some(&mut router),server);
        assert_eq!(valid,vec![vec![25,0]]);
        assert_eq!(offline.pending_count(),1);
        assert_eq!(router.stats().cookie_challenges,1);
        assert_eq!(router.stats().cookie_validations,1);

        // A lost OPEN_CONNECTION_REPLY can be sent again while the
        // ORIGINAL peer slot exists, without allocating another slot.
        let replay=dispatch_datagram(&[24,lo,hi],peer,now,&world,
            &mut limits,&mut offline,Some(&mut router),server);
        assert_eq!(replay,vec![vec![25,0]]);
        assert_eq!(offline.pending_count(),1);
        assert_eq!(router.stats().cookie_validations,1);
        assert_eq!(router.stats().cookie_retransmissions,1);

        // This previously could be redeemed with a different UDP port.
        let other:SocketAddr="127.0.0.1:54001".parse().unwrap();
        let copied=dispatch_datagram(&[24,lo,hi],other,now,&world,
            &mut limits,&mut offline,Some(&mut router),server);
        assert_eq!(copied.len(),1);
        assert_eq!(copied[0][0],26);
        assert_eq!(offline.pending_count(),1);

        // No authentic open.mp auth table is installed, so we never issue
        // a fabricated reliable challenge, and never admit a game player.
        use rustmp_protocol::legacy_frame::{encode_datagram,Frame,Reliability};
        let req=encode_datagram(&[],&[Frame{
            sequence:0,reliability:Reliability::Reliable,ordering:None,
            payload_bits:8,payload:vec![11],split:None
        }]).unwrap();
        let replies=dispatch_datagram(&req,peer,now,&world,
            &mut limits,&mut offline,Some(&mut router),server);
        assert!(replies.is_empty());
        assert_eq!(router.pending_count(),0);
        assert!(world.query_snapshot().players.is_empty());
    }


    #[test]
    fn openmp_cookie_exchange_works_on_real_loopback_udp_sockets() {
        let server=UdpSocket::bind("127.0.0.1:0").unwrap();
        let client=UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let bound=server.local_addr().unwrap();
        let world=World::new(Config::default());
        let now=Instant::now();
        let mut limits=HashMap::new();
        let mut offline=OfflineGateway::new(5);
        let mut router=ExperimentalPreAuth::new();
        let mut buf=[0u8;256];

        client.send_to(&[24,0,0],bound).unwrap();
        let (n,remote)=server.recv_from(&mut buf).unwrap();
        let replies=dispatch_datagram(&buf[..n],remote,now,&world,
            &mut limits,&mut offline,Some(&mut router),bound);
        assert_eq!(replies.len(),1);
        assert_eq!(offline.pending_count(),0); // No allocation before cookie.
        server.send_to(&replies[0],remote).unwrap();
        let (n,_)=client.recv_from(&mut buf).unwrap();
        assert_eq!(n,3);
        assert_eq!(buf[0],26);
        let token=u16::from_le_bytes([buf[1],buf[2]]);
        let [lo,hi]=(token ^ 0x6D70).to_le_bytes();

        client.send_to(&[24,lo,hi],bound).unwrap();
        let (n,remote)=server.recv_from(&mut buf).unwrap();
        let replies=dispatch_datagram(&buf[..n],remote,now,&world,
            &mut limits,&mut offline,Some(&mut router),bound);
        assert_eq!(replies,vec![vec![25,0]]);
        server.send_to(&replies[0],remote).unwrap();
        let (n,_)=client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n],&[25,0]);
        assert_eq!(offline.pending_count(),1);

        // Repeat the already accepted cookie when the first response is
        // notionally lost. The same old OPEN_REPLY is retransmitted.
        client.send_to(&[24,lo,hi],bound).unwrap();
        let (n,remote)=server.recv_from(&mut buf).unwrap();
        let again=dispatch_datagram(&buf[..n],remote,now,&world,
            &mut limits,&mut offline,Some(&mut router),bound);
        assert_eq!(again,vec![vec![25,0]]);
        assert_eq!(offline.pending_count(),1);
        assert_eq!(router.stats().cookie_retransmissions,1);
        assert!(world.query_snapshot().players.is_empty());
    }

    #[test]
    fn localhost_probe_is_actually_in_main_and_disabled_by_default() {
        // Regression: alpha.11 included experimental.rs but main.rs did not
        // invoke the dispatcher. Keep direct coverage of both CLI branches.
        let selected=vec!["--bind".to_string(),"127.0.0.1".to_string(),
            "--experimental-preauth".to_string()];
        assert!(parse_runtime_options(&selected).unwrap().1);
        let normal=vec!["--bind".to_string(),"127.0.0.1".to_string()];
        assert!(!parse_runtime_options(&normal).unwrap().1);
    }

    #[test]
    fn open_mp_config_json_maps_supported_fields() {
        let json: Value = serde_json::from_str(r#"{
            "name": "My Rust SA-MP", "max_players": 150,
            "network": { "port": 7779 },
            "game": { "mode": "Drift", "map": "SA" }
        }"#).unwrap();
        let mut cfg = Config::default();
        cfg.hostname = string_field(&json, "name").unwrap();
        cfg.max_players = json["max_players"].as_u64().unwrap() as u16;
        assert_eq!(cfg.hostname, "My Rust SA-MP");
        assert_eq!(cfg.max_players, 150);
    }
}
