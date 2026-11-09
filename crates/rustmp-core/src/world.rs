use std::collections::HashSet;
use std::time::Instant;

use rustmp_protocol::query::{QueryPlayer, QuerySnapshot, TextEncoding};

use crate::pool::Pool;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlayerState {
    Connected,
    Spawned,
    Spectating,
}

#[derive(Clone, Debug)]
pub struct Player {
    pub id: u16,
    pub nickname: String,
    pub state: PlayerState,
    pub position: Vec3,
    pub virtual_world: i32,
    pub interior: u8,
    pub health: f32,
    pub armour: f32,
    pub score: i32,
    pub ping_ms: u32,
}

#[derive(Clone, Debug)]
pub struct Vehicle {
    pub id: u16,
    pub model_id: u16,
    pub position: Vec3,
    pub angle: f32,
    pub health: f32,
    pub virtual_world: i32,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    pub port: u16,
    pub max_players: u16,
    pub hostname: String,
    pub gamemode: String,
    pub language: String,
    pub map: String,
    pub website: String,
    pub password: Option<String>,
    pub encoding: TextEncoding,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: 7777,
            max_players: 50,
            hostname: "RUSTMP development server".into(),
            gamemode: "Rust Core (network alpha)".into(),
            language: "Russian".into(),
            map: "San Andreas".into(),
            website: "open.mp".into(),
            password: None,
            encoding: TextEncoding::Windows1251,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum WorldError {
    InvalidPlayerName,
    DuplicatePlayerName,
    PlayerPoolFull,
    PlayerNotFound,
    InvalidPosition,
    InvalidVehicleModel,
    VehiclePoolFull,
}

#[derive(Debug)]
pub struct World {
    pub config: Config,
    pub players: Pool<Player>,
    pub vehicles: Pool<Vehicle>,
    started_at: Instant,
    tick_count: u64,
}

impl World {
    pub fn new(config: Config) -> Self {
        assert!(config.max_players > 0, "max_players must be nonzero");
        Self {
            players: Pool::with_capacity(config.max_players as usize),
            vehicles: Pool::with_capacity(2000),
            config,
            started_at: Instant::now(),
            tick_count: 0,
        }
    }

    pub fn add_player(&mut self, nickname: &str) -> Result<u16, WorldError> {
        // Classic SA-MP nicknames are restricted to a small ASCII alphabet.
        if !(3..=24).contains(&nickname.len())
            || !nickname.bytes().all(|b| b.is_ascii_alphanumeric() || b"_[]().$@=-".contains(&b)) {
            return Err(WorldError::InvalidPlayerName);
        }
        if self.players.iter().any(|(_, p)| p.nickname.eq_ignore_ascii_case(nickname)) {
            return Err(WorldError::DuplicatePlayerName);
        }
        let player = Player {
            id: 0,
            nickname: nickname.to_owned(),
            state: PlayerState::Connected,
            position: Vec3::default(),
            virtual_world: 0,
            interior: 0,
            health: 100.0,
            armour: 0.0,
            score: 0,
            ping_ms: 0,
        };
        let id = self.players.insert(player).map_err(|_| WorldError::PlayerPoolFull)?;
        if let Some(player) = self.players.get_mut(id) { player.id = id; }
        Ok(id)
    }

    pub fn remove_player(&mut self, id: u16) -> Result<Player, WorldError> {
        self.players.remove(id).ok_or(WorldError::PlayerNotFound)
    }

    pub fn set_player_position(&mut self, id: u16, position: Vec3) -> Result<(), WorldError> {
        if !position.is_finite() { return Err(WorldError::InvalidPosition); }
        let player = self.players.get_mut(id).ok_or(WorldError::PlayerNotFound)?;
        player.position = position;
        Ok(())
    }

    pub fn spawn_vehicle(&mut self, model_id: u16, position: Vec3, angle: f32) -> Result<u16, WorldError> {
        if !(400..=611).contains(&model_id) { return Err(WorldError::InvalidVehicleModel); }
        if !position.is_finite() || !angle.is_finite() { return Err(WorldError::InvalidPosition); }
        let vehicle = Vehicle {
            id: 0,
            model_id,
            position,
            angle,
            health: 1000.0,
            virtual_world: 0,
        };
        let id = self.vehicles.insert(vehicle).map_err(|_| WorldError::VehiclePoolFull)?;
        if let Some(vehicle) = self.vehicles.get_mut(id) { vehicle.id = id; }
        Ok(id)
    }

    pub fn tick(&mut self) { self.tick_count = self.tick_count.saturating_add(1); }
    pub fn ticks(&self) -> u64 { self.tick_count }
    pub fn uptime_seconds(&self) -> u64 { self.started_at.elapsed().as_secs() }

    pub fn query_snapshot(&self) -> QuerySnapshot {
        let players: Vec<_> = self.players.iter().map(|(id, p)| QueryPlayer {
            id,
            name: p.nickname.clone(),
            score: p.score,
            ping: p.ping_ms,
        }).collect();
        let mut rules: Vec<(String, String)> = vec![
            ("version".into(), "RUSTMP-0.2.0-alpha.15".into()),
            ("mapname".into(), self.config.map.clone()),
            ("weburl".into(), self.config.website.clone()),
            ("worldtime".into(), "12:00".into()),
        ];
        // Retain deterministic distinct rule keys if the configuration evolves.
        let mut seen = HashSet::new();
        rules.retain(|(key, _)| seen.insert(key.clone()));
        QuerySnapshot {
            hostname: self.config.hostname.clone(),
            gamemode: self.config.gamemode.clone(),
            language: self.config.language.clone(),
            passworded: self.config.password.as_ref().is_some_and(|p| !p.is_empty()),
            max_players: self.config.max_players,
            players,
            rules,
            encoding: self.config.encoding,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn player_creation_and_snapshot() {
        let mut world = World::new(Config { max_players: 2, ..Config::default() });
        let id = world.add_player("Player_1").unwrap();
        assert_eq!(id, 0);
        assert_eq!(world.add_player("player_1"), Err(WorldError::DuplicatePlayerName));
        assert_eq!(world.add_player("no spaces"), Err(WorldError::InvalidPlayerName));
        assert!(world.set_player_position(id, Vec3 { x: 1., y: 2., z: 3. }).is_ok());
        assert_eq!(world.query_snapshot().players[0].name, "Player_1");
        assert!(world.remove_player(id).is_ok());
        assert_eq!(world.query_snapshot().players.len(), 0);
    }

    #[test]
    fn pool_limits_and_invalid_positions() {
        let mut world = World::new(Config { max_players: 1, ..Config::default() });
        let id = world.add_player("Tester").unwrap();
        assert_eq!(world.add_player("Other"), Err(WorldError::PlayerPoolFull));
        assert_eq!(world.set_player_position(id, Vec3 { x: f32::NAN, y: 0., z: 0. }), Err(WorldError::InvalidPosition));
        assert_eq!(world.spawn_vehicle(1, Vec3::default(), 0.), Err(WorldError::InvalidVehicleModel));
        let car = world.spawn_vehicle(411, Vec3::default(), 90.).unwrap();
        assert_eq!(world.vehicles.get(car).unwrap().model_id, 411);
    }
}
