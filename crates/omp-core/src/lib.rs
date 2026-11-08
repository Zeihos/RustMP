//! Minimal standalone server core built in safe Rust.
//! This is infrastructure for the port, not a complete SA-MP game server.

pub mod pool;
pub mod world;

pub use pool::Pool;
pub use world::{Config, Player, PlayerState, Vec3, Vehicle, World, WorldError};
