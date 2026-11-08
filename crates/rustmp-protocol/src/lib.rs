//! Protocol utilities for the Rust open.mp rewrite.
//! The SA-MP query protocol is implemented; the RakNet game protocol is NOT implemented.

pub mod bitstream;
pub mod query;

pub mod ack;

/// Bounded codec for the non-split legacy RakNet datagram wire format.
pub mod legacy_frame;
