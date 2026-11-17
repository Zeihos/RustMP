//! Protocol utilities for the Rust open.mp rewrite.
//! The SA-MP query protocol is implemented; the RakNet game protocol is NOT implemented.

pub mod bitstream;
pub mod query;

pub mod ack;

/// Bounded codec for legacy RakNet datagrams and split headers.
pub mod legacy_frame;

/// Privacy-conscious classic PCAP/UDP capture inspector (no payload logging).
pub mod capture;

/// Offline handshake timeline analysis (metadata only).
pub mod handshake_trace;

/// Reliable frame/ACK correlation within a capture (no raw payload).
pub mod reliable_trace;
