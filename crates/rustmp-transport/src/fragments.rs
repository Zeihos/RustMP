//! Per-peer bounded split-message reassembly for legacy SA-MP RakNet.
//!
//! A caller MUST create a separate assembler per authenticated game session,
//! verify packet origin/integrity, and suppress replayed reliable message
//! numbers before inserting fragments. This is a reusable internal component,
//! NOT connected to the public UDP entry point in alpha.6.
//!
//! The upstream legacy fork uses a 16-bit split ID and compressed 32-bit
//! index/count. The wire parser in rustmp-protocol validates the header.
//! This assembler additionally protects against inconsistent fragments,
//! memory exhaustion and indefinitely retained incomplete messages.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use rustmp_protocol::legacy_frame::{
    Frame, Reliability, SplitInfo, MAX_FRAME_PAYLOAD_BYTES, MAX_SPLIT_PARTS,
};

pub const SPLIT_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_SPLIT_GROUPS: usize = 16;
pub const MAX_GROUP_BYTES: usize = 64 * 1024;
pub const MAX_BUFFERED_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitError {
    NotSplit,
    InvalidHeader,
    InvalidPayload,
    ConflictingMetadata,
    ConflictingDuplicate,
    TooManyGroups,
    MemoryLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassembledMessage {
    pub first_sequence: u16,
    pub reliability: Reliability,
    pub ordering: Option<(u8, u16)>,
    pub payload_bits: u32,
    pub payload: Vec<u8>,
}

struct SplitGroup {
    created: Instant,
    reliability: Reliability,
    ordering: Option<(u8, u16)>,
    chunks: Vec<Option<Frame>>,
    received: usize,
    bytes: usize,
}

#[derive(Default)]
pub struct SplitAssembler {
    groups: HashMap<u16, SplitGroup>,
    buffered_bytes: usize,
}

impl SplitAssembler {
    pub fn new() -> Self { Self::default() }
    pub fn pending_groups(&self) -> usize { self.groups.len() }
    pub fn buffered_bytes(&self) -> usize { self.buffered_bytes }

    /// Drop old incomplete groups. Lifetime is measured from creation,
    /// so repeated fragments cannot extend a half-open group's lifetime.
    pub fn cleanup(&mut self, now: Instant) -> usize {
        let mut removed = 0usize;
        self.groups.retain(|_, group| {
            if now.saturating_duration_since(group.created) >= SPLIT_TIMEOUT {
                self.buffered_bytes -= group.bytes;
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Returns the complete message exactly once when the last missing
    /// fragment arrives. A duplicated identical fragment is a no-op.
    pub fn insert(
        &mut self,
        frame: Frame,
        now: Instant,
    ) -> Result<Option<ReassembledMessage>, SplitError> {
        let split = frame.split.ok_or(SplitError::NotSplit)?;
        validate_fragment(&frame, split)?;
        self.cleanup(now);

        if !self.groups.contains_key(&split.id) {
            if self.groups.len() >= MAX_SPLIT_GROUPS {
                return Err(SplitError::TooManyGroups);
            }
            self.groups.insert(split.id, SplitGroup {
                created: now,
                reliability: frame.reliability,
                ordering: frame.ordering,
                chunks: vec![None; split.count as usize],
                received: 0,
                bytes: 0,
            });
        }

        let completed;
        {
            let group = self.groups.get_mut(&split.id).expect("group initialized");
            if group.chunks.len() != split.count as usize
                || group.reliability != frame.reliability
                || group.ordering != frame.ordering
            {
                return Err(SplitError::ConflictingMetadata);
            }

            let idx = split.index as usize;
            if let Some(existing) = &group.chunks[idx] {
                if existing == &frame { return Ok(None); }
                return Err(SplitError::ConflictingDuplicate);
            }

            let incoming = frame.payload.len();
            if group.bytes + incoming > MAX_GROUP_BYTES
                || self.buffered_bytes + incoming > MAX_BUFFERED_BYTES
            {
                return Err(SplitError::MemoryLimit);
            }
            group.bytes += incoming;
            group.received += 1;
            group.chunks[idx] = Some(frame);
            self.buffered_bytes += incoming;
            completed = group.received == group.chunks.len();
        }

        if !completed { return Ok(None); }
        let group = self.groups.remove(&split.id).expect("complete group present");
        self.buffered_bytes -= group.bytes;
        let mut payload = Vec::with_capacity(group.bytes);
        let mut payload_bits = 0u32;
        let mut first_sequence = 0u16;
        for (index, chunk) in group.chunks.into_iter().enumerate() {
            let chunk = chunk.expect("all fragments present");
            if index == 0 { first_sequence = chunk.sequence; }
            payload_bits += u32::from(chunk.payload_bits);
            payload.extend_from_slice(&chunk.payload);
        }
        Ok(Some(ReassembledMessage {
            first_sequence,
            reliability: group.reliability,
            ordering: group.ordering,
            payload_bits,
            payload,
        }))
    }
}

fn validate_fragment(frame: &Frame, split: SplitInfo) -> Result<(), SplitError> {
    if split.count < 2 || split.count > MAX_SPLIT_PARTS || split.index >= split.count {
        return Err(SplitError::InvalidHeader);
    }
    let bits = usize::from(frame.payload_bits);
    if bits == 0 || frame.payload.len() != bits.div_ceil(8)
        || frame.payload.len() > MAX_FRAME_PAYLOAD_BYTES
        || (split.index + 1 != split.count && bits % 8 != 0)
    {
        return Err(SplitError::InvalidPayload);
    }
    if frame.reliability.needs_ordering() {
        if !frame.ordering.is_some_and(|(channel, _)| channel < 32) {
            return Err(SplitError::InvalidHeader);
        }
    } else if frame.ordering.is_some() {
        return Err(SplitError::InvalidHeader);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmp_protocol::legacy_frame::{decode_datagram, encode_datagram};

    fn fragment(id: u16, index: u32, count: u32, bytes: &[u8]) -> Frame {
        Frame {
            sequence: 100 + index as u16,
            reliability: Reliability::ReliableOrdered,
            ordering: Some((1, 42)),
            payload_bits: (bytes.len() * 8) as u16,
            payload: bytes.to_vec(),
            split: Some(SplitInfo { id, index, count }),
        }
    }

    #[test]
    fn out_of_order_chunks_reassemble_and_free_buffers() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        assert_eq!(a.insert(fragment(7, 2, 3, b"cc"), now), Ok(None));
        assert_eq!(a.insert(fragment(7, 0, 3, b"aa"), now), Ok(None));
        let complete = a.insert(fragment(7, 1, 3, b"bb"), now).unwrap().unwrap();
        assert_eq!(complete.first_sequence, 100);
        assert_eq!(complete.payload, b"aabbcc");
        assert_eq!(complete.payload_bits, 48);
        assert_eq!(complete.ordering, Some((1, 42)));
        assert_eq!(a.buffered_bytes(), 0);
        assert_eq!(a.pending_groups(), 0);
    }

    #[test]
    fn duplicate_identical_fragment_does_not_consume_memory() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        let f = fragment(7, 0, 2, b"hi");
        a.insert(f.clone(), now).unwrap();
        assert_eq!(a.insert(f.clone(), now), Ok(None));
        assert_eq!(a.buffered_bytes(), 2);
        let mut modified = f;
        modified.payload = b"no".to_vec();
        assert_eq!(a.insert(modified, now), Err(SplitError::ConflictingDuplicate));
        assert_eq!(a.buffered_bytes(), 2);
    }

    #[test]
    fn conflicting_metadata_rejected_without_corruption() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        a.insert(fragment(5, 0, 2, b"one"), now).unwrap();
        assert_eq!(a.insert(fragment(5, 1, 3, b"two"), now), Err(SplitError::ConflictingMetadata));
        let mut modified = fragment(5, 1, 2, b"two");
        modified.ordering = Some((2, 42));
        assert_eq!(a.insert(modified, now), Err(SplitError::ConflictingMetadata));
        let done = a.insert(fragment(5, 1, 2, b"two"), now).unwrap().unwrap();
        assert_eq!(done.payload, b"onetwo");
    }

    #[test]
    fn stale_groups_are_evicted_even_under_retransmissions() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        let f = fragment(1, 0, 2, b"abc");
        a.insert(f.clone(), now).unwrap();
        a.insert(f, now + SPLIT_TIMEOUT / 2).unwrap();
        assert_eq!(a.cleanup(now + SPLIT_TIMEOUT), 1);
        assert_eq!(a.pending_groups(), 0);
        assert_eq!(a.buffered_bytes(), 0);
    }

    #[test]
    fn split_id_isolation_and_group_limit() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        for id in 0..MAX_SPLIT_GROUPS as u16 {
            a.insert(fragment(id, 0, 2, b"x"), now).unwrap();
        }
        assert_eq!(a.insert(fragment(99, 0, 2, b"x"), now), Err(SplitError::TooManyGroups));
        assert_eq!(a.pending_groups(), MAX_SPLIT_GROUPS);
        let complete = a.insert(fragment(3, 1, 2, b"y"), now).unwrap().unwrap();
        assert_eq!(complete.payload, b"xy");
        assert_eq!(a.insert(fragment(99, 0, 2, b"x"), now), Ok(None));
    }

    #[test]
    fn group_byte_limit_rejects_big_messages_without_leaks() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        let block = vec![9; MAX_FRAME_PAYLOAD_BYTES];
        let mut rejected = false;
        for index in 0..MAX_SPLIT_PARTS {
            let result = a.insert(fragment(1, index, MAX_SPLIT_PARTS, &block), now);
            if result == Err(SplitError::MemoryLimit) {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert!(a.buffered_bytes() <= MAX_GROUP_BYTES);
        assert_eq!(a.pending_groups(), 1);
    }

    #[test]
    fn last_partial_byte_remains_significant_only_to_its_bit_length() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        let mut end = fragment(4, 1, 2, &[0xa0]);
        end.payload_bits = 3;
        assert_eq!(a.insert(end, now), Ok(None));
        let msg = a.insert(fragment(4, 0, 2, &[0xff]), now).unwrap().unwrap();
        assert_eq!(msg.payload, vec![0xff, 0xa0]);
        assert_eq!(msg.payload_bits, 11);
    }

    #[test]
    fn end_to_end_codec_to_reassembly() {
        let now = Instant::now();
        let frames = vec![
            fragment(40, 2, 3, b"C"),
            fragment(40, 0, 3, b"A"),
            fragment(40, 1, 3, b"B"),
        ];
        let mut a = SplitAssembler::new();
        let mut complete = Vec::new();
        for frame in frames {
            let packet = encode_datagram(&[], &[frame]).unwrap();
            let parsed = decode_datagram(&packet).unwrap();
            for fragment in parsed.frames {
                if let Some(message) = a.insert(fragment, now).unwrap() {
                    complete.push(message);
                }
            }
        }
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].payload, b"ABC");
    }

    #[test]
    fn rejects_invalid_fragments_before_state_is_allocated() {
        let now = Instant::now();
        let mut a = SplitAssembler::new();
        let mut f = fragment(1, 0, 1, b"x");
        assert_eq!(a.insert(f.clone(), now), Err(SplitError::InvalidHeader));
        f.split = None;
        assert_eq!(a.insert(f, now), Err(SplitError::NotSplit));
        let mut partial = fragment(2, 0, 2, &[0x80]);
        partial.payload_bits = 1;
        assert_eq!(a.insert(partial, now), Err(SplitError::InvalidPayload));
        assert_eq!(a.pending_groups(), 0);
        assert_eq!(a.buffered_bytes(), 0);
    }
}
