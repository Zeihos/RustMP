//! Independent Rust codec for the non-split *legacy* SA-MP RakNet datagram.
//!
//! Sources for wire-field order: openmultiplayer/RakNet:
//! Source/ReliabilityLayer.cpp and Include/raknet/PacketPriority.h.
//!
//! This is a bounded codec, not a connected networking layer. It does not
//! authenticate peers, decrypt packets, negotiate sessions, send RPCs or
//! rebuild split packets. Packets must not be routed to gameplay yet.

use crate::ack::{decode_ack_prefix, encode_ack_prefix, AckError, AckRange};
use crate::bitstream::{BitReader, BitWriter};

pub const MAX_DATAGRAM_BYTES: usize = 1400;
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 1200;
pub const MAX_FRAMES_PER_DATAGRAM: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reliability {
    Unreliable = 6,
    UnreliableSequenced = 7,
    Reliable = 8,
    ReliableOrdered = 9,
    ReliableSequenced = 10,
}

impl Reliability {
    fn from_wire(value: u8) -> Option<Self> {
        match value {
            6 => Some(Self::Unreliable),
            7 => Some(Self::UnreliableSequenced),
            8 => Some(Self::Reliable),
            9 => Some(Self::ReliableOrdered),
            10 => Some(Self::ReliableSequenced),
            _ => None,
        }
    }

    pub fn needs_ordering(self) -> bool {
        matches!(self, Self::UnreliableSequenced | Self::ReliableOrdered | Self::ReliableSequenced)
    }

    pub fn is_reliable(self) -> bool {
        matches!(self, Self::Reliable | Self::ReliableOrdered | Self::ReliableSequenced)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub sequence: u16,
    pub reliability: Reliability,
    /// Some(channel, 16-bit ordering index), channel 0..31.
    pub ordering: Option<(u8, u16)>,
    /// Exact significant payload length. Last byte can contain padding bits.
    pub payload_bits: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub acknowledgements: Vec<AckRange>,
    pub frames: Vec<Frame>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Empty,
    TooLarge,
    TooManyFrames,
    Truncated,
    InvalidReliability,
    InvalidOrdering,
    InvalidLength,
    UnsupportedSplit,
    Ack(AckError),
}

impl From<AckError> for FrameError {
    fn from(error: AckError) -> Self { Self::Ack(error) }
}

fn append_bitstream(writer: &mut BitWriter, bytes: &[u8], bit_len: usize) {
    for bit in 0..bit_len {
        let value = (bytes[bit / 8] >> (7 - (bit % 8))) & 1;
        writer.write_bits(u64::from(value), 1).expect("bit fits");
    }
}

fn align_write(writer: &mut BitWriter) {
    while writer.len_bits() % 8 != 0 {
        writer.write_bits(0, 1).expect("bit fits");
    }
}

fn align_read(reader: &mut BitReader<'_>) -> Result<(), FrameError> {
    let extra = (8 - reader.position_bits() % 8) % 8;
    if reader.skip(extra) { Ok(()) } else { Err(FrameError::Truncated) }
}

fn validate_frame(frame: &Frame) -> Result<(), FrameError> {
    if frame.reliability.needs_ordering() {
        match frame.ordering {
            Some((channel, _)) if channel < 32 => {}
            _ => return Err(FrameError::InvalidOrdering),
        }
    } else if frame.ordering.is_some() {
        return Err(FrameError::InvalidOrdering);
    }
    let length = frame.payload_bits as usize;
    if length == 0 { return Err(FrameError::InvalidLength); }
    if length.div_ceil(8) != frame.payload.len() {
        return Err(FrameError::InvalidLength);
    }
    if frame.payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(FrameError::TooLarge);
    }
    Ok(())
}

/// Encode ACK prefix and up to 32 non-split frames; validate before returning.
/// This serializer emits exactly one has-ack bit before any frames.
pub fn encode_datagram(ack_numbers: &[u16], frames: &[Frame]) -> Result<Vec<u8>, FrameError> {
    if frames.len() > MAX_FRAMES_PER_DATAGRAM {
        return Err(FrameError::TooManyFrames);
    }
    if ack_numbers.is_empty() && frames.is_empty() { return Err(FrameError::Empty); }
    let prefix = encode_ack_prefix(ack_numbers)?;
    let mut writer = BitWriter::new();
    append_bitstream(&mut writer, &prefix.bytes, prefix.bit_len);

    for frame in frames {
        validate_frame(frame)?;
        writer.write_u16_le(frame.sequence);
        writer.write_bits(frame.reliability as u64, 4).expect("four bits fit");
        if let Some((channel, ordering_index)) = frame.ordering {
            writer.write_bits(u64::from(channel), 5).expect("five bits fit");
            writer.write_u16_le(ordering_index);
        }
        writer.write_bits(0, 1).expect("split bit fits");
        // Compression is the legacy unsigned RakNet bitstream scheme.
        // Also used by the ACK RangeList prefix.
        crate::ack::write_compressed_u16(&mut writer, frame.payload_bits);
        align_write(&mut writer);
        for &byte in &frame.payload { writer.write_u8(byte); }
        if writer.len_bits().div_ceil(8) > MAX_DATAGRAM_BYTES {
            return Err(FrameError::TooLarge);
        }
    }
    let result = writer.into_bytes();
    if result.len() > MAX_DATAGRAM_BYTES { return Err(FrameError::TooLarge); }
    Ok(result)
}

/// Read the legacy ACK prefix then zero or more non-split reliable frames.
/// A final tail shorter than 16 bits is treated as datagram padding, following
/// legacy RakNet's minimum packet-number check. Its size is at most 15 bits.
pub fn decode_datagram(bytes: &[u8]) -> Result<Datagram, FrameError> {
    if bytes.is_empty() { return Err(FrameError::Empty); }
    if bytes.len() > MAX_DATAGRAM_BYTES { return Err(FrameError::TooLarge); }
    let prefix = decode_ack_prefix(bytes)?;
    let mut reader = BitReader::new(bytes);
    if !reader.skip(prefix.bits_consumed) { return Err(FrameError::Truncated); }
    let mut frames = Vec::new();
    while reader.remaining_bits() >= 16 {
        if frames.len() >= MAX_FRAMES_PER_DATAGRAM {
            return Err(FrameError::TooManyFrames);
        }
        let sequence = reader.read_u16_le().ok_or(FrameError::Truncated)?;
        let kind = reader.read_bits(4).ok_or(FrameError::Truncated)? as u8;
        let reliability = Reliability::from_wire(kind)
            .ok_or(FrameError::InvalidReliability)?;
        let ordering = if reliability.needs_ordering() {
            let channel = reader.read_bits(5).ok_or(FrameError::Truncated)? as u8;
            let index = reader.read_u16_le().ok_or(FrameError::Truncated)?;
            Some((channel, index))
        } else { None };
        let is_split = reader.read_bits(1).ok_or(FrameError::Truncated)? != 0;
        // Fragment reassembly and compressed u32 split indexes are a future
        // milestone. Do not consume/interpret split payloads prematurely.
        if is_split { return Err(FrameError::UnsupportedSplit); }
        let payload_bits = crate::ack::read_compressed_u16(&mut reader)?;
        if payload_bits == 0 { return Err(FrameError::InvalidLength); }
        let byte_len = (payload_bits as usize).div_ceil(8);
        if byte_len > MAX_FRAME_PAYLOAD_BYTES { return Err(FrameError::TooLarge); }
        align_read(&mut reader)?;
        if reader.remaining_bits() < byte_len * 8 {
            return Err(FrameError::Truncated);
        }
        let mut payload = Vec::with_capacity(byte_len);
        for _ in 0..byte_len {
            payload.push(reader.read_u8().ok_or(FrameError::Truncated)?);
        }
        frames.push(Frame { sequence, reliability, ordering, payload_bits, payload });
    }
    if frames.is_empty() && !prefix.has_acks { return Err(FrameError::Empty); }
    Ok(Datagram { acknowledgements: prefix.ranges, frames })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u16, rel: Reliability, ordering: Option<(u8,u16)>, body: &[u8]) -> Frame {
        Frame { sequence: seq, reliability: rel, ordering,
            payload_bits: (body.len() * 8) as u16, payload: body.to_vec() }
    }

    #[test]
    fn reliable_frame_round_trip() {
        let frames = vec![frame(42, Reliability::Reliable, None, b"hello")];
        let bytes = encode_datagram(&[], &frames).unwrap();
        let decoded = decode_datagram(&bytes).unwrap();
        assert!(decoded.acknowledgements.is_empty());
        assert_eq!(decoded.frames, frames);
    }

    #[test]
    fn all_legacy_reliability_modes_roundtrip() {
        let kinds = [
            Reliability::Unreliable, Reliability::UnreliableSequenced,
            Reliability::Reliable, Reliability::ReliableOrdered,
            Reliability::ReliableSequenced
        ];
        let frames: Vec<_> = kinds.iter().enumerate().map(|(i, kind)| {
            frame(i as u16, *kind,
                kind.needs_ordering().then_some((i as u8, 300 + i as u16)), &[i as u8, 4])
        }).collect();
        assert_eq!(decode_datagram(&encode_datagram(&[], &frames).unwrap()).unwrap().frames, frames);
    }

    #[test]
    fn ack_and_frames_share_unaligned_bitstream() {
        let frames = vec![
            frame(12, Reliability::ReliableOrdered, Some((31, 2048)), b"ordered"),
            frame(u16::MAX, Reliability::Unreliable, None, b"last"),
        ];
        let encoded = encode_datagram(&[2, 3, 7], &frames).unwrap();
        let decoded = decode_datagram(&encoded).unwrap();
        assert_eq!(decoded.acknowledgements, vec![
            AckRange { start: 2, end: 3 }, AckRange { start: 7, end: 7 }
        ]);
        assert_eq!(decoded.frames, frames);
    }

    #[test]
    fn ack_only_round_trip() {
        let data = encode_datagram(&[1, 2, 300, 400], &[]).unwrap();
        let parsed = decode_datagram(&data).unwrap();
        assert_eq!(parsed.frames.len(), 0);
        assert_eq!(parsed.acknowledgements.len(), 3);
    }

    #[test]
    fn partial_payload_bits_preserved() {
        let f = Frame { sequence: 4, reliability: Reliability::Reliable,
            ordering: None, payload_bits: 11, payload: vec![0xFF, 0xE0] };
        let out = decode_datagram(&encode_datagram(&[], &[f.clone()]).unwrap()).unwrap();
        assert_eq!(out.frames, vec![f]);
    }

    #[test]
    fn rejects_invalid_ordering_and_empty_frames() {
        let wrong = frame(0, Reliability::Reliable, Some((0,0)), b"oops");
        assert_eq!(encode_datagram(&[], &[wrong]), Err(FrameError::InvalidOrdering));
        let wrong = frame(0, Reliability::ReliableOrdered, Some((32,0)), b"oops");
        assert_eq!(encode_datagram(&[], &[wrong]), Err(FrameError::InvalidOrdering));
        let wrong = frame(0, Reliability::Reliable, None, b"");
        assert_eq!(encode_datagram(&[], &[wrong]), Err(FrameError::InvalidLength));
        assert_eq!(encode_datagram(&[], &[]), Err(FrameError::Empty));
    }

    #[test]
    fn bounded_and_truncated() {
        let frames = vec![frame(0, Reliability::Reliable, None, b"small"); MAX_FRAMES_PER_DATAGRAM + 1];
        assert_eq!(encode_datagram(&[], &frames), Err(FrameError::TooManyFrames));
        let bytes = encode_datagram(&[], &[frame(0, Reliability::Reliable, None, b"payload")]).unwrap();
        for len in 1..bytes.len() {
            assert!(decode_datagram(&bytes[..len]).is_err(), "len={len}");
        }
        assert_eq!(decode_datagram(&vec![0u8;MAX_DATAGRAM_BYTES + 1]), Err(FrameError::TooLarge));
    }

    #[test]
    fn invalid_reliability_and_split_not_accepted() {
        let bytes = encode_datagram(&[], &[frame(0, Reliability::Reliable, None, &[0x55])]).unwrap();
        // First bit is has-ACK=0, following message number is 16 bits.
        // Flip the reliability nibble (bits 17..20) to zero.
        let mut bad = bytes.clone();
        for bit in 17..21 { bad[bit / 8] &= !(1 << (7 - bit % 8)); }
        assert_eq!(decode_datagram(&bad), Err(FrameError::InvalidReliability));
        // The split flag follows 16-bit sequence + 4-bit kind.
        let mut split = bytes;
        let bit = 21;
        split[bit / 8] |= 1 << (7 - bit % 8);
        assert_eq!(decode_datagram(&split), Err(FrameError::UnsupportedSplit));
    }

    #[test]
    fn fuzzlike_inputs_do_not_panic() {
        for len in 1..500usize {
            let bogus = vec![0xff; len];
            let _ = decode_datagram(&bogus);
        }
    }

    #[test]
    fn fixed_wire_vector_no_ack_reliable_message() {
        // has-ack=0, message=42 LE, kind=8 (4 bits), no split,
        // compressed payload-bit-length=8, align, one payload byte.
        let packet = frame(42, Reliability::Reliable, None, &[0xab]);
        let bytes = encode_datagram(&[], &[packet.clone()]).unwrap();
        assert_eq!(bytes, vec![0x15, 0x00, 0x43, 0x80, 0xab]);
        assert_eq!(decode_datagram(&bytes).unwrap().frames, vec![packet]);
    }

}
