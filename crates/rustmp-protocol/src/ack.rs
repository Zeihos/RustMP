//! Legacy SA-MP RakNet ACK prefix codec. Not a full reliable datagram.
//! Format reviewed against openmultiplayer/RakNet DS_RangeList and BitStream.
//! This independent implementation still needs comparison with client captures.

use std::collections::BTreeSet;
use crate::bitstream::{BitReader, BitWriter};

pub const MAX_ACK_NUMBERS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckError { Truncated, TooManyNumbers, InvalidRange, UnsortedRanges }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange { pub start: u16, pub end: u16 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAcks {
    pub has_acks: bool,
    pub ranges: Vec<AckRange>,
    pub bits_consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAcks {
    pub bytes: Vec<u8>,
    pub bit_len: usize,
}

/// Unsigned RakNet compressed u16: one bit per zero high byte,
/// then a one-bit nibble flag and either four or eight low bits.
/// When the high byte is nonzero, both native little-endian bytes follow.
pub(crate) fn write_compressed_u16(w: &mut BitWriter, value: u16) {
    let [low, high] = value.to_le_bytes();
    if high == 0 {
        w.write_bits(1, 1).expect("one bit fits");
        if low < 16 {
            w.write_bits(1, 1).expect("one bit fits");
            w.write_bits(u64::from(low), 4).expect("four bits fit");
        } else {
            w.write_bits(0, 1).expect("one bit fits");
            w.write_u8(low);
        }
    } else {
        w.write_bits(0, 1).expect("one bit fits");
        w.write_u16_le(value);
    }
}

pub(crate) fn read_compressed_u16(r: &mut BitReader<'_>) -> Result<u16, AckError> {
    let zero_high = r.read_bits(1).ok_or(AckError::Truncated)? == 1;
    if !zero_high { return r.read_u16_le().ok_or(AckError::Truncated); }
    let nibble = r.read_bits(1).ok_or(AckError::Truncated)? == 1;
    if nibble {
        Ok(r.read_bits(4).ok_or(AckError::Truncated)? as u16)
    } else {
        Ok(r.read_u8().ok_or(AckError::Truncated)? as u16)
    }
}

/// Prefix begins with has-ACK bit. Range count is a compressed u16.
/// Each sorted range encodes: one equal-boundary flag, LE u16 start,
/// and LE u16 end when not equal. Last byte may contain padding.
pub fn encode_ack_prefix(numbers: &[u16]) -> Result<EncodedAcks, AckError> {
    if numbers.len() > MAX_ACK_NUMBERS { return Err(AckError::TooManyNumbers); }
    let unique: BTreeSet<u16> = numbers.iter().copied().collect();
    let mut writer = BitWriter::new();
    if unique.is_empty() {
        writer.write_bits(0, 1).expect("bit fits");
    } else {
        writer.write_bits(1, 1).expect("bit fits");
        let mut ranges: Vec<AckRange> = Vec::new();
        for number in unique {
            match ranges.last_mut() {
                Some(range) if range.end.checked_add(1) == Some(number) => range.end = number,
                _ => ranges.push(AckRange { start: number, end: number }),
            }
        }
        write_compressed_u16(&mut writer, ranges.len() as u16);
        for range in ranges {
            writer.write_bits(u64::from(range.start == range.end), 1).expect("bit fits");
            writer.write_u16_le(range.start);
            if range.start != range.end { writer.write_u16_le(range.end); }
        }
    }
    let bit_len = writer.len_bits();
    Ok(EncodedAcks { bytes: writer.into_bytes(), bit_len })
}

/// Decode only the ACK prefix; do not consume the following gameplay bits.
/// A hard cap applies to expanded ACK numbers as well as range count.
pub fn decode_ack_prefix(bytes: &[u8]) -> Result<DecodedAcks, AckError> {
    let mut reader = BitReader::new(bytes);
    let has_acks = reader.read_bits(1).ok_or(AckError::Truncated)? != 0;
    if !has_acks {
        return Ok(DecodedAcks { has_acks, ranges: Vec::new(), bits_consumed: 1 });
    }
    let count = read_compressed_u16(&mut reader)? as usize;
    if count > MAX_ACK_NUMBERS { return Err(AckError::TooManyNumbers); }
    let mut ranges: Vec<AckRange> = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let equal = reader.read_bits(1).ok_or(AckError::Truncated)? != 0;
        let start = reader.read_u16_le().ok_or(AckError::Truncated)?;
        let end = if equal { start } else { reader.read_u16_le().ok_or(AckError::Truncated)? };
        if end < start { return Err(AckError::InvalidRange); }
        if ranges.last().is_some_and(|prev| start <= prev.end) {
            return Err(AckError::UnsortedRanges);
        }
        total += usize::from(end - start) + 1;
        if total > MAX_ACK_NUMBERS { return Err(AckError::TooManyNumbers); }
        ranges.push(AckRange { start, end });
    }
    Ok(DecodedAcks { has_acks, ranges, bits_consumed: reader.position_bits() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bit_vectors() {
        assert_eq!(encode_ack_prefix(&[]).unwrap(), EncodedAcks { bytes: vec![0], bit_len: 1 });
        let one = encode_ack_prefix(&[5]).unwrap();
        assert_eq!(one, EncodedAcks { bytes: vec![0xe3, 5, 0], bit_len: 24 });
        assert_eq!(decode_ack_prefix(&one.bytes).unwrap(),
            DecodedAcks { has_acks: true, ranges: vec![AckRange {start:5,end:5}], bits_consumed:24 });
        let range = encode_ack_prefix(&[4, 2, 3, 4]).unwrap();
        assert_eq!(range, EncodedAcks { bytes: vec![0xe2, 2, 0, 4, 0], bit_len: 40 });
    }

    #[test]
    fn round_trip_compressed_counts_and_wrap() {
        for numbers in [
            vec![1,3,5],
            (0u16..32).step_by(2).collect(),
            (0u16..64).step_by(2).collect(),
            vec![u16::MAX - 1, u16::MAX, 0, 1, 1],
            vec![127, 129, 255, 256]
        ] {
            let encoded = encode_ack_prefix(&numbers).unwrap();
            let decoded = decode_ack_prefix(&encoded.bytes).unwrap();
            let expected: BTreeSet<_> = numbers.iter().copied().collect();
            let actual: BTreeSet<_> = decoded.ranges.iter()
                .flat_map(|r| r.start..=r.end).collect();
            assert_eq!(actual, expected);
            assert_eq!(decoded.bits_consumed, encoded.bit_len);
        }
    }

    #[test]
    fn trailing_data_not_swallowed() {
        let encoded = encode_ack_prefix(&[1,2,3]).unwrap();
        let mut combined = encoded.bytes.clone();
        combined.extend_from_slice(&[0xAA,0x55]);
        assert_eq!(decode_ack_prefix(&combined).unwrap().bits_consumed, encoded.bit_len);
    }

    #[test]
    fn truncated_and_bogus_data_rejected() {
        assert_eq!(decode_ack_prefix(&[]), Err(AckError::Truncated));
        let bytes = encode_ack_prefix(&[13, 18, 56, 90]).unwrap().bytes;
        for len in 0..bytes.len() {
            assert_eq!(decode_ack_prefix(&bytes[..len]), Err(AckError::Truncated));
        }
        let mut writer = BitWriter::new();
        writer.write_bits(1,1).unwrap();
        write_compressed_u16(&mut writer, 1);
        writer.write_bits(0,1).unwrap();
        writer.write_u16_le(6);
        writer.write_u16_le(5);
        assert_eq!(decode_ack_prefix(&writer.into_bytes()), Err(AckError::InvalidRange));
    }

    #[test]
    fn bounded_expansion_and_invalid_order() {
        assert_eq!(encode_ack_prefix(&vec![1; MAX_ACK_NUMBERS+1]),
            Err(AckError::TooManyNumbers));
        let mut writer = BitWriter::new();
        writer.write_bits(1,1).unwrap();
        write_compressed_u16(&mut writer, MAX_ACK_NUMBERS as u16 + 1);
        assert_eq!(decode_ack_prefix(&writer.into_bytes()), Err(AckError::TooManyNumbers));
        let mut writer = BitWriter::new();
        writer.write_bits(1,1).unwrap();
        write_compressed_u16(&mut writer, 2);
        for _ in 0..2 {
            writer.write_bits(1,1).unwrap();
            writer.write_u16_le(5);
        }
        assert_eq!(decode_ack_prefix(&writer.into_bytes()), Err(AckError::UnsortedRanges));
        let mut writer = BitWriter::new();
        writer.write_bits(1,1).unwrap();
        write_compressed_u16(&mut writer, 1);
        writer.write_bits(0,1).unwrap();
        writer.write_u16_le(0);
        writer.write_u16_le(512);
        assert_eq!(decode_ack_prefix(&writer.into_bytes()), Err(AckError::TooManyNumbers));
    }

    #[test]
    fn arbitrary_lengths_never_crash() {
        for len in 0..1200 {
            let bogus = vec![0xff;len];
            let _ = decode_ack_prefix(&bogus);
        }
    }
}
