//! Small safe bit stream primitives for the next networking stage.
//! This generic codec has not yet been validated against the SA-MP RakNet fork.

#[derive(Clone, Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, offset: 0 } }
    pub fn remaining_bits(&self) -> usize { self.data.len() * 8 - self.offset }
    pub fn position_bits(&self) -> usize { self.offset }

    /// Reads up to 64 bits, most-significant-bit first.
    /// Returns None without advancing on truncation.
    pub fn read_bits(&mut self, count: u8) -> Option<u64> {
        if count > 64 || (count as usize) > self.remaining_bits() { return None; }
        let mut value = 0u64;
        for _ in 0..count {
            let byte = self.data[self.offset / 8];
            let shift = 7 - (self.offset % 8);
            value = (value << 1) | ((byte >> shift) & 1) as u64;
            self.offset += 1;
        }
        Some(value)
    }

    pub fn read_u8(&mut self) -> Option<u8> { self.read_bits(8).map(|value| value as u8) }

    pub fn read_u16_le(&mut self) -> Option<u16> {
        if self.remaining_bits() < 16 { return None; }
        let low = self.read_u8()?;
        let high = self.read_u8()?;
        Some(u16::from_le_bytes([low, high]))
    }

    pub fn skip(&mut self, count: usize) -> bool {
        if count > self.remaining_bits() { return false; }
        self.offset += count;
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct BitWriter {
    data: Vec<u8>,
    bit_len: usize,
}

impl BitWriter {
    pub fn new() -> Self { Self::default() }
    pub fn len_bits(&self) -> usize { self.bit_len }
    pub fn is_empty(&self) -> bool { self.bit_len == 0 }

    /// Writes up to 64 bits, most-significant-bit first.
    pub fn write_bits(&mut self, value: u64, count: u8) -> Result<(), &'static str> {
        if count > 64 { return Err("count must be at most 64 bits"); }
        if self.bit_len.checked_add(count as usize).is_none() { return Err("bit count overflow"); }
        for index in (0..count).rev() {
            if self.bit_len % 8 == 0 { self.data.push(0); }
            let bit = ((value >> index) & 1) as u8;
            let byte_index = self.bit_len / 8;
            let shift = 7 - (self.bit_len % 8);
            self.data[byte_index] |= bit << shift;
            self.bit_len += 1;
        }
        Ok(())
    }

    pub fn write_u8(&mut self, value: u8) { self.write_bits(value as u64, 8).expect("8 bits fit"); }
    pub fn write_u16_le(&mut self, value: u16) {
        for byte in value.to_le_bytes() { self.write_u8(byte); }
    }
    pub fn into_bytes(self) -> Vec<u8> { self.data }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_byte_roundtrip() {
        let mut writer = BitWriter::new();
        writer.write_bits(0b101, 3).unwrap();
        writer.write_u8(0xA5);
        writer.write_u16_le(0x1234);
        assert_eq!(writer.len_bits(), 27);
        let bytes = writer.into_bytes();
        let mut reader = BitReader::new(&bytes);
        assert_eq!(reader.read_bits(3), Some(0b101));
        assert_eq!(reader.read_u8(), Some(0xA5));
        assert_eq!(reader.read_u16_le(), Some(0x1234));
        assert_eq!(reader.remaining_bits(), 5); // padded last byte
    }

    #[test]
    fn invalid_reads_do_not_advance() {
        let mut reader = BitReader::new(&[0xFF]);
        assert_eq!(reader.read_bits(9), None);
        assert_eq!(reader.position_bits(), 0);
        assert_eq!(reader.read_u8(), Some(255));
        assert_eq!(reader.read_u8(), None);
    }
}
