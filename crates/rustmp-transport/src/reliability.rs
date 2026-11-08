//! Bounded reliability bookkeeping for legacy SA-MP/open.mp RakNet.
//! This module does NOT encode wire ACKs/frames or accept game connections.
//! Wire-format parsing must be verified with actual legacy client traffic.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub const MAX_IN_FLIGHT: usize = 512;
pub const MAX_MESSAGE_BYTES: usize = 1200;
pub const MAX_ACK_BATCH: usize = 512;
pub const MAX_ACK_RANGE: usize = 1024;
pub const RECEIVE_WINDOW: usize = 512;
pub const ORDER_CHANNELS: usize = 32;
pub const MAX_ORDERED_PENDING: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliabilityError {
    EmptyMessage,
    OversizedMessage,
    QueueFull,
    SequenceInUse,
    InvalidAckRange,
    InvalidChannel,
    Duplicate,
    Old,
    TooFarAhead,
}

#[derive(Debug, Clone)]
struct Outstanding {
    bytes: Vec<u8>,
    last_sent: Instant,
    retries: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resend {
    pub sequence: u16,
    pub bytes: Vec<u8>,
    pub attempt: u8,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetryBatch {
    pub resend: Vec<Resend>,
    pub abandoned: Vec<u16>,
}

/// Per-peer reliable send bookkeeping. A separate verified wire codec is
/// responsible for serializing packets and decoding acknowledgements.
pub struct OutboundReliability {
    next_sequence: u16,
    outstanding: BTreeMap<u16, Outstanding>,
    retry_after: Duration,
    max_retries: u8,
}

impl OutboundReliability {
    pub fn new(retry_after: Duration, max_retries: u8) -> Self {
        Self {
            next_sequence: 0,
            outstanding: BTreeMap::new(),
            retry_after: retry_after.max(Duration::from_millis(1)),
            max_retries,
        }
    }

    pub fn pending_count(&self) -> usize { self.outstanding.len() }

    pub fn track_sent(&mut self, data: &[u8], now: Instant) -> Result<u16, ReliabilityError> {
        if data.is_empty() { return Err(ReliabilityError::EmptyMessage); }
        if data.len() > MAX_MESSAGE_BYTES { return Err(ReliabilityError::OversizedMessage); }
        if self.outstanding.len() >= MAX_IN_FLIGHT { return Err(ReliabilityError::QueueFull); }
        let sequence = self.next_sequence;
        if self.outstanding.contains_key(&sequence) {
            return Err(ReliabilityError::SequenceInUse);
        }
        self.outstanding.insert(sequence, Outstanding {
            bytes: data.to_vec(), last_sent: now, retries: 0,
        });
        self.next_sequence = sequence.wrapping_add(1);
        Ok(sequence)
    }

    pub fn acknowledge(&mut self, sequence: u16) -> bool {
        self.outstanding.remove(&sequence).is_some()
    }

    /// Reject untrusted broad or reversed ranges before touching state.
    pub fn acknowledge_range(&mut self, start: u16, end: u16) -> Result<usize, ReliabilityError> {
        if start > end || usize::from(end - start) + 1 > MAX_ACK_RANGE {
            return Err(ReliabilityError::InvalidAckRange);
        }
        let mut removed = 0;
        for seq in start..=end {
            if self.acknowledge(seq) { removed += 1; }
        }
        Ok(removed)
    }

    /// Returns messages due for a retransmission, and permanently failed
    /// sequences for which the caller must handle disconnect/error policy.
    pub fn poll_retries(&mut self, now: Instant, limit: usize) -> RetryBatch {
        let mut batch = RetryBatch::default();
        if limit == 0 { return batch; }
        for (&seq, entry) in self.outstanding.iter_mut() {
            if batch.resend.len() + batch.abandoned.len() >= limit { break; }
            if now.saturating_duration_since(entry.last_sent) < self.retry_after { continue; }
            if entry.retries >= self.max_retries {
                batch.abandoned.push(seq);
                continue;
            }
            entry.retries += 1;
            entry.last_sent = now;
            batch.resend.push(Resend {
                sequence: seq, bytes: entry.bytes.clone(), attempt: entry.retries,
            });
        }
        for seq in &batch.abandoned {
            self.outstanding.remove(seq);
        }
        batch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveDecision {
    New,
    Duplicate,
    Old,
    TooFarAhead,
}

/// Bounded sliding window for 16-bit sequence numbers, including wraparound.
pub struct ReceiveWindow {
    next_expected: u16,
    seen: [bool; RECEIVE_WINDOW],
}

impl Default for ReceiveWindow {
    fn default() -> Self {
        Self { next_expected: 0, seen: [false; RECEIVE_WINDOW] }
    }
}

impl ReceiveWindow {
    pub fn next_expected(&self) -> u16 { self.next_expected }

    pub fn observe(&mut self, sequence: u16) -> ReceiveDecision {
        let ahead = sequence.wrapping_sub(self.next_expected);
        if usize::from(ahead) >= RECEIVE_WINDOW {
            return if ahead >= 0x8000 {
                ReceiveDecision::Old
            } else {
                ReceiveDecision::TooFarAhead
            };
        }
        let offset = usize::from(ahead);
        if self.seen[offset] { return ReceiveDecision::Duplicate; }
        self.seen[offset] = true;
        while self.seen[0] {
            self.seen.rotate_left(1);
            self.seen[RECEIVE_WINDOW - 1] = false;
            self.next_expected = self.next_expected.wrapping_add(1);
        }
        ReceiveDecision::New
    }
}

/// ACK message numbers pending serialization. Does not represent a wire frame.
#[derive(Default)]
pub struct PendingAcks {
    entries: BTreeSet<u16>,
}

impl PendingAcks {
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn mark(&mut self, number: u16) -> Result<(), ReliabilityError> {
        if self.entries.contains(&number) { return Ok(()); }
        if self.entries.len() >= MAX_ACK_BATCH { return Err(ReliabilityError::QueueFull); }
        self.entries.insert(number);
        Ok(())
    }

    pub fn take(&mut self, limit: usize) -> Vec<u16> {
        let batch: Vec<_> = self.entries.iter().copied().take(limit).collect();
        for n in &batch { self.entries.remove(n); }
        batch
    }
}

#[derive(Default)]
struct OrderedChannel {
    next_expected: u16,
    waiting: BTreeMap<u16, Vec<u8>>,
}

/// 32 independent bounded channels for ordered packet delivery.
pub struct OrderedDelivery {
    channels: Vec<OrderedChannel>,
}

impl Default for OrderedDelivery {
    fn default() -> Self {
        Self { channels: (0..ORDER_CHANNELS).map(|_| OrderedChannel::default()).collect() }
    }
}

impl OrderedDelivery {
    pub fn pending(&self, channel: u8) -> Option<usize> {
        self.channels.get(usize::from(channel)).map(|c| c.waiting.len())
    }

    /// Returns packets delivered in order; future packets remain buffered.
    pub fn push(&mut self, channel: u8, index: u16, payload: Vec<u8>)
        -> Result<Vec<Vec<u8>>, ReliabilityError>
    {
        let ch = self.channels.get_mut(usize::from(channel))
            .ok_or(ReliabilityError::InvalidChannel)?;
        if payload.is_empty() { return Err(ReliabilityError::EmptyMessage); }
        if payload.len() > MAX_MESSAGE_BYTES { return Err(ReliabilityError::OversizedMessage); }
        let ahead = index.wrapping_sub(ch.next_expected);
        if ahead == 0 {
            let mut delivered = vec![payload];
            ch.next_expected = ch.next_expected.wrapping_add(1);
            while let Some(packet) = ch.waiting.remove(&ch.next_expected) {
                delivered.push(packet);
                ch.next_expected = ch.next_expected.wrapping_add(1);
            }
            return Ok(delivered);
        }
        if ahead >= 0x8000 { return Err(ReliabilityError::Old); }
        if usize::from(ahead) > MAX_ORDERED_PENDING {
            return Err(ReliabilityError::TooFarAhead);
        }
        if ch.waiting.contains_key(&index) { return Err(ReliabilityError::Duplicate); }
        if ch.waiting.len() >= MAX_ORDERED_PENDING {
            return Err(ReliabilityError::QueueFull);
        }
        ch.waiting.insert(index, payload);
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliable_ack_and_retry_expiry() {
        let t = Instant::now();
        let mut q = OutboundReliability::new(Duration::from_millis(100), 2);
        assert_eq!(q.track_sent(b"hello", t), Ok(0));
        assert!(q.poll_retries(t + Duration::from_millis(99), 2).resend.is_empty());
        assert_eq!(q.poll_retries(t + Duration::from_millis(100), 2).resend,
            vec![Resend { sequence: 0, bytes: b"hello".to_vec(), attempt: 1 }]);
        assert_eq!(q.poll_retries(t + Duration::from_millis(200), 2).resend[0].attempt, 2);
        assert_eq!(q.poll_retries(t + Duration::from_millis(300), 2).abandoned, vec![0]);
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn ack_range_validation_is_atomic() {
        let t = Instant::now();
        let mut q = OutboundReliability::new(Duration::from_millis(10), 3);
        for _ in 0..5 { q.track_sent(b"x", t).unwrap(); }
        assert_eq!(q.acknowledge_range(4, 2), Err(ReliabilityError::InvalidAckRange));
        assert_eq!(q.acknowledge_range(0, u16::MAX), Err(ReliabilityError::InvalidAckRange));
        assert_eq!(q.pending_count(), 5);
        assert_eq!(q.acknowledge_range(1, 3), Ok(3));
        assert!(!q.acknowledge(1));
    }

    #[test]
    fn limits_and_sequence_wrap() {
        let t = Instant::now();
        let mut q = OutboundReliability::new(Duration::from_millis(20), 1);
        assert_eq!(q.track_sent(b"", t), Err(ReliabilityError::EmptyMessage));
        assert_eq!(q.track_sent(&vec![0; MAX_MESSAGE_BYTES + 1], t),
            Err(ReliabilityError::OversizedMessage));
        for i in 0..MAX_IN_FLIGHT { assert_eq!(q.track_sent(b"x", t), Ok(i as u16)); }
        assert_eq!(q.track_sent(b"x", t), Err(ReliabilityError::QueueFull));
        let mut wrap = OutboundReliability::new(Duration::from_millis(20), 1);
        wrap.next_sequence = u16::MAX;
        assert_eq!(wrap.track_sent(b"last", t), Ok(u16::MAX));
        assert_eq!(wrap.track_sent(b"first", t), Ok(0));
    }

    #[test]
    fn deduplication_and_out_of_order_window() {
        let mut w = ReceiveWindow::default();
        assert_eq!(w.observe(1), ReceiveDecision::New);
        assert_eq!(w.observe(1), ReceiveDecision::Duplicate);
        assert_eq!(w.observe(513), ReceiveDecision::TooFarAhead);
        assert_eq!(w.observe(0), ReceiveDecision::New);
        assert_eq!(w.next_expected(), 2);
        assert_eq!(w.observe(1), ReceiveDecision::Old);
        assert_eq!(w.observe(u16::MAX), ReceiveDecision::Old);
        let mut wrap = ReceiveWindow {
            next_expected: u16::MAX, seen: [false; RECEIVE_WINDOW],
        };
        assert_eq!(wrap.observe(0), ReceiveDecision::New);
        assert_eq!(wrap.observe(u16::MAX), ReceiveDecision::New);
        assert_eq!(wrap.next_expected(), 1);
    }

    #[test]
    fn ack_buffer_has_fixed_capacity() {
        let mut acks = PendingAcks::default();
        for i in 0..MAX_ACK_BATCH {
            acks.mark(i as u16).unwrap();
            acks.mark(i as u16).unwrap();
        }
        assert_eq!(acks.mark(900), Err(ReliabilityError::QueueFull));
        assert_eq!(acks.take(3), vec![0, 1, 2]);
        assert_eq!(acks.len(), MAX_ACK_BATCH - 3);
    }

    #[test]
    fn channel_ordering_isolated_and_bounded() {
        let mut d = OrderedDelivery::default();
        assert!(d.push(0, 2, b"c".to_vec()).unwrap().is_empty());
        assert!(d.push(0, 1, b"b".to_vec()).unwrap().is_empty());
        assert_eq!(d.push(0, 1, b"duplicate".to_vec()), Err(ReliabilityError::Duplicate));
        assert_eq!(d.push(1, 0, b"independent".to_vec()).unwrap(),
            vec![b"independent".to_vec()]);
        assert_eq!(d.push(0, 0, b"a".to_vec()).unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(d.push(0, 1, b"old".to_vec()), Err(ReliabilityError::Old));
        assert_eq!(d.push(32, 0, vec![1]), Err(ReliabilityError::InvalidChannel));
        assert_eq!(d.push(0, 100, vec![1]), Err(ReliabilityError::TooFarAhead));
        d.channels[0].next_expected = u16::MAX;
        assert!(d.push(0, 0, vec![2]).unwrap().is_empty());
        assert_eq!(d.push(0, u16::MAX, vec![1]).unwrap(), vec![vec![1], vec![2]]);
    }
}
