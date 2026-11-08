//! ID-based fixed-capacity entity storage. IDs are stable until removed.
//! Uses a bounded Vec instead of a generational arena because SA-MP exposes numeric IDs.

#[derive(Debug)]
pub struct Pool<T> {
    slots: Vec<Option<T>>,
    length: usize,
    next_hint: usize,
}

impl<T> Pool<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity <= u16::MAX as usize + 1, "pool IDs must fit u16");
        Self {
            slots: std::iter::repeat_with(|| None).take(capacity).collect(),
            length: 0,
            next_hint: 0,
        }
    }

    pub fn capacity(&self) -> usize { self.slots.len() }
    pub fn len(&self) -> usize { self.length }
    pub fn is_empty(&self) -> bool { self.length == 0 }

    pub fn insert(&mut self, value: T) -> Result<u16, T> {
        if self.length == self.slots.len() { return Err(value); }
        let cap = self.slots.len();
        for offset in 0..cap {
            let index = (self.next_hint + offset) % cap;
            if self.slots[index].is_none() {
                self.slots[index] = Some(value);
                self.length += 1;
                self.next_hint = (index + 1) % cap;
                return Ok(index as u16);
            }
        }
        Err(value)
    }

    pub fn get(&self, id: u16) -> Option<&T> {
        self.slots.get(id as usize)?.as_ref()
    }

    pub fn get_mut(&mut self, id: u16) -> Option<&mut T> {
        self.slots.get_mut(id as usize)?.as_mut()
    }

    pub fn remove(&mut self, id: u16) -> Option<T> {
        let index = id as usize;
        let old = self.slots.get_mut(index)?.take()?;
        self.length -= 1;
        self.next_hint = index;
        Some(old)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, &T)> {
        self.slots.iter().enumerate().filter_map(|(id, value)| {
            value.as_ref().map(|value| (id as u16, value))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_ids_and_recycles_removed_slots() {
        let mut pool = Pool::with_capacity(2);
        let a = pool.insert("a").unwrap();
        let b = pool.insert("b").unwrap();
        assert_eq!((a, b), (0, 1));
        assert_eq!(pool.insert("c"), Err("c"));
        assert_eq!(pool.remove(a), Some("a"));
        assert_eq!(pool.insert("d").unwrap(), a);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.get(b), Some(&"b"));
    }

    #[test]
    fn empty_pool_has_no_valid_ids() {
        let mut pool: Pool<u32> = Pool::with_capacity(0);
        assert!(pool.insert(4).is_err());
        assert_eq!(pool.remove(99), None);
        assert!(pool.is_empty());
    }
}
