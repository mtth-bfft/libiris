// This is a no_std environment: we cannot allocate dynamic memory.
// Any formatted message need to fit into a stack buffer, the rest will
// be truncated.
pub struct StackBuffer<const SIZE: usize> {
    pub(crate) buf: [u8; SIZE],
    pub(crate) used_bytes: usize,
}

impl<const SIZE: usize> StackBuffer<SIZE> {
    pub fn new() -> Self {
        Self {
            buf: [0u8; SIZE],
            used_bytes: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[0..self.used_bytes]
    }
}

impl<const SIZE: usize> core::fmt::Write for StackBuffer<SIZE> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let capacity = self.buf.len() - 1; // always keep a null byte
        for (i, &b) in self.buf[self.used_bytes..capacity] // truncate the rest, don't panic!()
            .iter_mut()
            .zip(s.as_bytes().iter())
        {
            *i = b;
        }
        self.used_bytes = usize::min(capacity, self.used_bytes + s.as_bytes().len());
        Ok(())
    }
}
