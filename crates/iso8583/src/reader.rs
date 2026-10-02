use crate::error::{Error, Result};

/// Bounds-checked cursor over untrusted input. All reads return `Err`
/// instead of panicking on short data.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::Truncated {
                what,
                need: n,
                have: self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub(crate) fn take_u8(&mut self, what: &'static str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }
}
