use super::{
    base_crypt::BaseCrypt, error::Result, handle::Handle, internal::checked, internal::length, raw,
    symbol,
};

pub struct Random {
    handle: Handle,
}
impl Random {
    pub fn new(parent: &BaseCrypt) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, createRandInstance);
        let delete = symbol!(p, deleteRandInstance);
        Ok(Self {
            handle: Handle::new(parent, delete, "createRandInstance", |e| unsafe {
                create(
                    parent.0.ptr.as_ptr(),
                    raw::RandomAlgDef_GostP1323565_1006_2017,
                    e,
                )
            })?,
        })
    }
    pub fn fill(&mut self, buffer: &mut [u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), genRandSeq);
        let len = length(buffer.len())?;
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.parent.ptr.as_ptr(),
                    self.handle.ptr.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    len,
                    &mut error,
                )
            },
            error,
            "genRandSeq",
        )
    }
    pub fn generate(&mut self, count: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        length(count)?;
        let mut result = zeroize::Zeroizing::new(vec![0; count]);
        self.fill(&mut result)?;
        Ok(result)
    }
}
