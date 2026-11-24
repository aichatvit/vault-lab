use super::internal::secret_copy;
use super::{
    base_crypt::BaseCrypt, digest_length::DigestLength, error::Result, handle::Handle,
    internal::checked, internal::length, raw, symbol,
};

pub struct Hash {
    handle: Handle,
    bits: DigestLength,
}
impl Hash {
    pub fn new(parent: &BaseCrypt, bits: DigestLength) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, createHashInst);
        let delete = symbol!(p, deleteHashInst);
        let handle = Handle::new(parent, delete, "createHashInst", |e| unsafe {
            create(parent.0.ptr.as_ptr(), raw::HashAlgDef_gost, bits.id(), e)
        })?;
        Ok(Self { handle, bits })
    }
    pub fn compute(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let f = symbol!(self.handle.plugin(), compHash);
        let mut out = vec![0; self.bits.bytes()];
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_ptr().cast(),
                    length(data.len())?,
                    out.as_mut_ptr().cast(),
                    &mut error,
                )
            },
            error,
            "compHash",
        )?;
        Ok(out)
    }
    pub fn compute_portable(
        parent: &BaseCrypt,
        bits: DigestLength,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let f = symbol!(parent.0.plugin(), compHash_port);
        let mut input = secret_copy(data);
        let mut out = vec![0; bits.bytes()];
        let mut error = 0;
        checked(
            unsafe {
                f(
                    parent.0.ptr.as_ptr(),
                    raw::HashAlgDef_gost,
                    bits.id(),
                    input.as_mut_ptr().cast(),
                    length(input.len())?,
                    out.as_mut_ptr().cast(),
                    &mut error,
                )
            },
            error,
            "compHash_port",
        )?;
        Ok(out)
    }
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), updateHash);
        let mut input = secret_copy(data);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    input.as_mut_ptr().cast(),
                    length(input.len())?,
                    &mut error,
                )
            },
            error,
            "updateHash",
        )
    }
    /// Потребить потоковый контекст, исключив обновление после завершения.
    pub fn finalize(self) -> Result<Vec<u8>> {
        let f = symbol!(self.handle.plugin(), finalResult);
        let mut out = vec![0; self.bits.bytes()];
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    out.as_mut_ptr().cast(),
                    &mut error,
                )
            },
            error,
            "finalResult",
        )?;
        Ok(out)
    }
}
