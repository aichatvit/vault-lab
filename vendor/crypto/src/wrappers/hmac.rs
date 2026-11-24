use super::internal::secret_copy;
use super::{
    base_crypt::BaseCrypt, digest_length::DigestLength, error::Result, handle::Handle,
    internal::checked, internal::length, raw, symbol,
};

pub struct Hmac {
    handle: Handle,
    bits: DigestLength,
}
impl Hmac {
    pub fn new(parent: &BaseCrypt, bits: DigestLength) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, createHmacInst);
        let delete = symbol!(p, deleteHmacInst);
        let handle = Handle::new(parent, delete, "createHmacInst", |e| unsafe {
            create(
                parent.0.ptr.as_ptr(),
                raw::HmacAlgDef_HMAC_GOSTR3411_2012,
                bits.id(),
                e,
            )
        })?;
        Ok(Self { handle, bits })
    }
    /// Ограничения плагина на длину ключа сохраняются; дополнение не выполняется.
    pub fn with_key(parent: &BaseCrypt, bits: DigestLength, key: &[u8]) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, createHmacInst_key);
        let delete = symbol!(p, deleteHmacInst);
        let mut key = secret_copy(key);
        let len = length(key.len())?;
        let handle = Handle::new(parent, delete, "createHmacInst_key", |e| unsafe {
            create(
                parent.0.ptr.as_ptr(),
                raw::HmacAlgDef_HMAC_GOSTR3411_2012,
                bits.id(),
                key.as_mut_ptr().cast(),
                len,
                e,
            )
        })?;
        Ok(Self { handle, bits })
    }
    pub fn data(&self) -> Result<raw::HmacData> {
        let f = symbol!(self.handle.plugin(), Hmac_getData);
        let mut out = raw::HmacData::default();
        let mut error = 0;
        checked(
            unsafe { f(self.handle.ptr.as_ptr(), &mut out, &mut error) },
            error,
            "Hmac_getData",
        )?;
        Ok(out)
    }
    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), setKeyInst);
        let mut key = secret_copy(key);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    key.as_mut_ptr().cast(),
                    length(key.len())?,
                    &mut error,
                )
            },
            error,
            "setKeyInst",
        )
    }
    pub fn compute(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let f = symbol!(self.handle.plugin(), compHmac);
        let mut input = secret_copy(data);
        let mut out = vec![0; self.bits.bytes()];
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    input.as_mut_ptr().cast(),
                    length(input.len())?,
                    out.as_mut_ptr().cast(),
                    &mut error,
                )
            },
            error,
            "compHmac",
        )?;
        Ok(out)
    }
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), updateHmac);
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
            "updateHmac",
        )
    }
    pub fn finalize(self) -> Result<Vec<u8>> {
        let f = symbol!(self.handle.plugin(), finalHmac);
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
            "finalHmac",
        )?;
        Ok(out)
    }
}
