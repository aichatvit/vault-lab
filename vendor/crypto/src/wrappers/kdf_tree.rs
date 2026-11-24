use super::{
    base_crypt::BaseCrypt, error::Error, error::Result, handle::Handle, internal::checked,
    internal::length, raw, symbol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KdfTreeR {
    R1 = 1,
    R2 = 2,
    R4 = 4,
}

/// Заимствованные параметры контекста KDF. Длина результата указана в байтах.
pub struct KdfInput<'a> {
    pub r: KdfTreeR,
    pub label: &'a [u8],
    pub seed: &'a [u8],
    pub output_len: usize,
}
impl KdfInput<'_> {
    fn validate(&self) -> Result<()> {
        if self.label.is_empty() || self.seed.is_empty() || self.output_len == 0 {
            return Err(Error::InvalidInput(
                "KDF label, seed and output must not be empty",
            ));
        }
        length(self.label.len())?;
        length(self.seed.len())?;
        length(self.output_len)?;
        let max = match self.r {
            KdfTreeR::R1 => 8160u64,
            KdfTreeR::R2 => 2097120,
            KdfTreeR::R4 => 137438953440,
        };
        if self.output_len as u64 > max {
            return Err(Error::InvalidInput(
                "KDF output exceeds the counter's limit",
            ));
        }
        Ok(())
    }
}
pub struct KdfTree {
    handle: Handle,
}
impl KdfTree {
    pub fn new(parent: &BaseCrypt) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, KdfTree_createInst);
        let delete = symbol!(p, KdfTree_deleteInst);
        Ok(Self {
            handle: Handle::new(parent, delete, "KdfTree_createInst", |e| unsafe {
                create(
                    parent.0.ptr.as_ptr(),
                    raw::KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
                    e,
                )
            })?,
        })
    }
    pub fn data(parent: &BaseCrypt, r: KdfTreeR) -> Result<raw::KdfTreeData> {
        let f = symbol!(parent.0.plugin(), KdfTree_getData);
        let mut out = raw::KdfTreeData::default();
        let mut error = 0;
        checked(
            unsafe {
                f(
                    raw::KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
                    r as i32,
                    &mut out,
                    &mut error,
                )
            },
            error,
            "KdfTree_getData",
        )?;
        Ok(out)
    }
    pub fn derive(
        &mut self,
        key: &[u8],
        input: &KdfInput<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        input.validate()?;
        validate_key(key)?;
        let f = symbol!(self.handle.plugin(), KdfTree_deriveBytesInst);
        let mut out = zeroize::Zeroizing::new(vec![0; input.output_len]);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    input.r as i32,
                    key.as_ptr().cast(),
                    length(key.len())?,
                    input.label.as_ptr().cast(),
                    length(input.label.len())?,
                    input.seed.as_ptr().cast(),
                    length(input.seed.len())?,
                    out.as_mut_ptr().cast(),
                    length(out.len())?,
                    &mut error,
                )
            },
            error,
            "KdfTree_deriveBytesInst",
        )?;
        Ok(out)
    }
    pub fn derive_portable(
        parent: &BaseCrypt,
        key: &[u8],
        input: &KdfInput<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        input.validate()?;
        validate_key(key)?;
        let f = symbol!(parent.0.plugin(), KdfTree_deriveBytes);
        let mut out = zeroize::Zeroizing::new(vec![0; input.output_len]);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    parent.0.ptr.as_ptr(),
                    raw::KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
                    input.r as i32,
                    key.as_ptr().cast(),
                    length(key.len())?,
                    input.label.as_ptr().cast(),
                    length(input.label.len())?,
                    input.seed.as_ptr().cast(),
                    length(input.seed.len())?,
                    out.as_mut_ptr().cast(),
                    length(out.len())?,
                    &mut error,
                )
            },
            error,
            "KdfTree_deriveBytes",
        )?;
        Ok(out)
    }
    pub fn derive_by_sym_key(
        &mut self,
        key: &super::symmetric::Symmetric,
        input: &KdfInput<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.handle.same_parent(&key.handle)?;
        input.validate()?;
        let f = symbol!(self.handle.plugin(), KdfTree_deriveBytesBySymKeyInst);
        let mut out = zeroize::Zeroizing::new(vec![0; input.output_len]);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    input.r as i32,
                    key.handle.ptr.as_ptr(),
                    input.label.as_ptr().cast(),
                    length(input.label.len())?,
                    input.seed.as_ptr().cast(),
                    length(input.seed.len())?,
                    out.as_mut_ptr().cast(),
                    length(out.len())?,
                    &mut error,
                )
            },
            error,
            "KdfTree_deriveBytesBySymKeyInst",
        )?;
        Ok(out)
    }
    pub fn derive_by_sym_key_portable(
        parent: &BaseCrypt,
        key: &super::symmetric::Symmetric,
        input: &KdfInput<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if !std::rc::Rc::ptr_eq(&parent.0, &key.handle.parent) {
            return Err(Error::InvalidInput(
                "Handles belong to different base contexts",
            ));
        }
        input.validate()?;
        let f = symbol!(parent.0.plugin(), KdfTree_deriveBytesBySymKey);
        let mut out = zeroize::Zeroizing::new(vec![0; input.output_len]);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    parent.0.ptr.as_ptr(),
                    raw::KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
                    input.r as i32,
                    key.handle.ptr.as_ptr(),
                    input.label.as_ptr().cast(),
                    length(input.label.len())?,
                    input.seed.as_ptr().cast(),
                    length(input.seed.len())?,
                    out.as_mut_ptr().cast(),
                    length(out.len())?,
                    &mut error,
                )
            },
            error,
            "KdfTree_deriveBytesBySymKey",
        )?;
        Ok(out)
    }
}
fn validate_key(key: &[u8]) -> Result<()> {
    if (32..=64).contains(&key.len()) {
        Ok(())
    } else {
        Err(Error::InvalidInput("KDF key must contain 32..64 bytes"))
    }
}
