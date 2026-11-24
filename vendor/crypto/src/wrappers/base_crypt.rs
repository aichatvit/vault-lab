use super::password::Password;
use super::{
    error::Error, error::Result, init_params::InitParams, internal::checked, internal::length,
    library::Library, plugin_buffer::PluginBuffer, plugin_buffer::output, raw, symbol,
};
use std::{ffi::c_void, ptr::NonNull, rc::Rc};

pub(super) struct ContextInner {
    pub library: Library,
    pub ptr: NonNull<c_void>,
    destroy: unsafe extern "C" fn(*mut c_void) -> bool,
    pub free: unsafe extern "C" fn(*mut c_void, *mut c_void, u32) -> bool,
}
impl ContextInner {
    pub fn plugin(&self) -> &raw::CryptoPlugin {
        &self.library.0
    }
}
impl Drop for ContextInner {
    fn drop(&mut self) {
        unsafe {
            (self.destroy)(self.ptr.as_ptr());
        }
    }
}

/// Главный контекст. Дочерние объекты и буферы удерживают его совместным владением.
#[derive(Clone)]
pub struct BaseCrypt(pub(super) Rc<ContextInner>);
impl BaseCrypt {
    pub fn new(library: &Library, params: impl Into<InitParams>) -> Result<Self> {
        let p = &library.0;
        let destroy = symbol!(p, destroyCryptoContext);
        let free = symbol!(p, destroyMemory);
        let create = symbol!(p, createCryptoContextByParams);
        let mut params = params.into();
        let mut error = 0;
        // Временные структуры параметров указывают на принадлежащие нам данные,
        // которые существуют весь вызов. Плагин использует или копирует их значения.
        let ptr = unsafe {
            match &mut params {
                InitParams::BySeq(v) => {
                    if v.sequence.is_empty() {
                        return Err(Error::InvalidInput("Initialization sequence is empty"));
                    }
                    let value = raw::SeqParams {
                        typeOfParams: raw::TypeOfParams_seq,
                        needRandomBlock: v.need_random_block,
                        seq: v.sequence.as_mut_ptr().cast(),
                        lenOfSeq: length(v.sequence.len())?,
                    };
                    create((&value as *const raw::SeqParams).cast(), &mut error)
                }
                InitParams::Cont(v) => {
                    if v.container.is_empty() {
                        return Err(Error::InvalidInput("Initialization container is empty"));
                    }
                    let value = raw::ContainerParams {
                        typeOfParams: raw::TypeOfParams_cont,
                        pass: v.password.as_ptr(),
                        cont: v.container.as_ptr().cast(),
                        len: length(v.container.len())?,
                        needBlockByRand: v.need_random_block,
                    };
                    create((&value as *const raw::ContainerParams).cast(), &mut error)
                }
                InitParams::BySignSeq(v) => {
                    if v.sequence.is_empty() || v.container.is_empty() || v.signature.is_empty() {
                        return Err(Error::InvalidInput(
                            "Signed initialization inputs must not be empty",
                        ));
                    }
                    let value = raw::SigSeqParams {
                        typeOfParams: raw::TypeOfParams_signSeq,
                        needRandomBlock: v.need_random_block,
                        seq: v.sequence.as_ptr().cast(),
                        lenOfSeq: length(v.sequence.len())?,
                        kkp: v.container.as_ptr().cast(),
                        lenOfKkp: length(v.container.len())?,
                        passToKkp: v.password.as_ptr(),
                        lenOfPassToKkp: v.password.len(),
                        sign: v.signature.as_ptr().cast(),
                        lenOfSign: length(v.signature.len())?,
                    };
                    create((&value as *const raw::SigSeqParams).cast(), &mut error)
                }
            }
        };
        if error != 0 || ptr.is_null() {
            if !ptr.is_null() {
                unsafe {
                    destroy(ptr);
                }
            }
            return Err(Error::Native {
                operation: "createCryptoContextByParams",
                code: error,
            });
        }
        Ok(Self(Rc::new(ContextInner {
            library: library.clone(),
            ptr: NonNull::new(ptr).unwrap(),
            destroy,
            free,
        })))
    }

    pub fn create_kkp(&mut self, password: &Password) -> Result<PluginBuffer> {
        let f = symbol!(self.0.plugin(), createKkp);
        output(&self.0, "createKkp", |len, error| unsafe {
            f(self.0.ptr.as_ptr(), password.as_ptr(), len, error)
        })
    }

    pub fn hmac_key_sizes(
        &self,
        bits: super::digest_length::DigestLength,
    ) -> Result<raw::HmacData_KeySizes> {
        let f = symbol!(self.0.plugin(), Hmac_getData_KeySizes);
        let mut value = raw::HmacData_KeySizes::default();
        let mut error = 0;
        checked(
            unsafe {
                f(
                    raw::HmacAlgDef_HMAC_GOSTR3411_2012,
                    bits.id(),
                    &mut value,
                    &mut error,
                )
            },
            error,
            "Hmac_getData_KeySizes",
        )?;
        Ok(value)
    }
}
