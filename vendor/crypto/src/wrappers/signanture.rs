use super::internal::secret_copy;
use super::{
    base_crypt::BaseCrypt, error::Result, handle::Handle, internal::checked, internal::length,
    password::Password, plugin_buffer::PluginBuffer, plugin_buffer::output, raw, symbol,
};

/// Контекст подписи ГОСТ. В C++ имя класса записано с опечаткой: Signanture;
/// здесь доступны оба имени.
pub struct Signature {
    handle: Handle,
}
pub type Signanture = Signature;
impl Signature {
    pub fn new(parent: &BaseCrypt) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, sign_createSignAlgInstanse);
        let delete = symbol!(p, sign_deleteSignInst);
        Ok(Self {
            handle: Handle::new(parent, delete, "sign_createSignAlgInstanse", |e| unsafe {
                create(parent.0.ptr.as_ptr(), raw::SignAlgDef_Gost_3410, e)
            })?,
        })
    }
    pub fn export_public(&mut self, include_all: bool) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), sign_exportPublicData);
        output(
            &self.handle.parent,
            "sign_exportPublicData",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), len, include_all, e) },
        )
    }
    pub fn import_public(&mut self, data: &[u8], include_all: bool) -> Result<()> {
        let f = symbol!(self.handle.plugin(), sign_importPublicData);
        let mut data = secret_copy(data);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_mut_ptr().cast(),
                    length(data.len())?,
                    include_all,
                    &mut error,
                )
            },
            error,
            "sign_importPublicData",
        )
    }
    pub fn export_by_password(&mut self, password: &Password) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), sign_exportByPass);
        output(&self.handle.parent, "sign_exportByPass", |len, e| unsafe {
            f(self.handle.ptr.as_ptr(), password.as_ptr(), len, e)
        })
    }
    pub fn import_by_password(&mut self, container: &[u8], password: &Password) -> Result<()> {
        let f = symbol!(self.handle.plugin(), sign_importByPass);
        let mut data = secret_copy(container);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_mut_ptr().cast(),
                    data.len(),
                    password.as_ptr(),
                    &mut error,
                )
            },
            error,
            "sign_importByPass",
        )
    }
    pub fn sign(&mut self, data: &[u8]) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), sign);
        let len = length(data.len())?;
        output(&self.handle.parent, "sign", |out_len, e| unsafe {
            f(self.handle.ptr.as_ptr(), data.as_ptr(), len, out_len, e)
        })
    }
    /// Ошибка проверки возвращается с исходным кодом плагина.
    pub fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), sign_verify);
        let mut data = secret_copy(data);
        let mut signature = secret_copy(signature);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_mut_ptr(),
                    length(data.len())?,
                    signature.as_mut_ptr(),
                    length(signature.len())?,
                    &mut error,
                )
            },
            error,
            "sign_verify",
        )
    }
}
