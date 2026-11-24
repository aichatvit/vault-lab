use super::{
    base_crypt::BaseCrypt, error::Result, handle::Handle, internal::checked, internal::length,
    password::Password, plugin_buffer::PluginBuffer, plugin_buffer::output, raw, symbol,
};

pub struct Asymmetric {
    pub(super) handle: Handle,
}
impl Asymmetric {
    pub fn new(parent: &BaseCrypt) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, createAsymmetricContext);
        let delete = symbol!(p, destroyAsymmetricContext);
        Ok(Self {
            handle: Handle::new(parent, delete, "createAsymmetricContext", |e| unsafe {
                create(
                    parent.0.ptr.as_ptr(),
                    raw::AsymmetricAlgDef_Vko_Gostr3410,
                    e,
                )
            })?,
        })
    }
    pub fn export_public(&mut self, include_all: bool) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), exportPublicData);
        output(&self.handle.parent, "exportPublicData", |len, e| unsafe {
            f(self.handle.ptr.as_ptr(), include_all, len, e)
        })
    }
    pub fn import_public(&mut self, data: &[u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), importPublicData);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_ptr(),
                    length(data.len())?,
                    &mut error,
                )
            },
            error,
            "importPublicData",
        )
    }
    pub fn export_by_password(&mut self, password: &Password) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), asymm_exportKeyByPass);
        output(
            &self.handle.parent,
            "asymm_exportKeyByPass",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), password.as_ptr(), len, e) },
        )
    }
    pub fn import_by_password(&mut self, container: &[u8], password: &Password) -> Result<()> {
        let f = symbol!(self.handle.plugin(), asymm_importKeyByPass);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    password.as_ptr(),
                    container.as_ptr(),
                    length(container.len())?,
                    &mut error,
                )
            },
            error,
            "asymm_importKeyByPass",
        )
    }
    pub fn encrypt(&mut self, data: &[u8]) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), encrypt);
        let len = length(data.len())?;
        output(&self.handle.parent, "encrypt", |out_len, e| unsafe {
            f(self.handle.ptr.as_ptr(), data.as_ptr(), len, out_len, e)
        })
    }
    pub fn decrypt(&mut self, data: &[u8]) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), decrypt);
        let len = length(data.len())?;
        output(&self.handle.parent, "decrypt", |out_len, e| unsafe {
            f(self.handle.ptr.as_ptr(), data.as_ptr(), len, out_len, e)
        })
    }
}
