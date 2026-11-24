use super::internal::secret_copy;
use super::{
    base_crypt::BaseCrypt, error::Result, handle::Handle, internal::checked, internal::length,
    password::Password, plugin_buffer::PluginBuffer, plugin_buffer::output, raw, symbol,
};

pub struct DiffieHellman {
    handle: Handle,
    finished: bool,
}
pub struct AgreementStep {
    pub message: Option<PluginBuffer>,
    pub finished: bool,
}
impl DiffieHellman {
    pub fn new(parent: &BaseCrypt) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, DiffieHellman_createDiffHellInst);
        let delete = symbol!(p, DiffieHellman_deleteDiffHellInst);
        Ok(Self {
            finished: false,
            handle: Handle::new(
                parent,
                delete,
                "DiffieHellman_createDiffHellInst",
                |e| unsafe { create(parent.0.ptr.as_ptr(), raw::DiffieHellmanAlgDef_Echinacea, e) },
            )?,
        })
    }
    pub fn export_public(&mut self, include_all: bool) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), DiffieHellman_exportPublicData);
        output(
            &self.handle.parent,
            "DiffieHellman_exportPublicData",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), include_all, len, e) },
        )
    }
    pub fn import_public(&mut self, data: &[u8], include_all: bool) -> Result<()> {
        self.finished = false;
        let f = symbol!(self.handle.plugin(), DiffieHellman_importPublicData);
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
            "DiffieHellman_importPublicData",
        )
    }
    pub fn export_by_password(&mut self, password: &Password) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), DiffieHellman_exportByPass);
        output(
            &self.handle.parent,
            "DiffieHellman_exportByPass",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), password.as_ptr(), len, e) },
        )
    }
    pub fn import_by_password(&mut self, container: &[u8], password: &Password) -> Result<()> {
        self.finished = false;
        let f = symbol!(self.handle.plugin(), DiffieHellman_importByPass);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    container.as_ptr(),
                    length(container.len())?,
                    password.as_ptr(),
                    &mut error,
                )
            },
            error,
            "DiffieHellman_importByPass",
        )
    }
    pub fn private_params(&mut self) -> Result<PluginBuffer> {
        let f = symbol!(
            self.handle.plugin(),
            DiffieHellman_getAdditionalPrivateParams
        );
        output(
            &self.handle.parent,
            "DiffieHellman_getAdditionalPrivateParams",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), len, e) },
        )
    }
    pub fn set_private_params(&mut self, data: &[u8]) -> Result<()> {
        self.finished = false;
        let f = symbol!(
            self.handle.plugin(),
            DiffieHellman_setAdditionalPrivateParams
        );
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_ptr().cast(),
                    length(data.len())?,
                    &mut error,
                )
            },
            error,
            "DiffieHellman_setAdditionalPrivateParams",
        )
    }
    /// Передать сообщение протокола плагина; результат следует направить другой стороне.
    /// Кодирование начального сообщения и предварительно распределённые секретные параметры
    /// определяются протоколом плагина, а не этой обёрткой или объявлениями функций.
    pub fn derive_step(&mut self, data: &[u8]) -> Result<AgreementStep> {
        if self.finished {
            return Err(super::error::Error::InvalidInput(
                "Agreement has already finished",
            ));
        }
        let f = symbol!(self.handle.plugin(), DiffieHellman_deriveKeyMaterial);
        let mut data = secret_copy(data);
        let len = length(data.len())?;
        let mut finished = false;
        let message = super::plugin_buffer::output_optional(
            &self.handle.parent,
            "DiffieHellman_deriveKeyMaterial",
            |out_len, e| unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_mut_ptr().cast(),
                    len,
                    out_len,
                    e,
                    &mut finished,
                )
            },
        )?;
        self.finished = finished;
        Ok(AgreementStep { message, finished })
    }
    pub fn export_derived_by_password(&mut self, password: &Password) -> Result<PluginBuffer> {
        if !self.finished {
            return Err(super::error::Error::InvalidInput(
                "Cannot export a derived key before agreement finishes",
            ));
        }
        let f = symbol!(
            self.handle.plugin(),
            DiffieHellman_exportDerivedKeyMaterialByPass
        );
        output(
            &self.handle.parent,
            "DiffieHellman_exportDerivedKeyMaterialByPass",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), password.as_ptr(), len, e) },
        )
    }
}
