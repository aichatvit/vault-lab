use super::{
    base_crypt::BaseCrypt, error::Error, error::Result, handle::Handle, internal::checked,
    internal::length, password::Password, plugin_buffer::PluginBuffer, plugin_buffer::output, raw,
    symbol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SymmetricMode {
    Ecb = 0,
    Cbc = 1,
    Omac = 2,
    Cfb = 3,
}

pub struct Symmetric {
    pub(super) handle: Handle,
    mode: Option<SymmetricMode>,
}
impl Symmetric {
    pub fn new(parent: &BaseCrypt, mode: SymmetricMode) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, sym_createSymAlgInstance);
        let delete = symbol!(p, sym_deleteInst);
        let handle = Handle::new(parent, delete, "sym_createSymAlgInstance", |e| unsafe {
            create(
                parent.0.ptr.as_ptr(),
                raw::SymmAlgDef_Gost_34_12,
                mode as i32,
                e,
            )
        })?;
        Ok(Self {
            handle,
            mode: Some(mode),
        })
    }
    /// Контекст, полученный из пароля; алгоритм и режим выбирает плагин.
    pub fn from_password(parent: &BaseCrypt, password: &[u8], salt: &[u8]) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, sym_createSymAlgInstance_pass);
        let delete = symbol!(p, sym_deleteInst);
        let pass_len = length(password.len())?;
        let salt_len = length(salt.len())?;
        let handle = Handle::new(
            parent,
            delete,
            "sym_createSymAlgInstance_pass",
            |e| unsafe {
                create(
                    parent.0.ptr.as_ptr(),
                    password.as_ptr().cast(),
                    pass_len,
                    salt.as_ptr(),
                    salt_len,
                    e,
                )
            },
        )?;
        // ABI этой функции не раскрывает режим. Доступны только операции с ключами
        // и контейнерами до явного выбора режима шифрования вызывающим кодом.
        Ok(Self { handle, mode: None })
    }
    pub fn data(&self) -> Result<raw::SymmAlgData> {
        let f = symbol!(self.handle.plugin(), sym_getData);
        let mut out = raw::SymmAlgData::default();
        let mut error = 0;
        checked(
            unsafe { f(self.handle.ptr.as_ptr(), &mut out, &mut error) },
            error,
            "sym_getData",
        )?;
        Ok(out)
    }
    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        let f = symbol!(self.handle.plugin(), sym_setKey);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    key.as_ptr(),
                    length(key.len())?,
                    &mut error,
                )
            },
            error,
            "sym_setKey",
        )
    }
    pub fn key(&self) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), sym_getKey);
        output(&self.handle.parent, "sym_getKey", |len, e| unsafe {
            f(self.handle.ptr.as_ptr(), len, e)
        })
    }
    pub fn encrypt(&mut self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        self.crypt(data, iv, true)
    }
    pub fn decrypt(&mut self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        self.crypt(data, iv, false)
    }
    fn crypt(&mut self, data: &[u8], iv: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        let mode = self.mode.ok_or(Error::InvalidInput("Password-derived factory does not expose its cipher mode; use key/container operations"))?;
        let meta = self.data()?;
        if meta.blockSize == 0 || meta.blockSize > 1024 {
            return Err(Error::InvalidOutput("Invalid cipher block size"));
        }
        if iv.len() != meta.ivSize as usize {
            return Err(Error::InvalidInput(
                "IV length does not match the cipher context",
            ));
        }
        if data.is_empty()
            || (mode != SymmetricMode::Omac && !data.len().is_multiple_of(meta.blockSize as usize))
        {
            return Err(Error::InvalidInput(
                "Cipher input must contain whole nonempty blocks; no implicit padding is added",
            ));
        }
        if !encrypt && mode == SymmetricMode::Omac {
            return Err(Error::InvalidInput("OMAC does not support decryption"));
        }
        let out_len = if mode == SymmetricMode::Omac {
            meta.blockSize as usize
        } else {
            data.len()
        };
        let mut out = vec![0; out_len];
        let mut error = 0;
        let f = if encrypt {
            symbol!(self.handle.plugin(), sym_encrypt)
        } else {
            symbol!(self.handle.plugin(), sym_decrypt)
        };
        let iv_ptr = if iv.is_empty() {
            std::ptr::null()
        } else {
            iv.as_ptr()
        };
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    data.as_ptr(),
                    length(data.len())?,
                    out.as_mut_ptr(),
                    length(out.len())?,
                    iv_ptr,
                    length(iv.len())?,
                    &mut error,
                )
            },
            error,
            if encrypt {
                "sym_encrypt"
            } else {
                "sym_decrypt"
            },
        )?;
        Ok(out)
    }
    pub fn export_by_password(&mut self, password: &Password) -> Result<PluginBuffer> {
        let f = symbol!(self.handle.plugin(), sym_exportKeyByPass);
        output(
            &self.handle.parent,
            "sym_exportKeyByPass",
            |len, e| unsafe { f(self.handle.ptr.as_ptr(), password.as_ptr(), len, e) },
        )
    }
    pub fn import_by_password(&mut self, container: &[u8], password: &Password) -> Result<()> {
        let f = symbol!(self.handle.plugin(), sym_importKeyByPass);
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
            "sym_importKeyByPass",
        )
    }
    pub fn export_by_sym_key(&mut self, protector: &mut Symmetric) -> Result<PluginBuffer> {
        self.handle.same_parent(&protector.handle)?;
        let f = symbol!(self.handle.plugin(), sym_exportKeyBySymAlg);
        output(
            &self.handle.parent,
            "sym_exportKeyBySymAlg",
            |len, e| unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    protector.handle.ptr.as_ptr(),
                    len,
                    e,
                )
            },
        )
    }
    pub fn import_by_sym_key(&mut self, container: &[u8], protector: &mut Symmetric) -> Result<()> {
        self.handle.same_parent(&protector.handle)?;
        let f = symbol!(self.handle.plugin(), sym_importKeyBySymAlg);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    protector.handle.ptr.as_ptr(),
                    container.as_ptr(),
                    length(container.len())?,
                    &mut error,
                )
            },
            error,
            "sym_importKeyBySymAlg",
        )
    }
    pub fn export_by_asymmetric(
        &mut self,
        protector: &mut super::asymmetric::Asymmetric,
    ) -> Result<PluginBuffer> {
        self.handle.same_parent(&protector.handle)?;
        let f = symbol!(self.handle.plugin(), sym_exportKeyByAssymetricEncrypter);
        output(
            &self.handle.parent,
            "sym_exportKeyByAssymetricEncrypter",
            |len, e| unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    protector.handle.ptr.as_ptr(),
                    len,
                    e,
                )
            },
        )
    }
    pub fn import_by_asymmetric(
        &mut self,
        container: &[u8],
        protector: &mut super::asymmetric::Asymmetric,
    ) -> Result<()> {
        self.handle.same_parent(&protector.handle)?;
        let f = symbol!(self.handle.plugin(), sym_importKeyByAssymetricEncrypter);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.handle.ptr.as_ptr(),
                    protector.handle.ptr.as_ptr(),
                    container.as_ptr(),
                    length(container.len())?,
                    &mut error,
                )
            },
            error,
            "sym_importKeyByAssymetricEncrypter",
        )
    }
}
