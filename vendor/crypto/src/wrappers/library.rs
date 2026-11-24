use super::{error::Error, error::Result, raw};
use std::{path::Path, rc::Rc};

/// Загруженная библиотека. Копии совместно владеют дескриптором и не передаются между потоками.
#[derive(Clone)]
pub struct Library(pub(super) Rc<raw::CryptoPlugin>);
impl Library {
    /// Загрузить плагин по абсолютному пути.
    ///
    /// # Безопасность
    /// Библиотека и её зависимости должны быть доверенными и соблюдать указанные
    /// в заголовках ABI, границы буферов, правила выделения памяти и владения.
    #[expect(
        clippy::missing_safety_doc,
        reason = "Требования безопасности описаны в русскоязычном разделе «Безопасность»."
    )]
    pub unsafe fn load(path: impl AsRef<Path>) -> Result<Self> {
        if !path.as_ref().is_absolute() {
            return Err(Error::InvalidInput("Plugin path must be absolute"));
        }
        // БЕЗОПАСНОСТЬ: вызывающий код гарантирует доверенность библиотеки и её ABI.
        let plugin = unsafe { raw::CryptoPlugin::new(path.as_ref()) }
            .map_err(|e| Error::Load(e.to_string()))?;
        Ok(Self(Rc::new(plugin)))
    }
}
