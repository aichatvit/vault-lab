use super::{error::Error, error::Result, internal::length, raw};
use zeroize::{Zeroize, Zeroizing};

/// Строка платформы с завершающим NUL; собственное хранилище пароля обнуляется при удалении.
/// На Windows используется UTF-16, на Linux — UTF-8. Внутренние NUL запрещены.
pub struct Password(Zeroizing<Vec<raw::mchar>>);
impl Password {
    pub fn new(value: &str) -> Result<Self> {
        if value.contains('\0') {
            return Err(Error::InvalidInput("Password contains an interior NUL"));
        }
        #[cfg(windows)]
        let mut chars: Vec<raw::mchar> = value.encode_utf16().collect();
        #[cfg(not(windows))]
        let mut chars: Vec<raw::mchar> = value.bytes().map(|c| c as raw::mchar).collect();
        length(chars.len())?;
        chars.push(0);
        Ok(Self(Zeroizing::new(chars)))
    }
    pub(super) fn as_ptr(&self) -> *const raw::mchar {
        self.0.as_ptr()
    }
    pub(super) fn len(&self) -> u32 {
        (self.0.len() - 1) as u32
    }
}

// Предоставляем вызывающему коду реализацию Zeroize без раскрытия
// внутренностей пароля и без реализации Debug для секретных данных.
impl Zeroize for Password {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
        self.0.truncate(1); // Сохраняем корректную пустую строку с завершающим NUL.
    }
}
