use super::{error::Error, error::Result};
use zeroize::Zeroizing;

pub(super) fn length(value: usize) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| Error::InvalidInput("Buffer exceeds the plugin's u32 length limit"))
}
pub(super) fn checked(ok: bool, code: i32, operation: &'static str) -> Result<()> {
    if ok && code == 0 {
        Ok(())
    } else {
        Err(Error::Native { operation, code })
    }
}

/// Временная копия буфера Rust с обнулением перед освобождением.
pub(super) fn secret_copy(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes.to_vec())
}
