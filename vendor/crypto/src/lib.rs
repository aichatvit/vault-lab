//! Низкоуровневые привязки к экспортируемому C-интерфейсу криптоплагина.
//!
//! Вызовы низкоуровневого API требуют unsafe: вызывающий код должен соблюдать правила
//! заголовков по работе с буферами, времени жизни контекстов, владению и синхронизации.
//! Крейт не содержит реализаций криптографических алгоритмов.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::all, unsafe_op_in_unsafe_fn)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod wrappers;

impl CryptoPlugin {
    /// Проверить минимальный API создания контекста и освобождения его ресурсов.
    /// Перед вызовом дополнительной функции проверьте её поле типа `Result`.
    pub fn check_core_api(&self) -> Result<(), &'static str> {
        self.createCryptoContext
            .as_ref()
            .map_err(|_| "createCryptoContext")?;
        self.destroyCryptoContext
            .as_ref()
            .map_err(|_| "destroyCryptoContext")?;
        self.destroyMemory.as_ref().map_err(|_| "destroyMemory")?;
        Ok(())
    }
}
