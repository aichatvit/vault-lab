//! Rust-аналоги `Wrappers/CryptoWrappers` с управлением ресурсами.
//!
//! Загрузите доверенную библиотеку с совместимым ABI через [`library::Library::load`].
//! Остальные операции безопасны, принимают срезы и возвращают ошибки через [`error::Error`].
//! Дескрипторы и буферы удерживают свои контексты и библиотеку. Они намеренно
//! не реализуют Send и Sync; работайте с графом контекстов библиотеки в одном потоке.
//! Ошибки деструкторов плагина не могут быть возвращены из Drop и игнорируются.
#![doc = include_str!("README.md")]
#![warn(clippy::all)]
#![deny(unsafe_op_in_unsafe_fn)]
pub mod asymmetric;
pub mod base_crypt;
pub mod bio_rand_kb;
pub mod crypto_init_by_cont;
pub mod crypto_init_by_seq;
pub mod crypto_init_by_sign_seq;
pub mod diffie_hellman;
pub mod digest_length;
pub mod error;
mod handle;
pub mod hash;
pub mod hmac;
pub mod init_method_type;
pub mod init_params;
mod internal;
pub mod kdf_tree;
pub mod key_container;
pub mod library;
pub mod password;
pub mod plugin_buffer;
pub mod random;
pub mod sequence_checker;
pub mod signanture;
pub mod symmetric;

use crate as raw;

macro_rules! symbol {
    ($plugin:expr, $name:ident) => {
        *$plugin
            .$name
            .as_ref()
            .map_err(|_| $crate::wrappers::error::Error::MissingSymbol(stringify!($name)))?
    };
}
pub(crate) use symbol;
