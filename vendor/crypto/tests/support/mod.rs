use crypto::CryptoPlugin;
use std::{ffi::c_void, path::PathBuf};

pub fn load() -> CryptoPlugin {
    let path = PathBuf::from(
        std::env::var_os("ALDCRYPTO_LIBRARY")
            .expect("Set ALDCRYPTO_LIBRARY to the absolute path of a trusted plugin"),
    );
    assert!(path.is_absolute(), "ALDCRYPTO_LIBRARY must be absolute");
    // БЕЗОПАСНОСТЬ: явный запуск тестов подразумевает доверие ABI переданного плагина.
    let plugin = unsafe { CryptoPlugin::new(&path) }
        .unwrap_or_else(|error| panic!("Cannot load {}: {error}", path.display()));
    plugin.check_core_api().expect("Missing core export");
    plugin
}

pub struct Context {
    pub plugin: CryptoPlugin,
    pub ptr: *mut c_void,
}

impl Context {
    pub fn new() -> Self {
        let plugin = load();
        let mut seed = [0u8; 64];
        let mut error = 0;
        let mut ptr = std::ptr::null_mut();
        // Эта библиотека иногда возвращает initCryptoBySeq для случайной последовательности ОС.
        // Повторяем только эту ошибку с новой энтропией; внутренняя причина неизвестна.
        for _ in 0..16 {
            getrandom::fill(&mut seed).expect("OS randomness");
            error = 0;
            // БЕЗОПАСНОСТЬ: буфер и указатель ошибки корректны; библиотека остаётся загруженной.
            ptr = unsafe {
                plugin.createCryptoContext(seed.as_ptr().cast(), seed.len() as u32, &mut error)
            };
            if !ptr.is_null() || error != crypto::SharedErrors_Errors_initCryptoBySeq {
                break;
            }
            eprintln!("Plugin rejected initialization seed (17); drawing fresh OS entropy");
        }
        assert!(!ptr.is_null(), "createCryptoContext: {error}");
        assert_eq!(error, 0);
        Self { plugin, ptr }
    }

    pub fn child(
        &self,
        ptr: *mut c_void,
        delete: unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool,
    ) -> Child<'_> {
        assert!(!ptr.is_null(), "Child context creation failed");
        Child {
            owner: self,
            ptr,
            delete,
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // БЕЗОПАСНОСТЬ: родитель существует в одном экземпляре; заимствовавшие его дети уже удалены.
        let ok = unsafe { self.plugin.destroyCryptoContext(self.ptr) };
        if !std::thread::panicking() {
            assert!(ok, "destroyCryptoContext failed");
        }
    }
}

pub struct Child<'a> {
    owner: &'a Context,
    pub ptr: *mut c_void,
    delete: unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool,
}

impl Drop for Child<'_> {
    fn drop(&mut self) {
        // БЕЗОПАСНОСТЬ: деструктор соответствует объекту; родитель и библиотека ещё существуют.
        let ok = unsafe { (self.delete)(self.owner.ptr, self.ptr) };
        if !std::thread::panicking() {
            assert!(ok, "Child destructor failed");
        }
    }
}

pub fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
