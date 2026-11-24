use super::{error::Error, error::Result, internal::checked, library::Library, raw, symbol};
use std::{ffi::c_void, ops::Deref, ptr::NonNull, rc::Rc};

/// Перечисление C++ хранит позиции битов, а не битовые маски.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BioRandFlags {
    pub save_time: bool,
}
impl BioRandFlags {
    fn bits(self) -> i32 {
        if self.save_time {
            1 << raw::BioRandKBFlags_saveTime
        } else {
            0
        }
    }
}

struct BioInner {
    library: Library,
    ptr: NonNull<c_void>,
    flags: BioRandFlags,
    destroy: unsafe extern "C" fn(*mut c_void, i32) -> bool,
    free: unsafe extern "C" fn(*mut c_void, *mut c_void, u32) -> bool,
}
impl Drop for BioInner {
    fn drop(&mut self) {
        unsafe {
            (self.destroy)(self.ptr.as_ptr(), self.flags.bits());
        }
    }
}
pub struct BioRandKb {
    inner: Rc<BioInner>,
}
pub struct SymbolTiming {
    pub accepted: bool,
    pub time: u64,
}
pub struct BioBuffer {
    owner: Rc<BioInner>,
    ptr: NonNull<c_void>,
    len: u32,
}
impl Deref for BioBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast(), self.len as usize) }
    }
}
impl AsRef<[u8]> for BioBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl Drop for BioBuffer {
    fn drop(&mut self) {
        unsafe {
            (self.owner.free)(self.owner.ptr.as_ptr(), self.ptr.as_ptr(), self.len);
        }
    }
}
impl BioRandKb {
    pub fn new(library: &Library, flags: BioRandFlags) -> Result<Self> {
        let p = &library.0;
        let create = symbol!(p, BRa_kb_createContext);
        let destroy = symbol!(p, BRa_kb_destroyContext);
        let free = symbol!(p, BRa_kb_destroyMemory);
        let mut error = 0;
        let ptr = unsafe { create(flags.bits(), &mut error) };
        if ptr.is_null() || error != 0 {
            if !ptr.is_null() {
                unsafe {
                    destroy(ptr, flags.bits());
                }
            }
            return Err(Error::Native {
                operation: "BRa_kb_createContext",
                code: error,
            });
        }
        Ok(Self {
            inner: Rc::new(BioInner {
                library: library.clone(),
                ptr: NonNull::new(ptr).unwrap(),
                flags,
                destroy,
                free,
            }),
        })
    }
    pub fn generate_symbol(&mut self, flags: BioRandFlags) -> Result<raw::mchar> {
        let f = symbol!(self.inner.library.0, BRa_kb_genSymbol);
        let mut error = 0;
        let value = unsafe { f(self.inner.ptr.as_ptr(), flags.bits(), &mut error) };
        checked(true, error, "BRa_kb_genSymbol")?;
        Ok(value)
    }
    pub fn add_symbol(&mut self, symbol: raw::mchar, flags: BioRandFlags) -> Result<SymbolTiming> {
        let f = symbol!(self.inner.library.0, BRa_kb_addSymbolWithTimeCheck);
        let mut error = 0;
        let mut time = 0;
        let accepted = unsafe {
            f(
                self.inner.ptr.as_ptr(),
                flags.bits(),
                symbol,
                &mut time,
                &mut error,
            )
        };
        checked(true, error, "BRa_kb_addSymbolWithTimeCheck")?;
        Ok(SymbolTiming { accepted, time })
    }
    pub fn generate_result(&mut self, flags: BioRandFlags) -> Result<BioBuffer> {
        let f = symbol!(self.inner.library.0, BRa_kb_genResult);
        let mut len = 0;
        let mut error = 0;
        let ptr = unsafe { f(self.inner.ptr.as_ptr(), flags.bits(), &mut len, &mut error) };
        let Some(ptr) = NonNull::new(ptr) else {
            return Err(Error::Native {
                operation: "BRa_kb_genResult",
                code: error,
            });
        };
        let buffer = BioBuffer {
            owner: self.inner.clone(),
            ptr,
            len,
        };
        checked(true, error, "BRa_kb_genResult")?;
        if len as usize > isize::MAX as usize {
            return Err(Error::InvalidOutput("Bio allocation exceeds isize::MAX"));
        }
        Ok(buffer)
    }
}
