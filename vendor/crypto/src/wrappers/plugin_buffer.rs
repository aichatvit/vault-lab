use super::base_crypt::ContextInner;
use super::{error::Error, error::Result, internal::checked};
use std::{ffi::c_void, ops::Deref, ptr::NonNull, rc::Rc};

/// Буфер памяти плагина, освобождаемый без аллокатора Rust. Реализация Debug
/// намеренно отсутствует: буфер может содержать секретный ключевой материал.
pub struct PluginBuffer {
    parent: Rc<ContextInner>,
    ptr: NonNull<c_void>,
    len: u32,
}
impl Deref for PluginBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast(), self.len as usize) }
    }
}
impl AsRef<[u8]> for PluginBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl Drop for PluginBuffer {
    fn drop(&mut self) {
        unsafe {
            (self.parent.free)(self.parent.ptr.as_ptr(), self.ptr.as_ptr(), self.len);
        }
    }
}
pub(super) fn output(
    parent: &Rc<ContextInner>,
    operation: &'static str,
    call: impl FnOnce(*mut u32, *mut i32) -> *mut c_void,
) -> Result<PluginBuffer> {
    output_optional(parent, operation, call)?
        .ok_or(Error::InvalidOutput("Plugin returned no output allocation"))
}
pub(super) fn output_optional(
    parent: &Rc<ContextInner>,
    operation: &'static str,
    call: impl FnOnce(*mut u32, *mut i32) -> *mut c_void,
) -> Result<Option<PluginBuffer>> {
    let mut len = 0;
    let mut error = 0;
    let ptr = call(&mut len, &mut error);
    let Some(ptr) = NonNull::new(ptr) else {
        checked(true, error, operation)?;
        return if len == 0 {
            Ok(None)
        } else {
            Err(Error::InvalidOutput(
                "Plugin returned null with a nonzero length",
            ))
        };
    };
    let buffer = PluginBuffer {
        parent: parent.clone(),
        ptr,
        len,
    };
    checked(true, error, operation)?;
    if len as usize > isize::MAX as usize {
        return Err(Error::InvalidOutput("Plugin allocation exceeds isize::MAX"));
    }
    Ok(Some(buffer))
}
