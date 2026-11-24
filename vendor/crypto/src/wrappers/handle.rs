use super::base_crypt::ContextInner;
use super::{base_crypt::BaseCrypt, error::Error, error::Result, raw};
use std::{ffi::c_void, ptr::NonNull, rc::Rc};

pub(super) type DeleteChild = unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;
pub(super) struct Handle {
    pub parent: Rc<ContextInner>,
    pub ptr: NonNull<c_void>,
    delete: DeleteChild,
}
impl Handle {
    pub fn new(
        parent: &BaseCrypt,
        delete: DeleteChild,
        operation: &'static str,
        create: impl FnOnce(*mut i32) -> *mut c_void,
    ) -> Result<Self> {
        let mut error = 0;
        let ptr = create(&mut error);
        if ptr.is_null() || error != 0 {
            if !ptr.is_null() {
                unsafe {
                    delete(parent.0.ptr.as_ptr(), ptr);
                }
            }
            return Err(Error::Native {
                operation,
                code: error,
            });
        }
        Ok(Self {
            parent: parent.0.clone(),
            ptr: NonNull::new(ptr).unwrap(),
            delete,
        })
    }
    pub fn plugin(&self) -> &raw::CryptoPlugin {
        self.parent.plugin()
    }
    pub fn same_parent(&self, other: &Handle) -> Result<()> {
        if Rc::ptr_eq(&self.parent, &other.parent) {
            Ok(())
        } else {
            Err(Error::InvalidInput(
                "Handles belong to different base contexts",
            ))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            (self.delete)(self.parent.ptr.as_ptr(), self.ptr.as_ptr());
        }
    }
}
