use super::{
    base_crypt::BaseCrypt, error::Error, error::Result, internal::length,
    plugin_buffer::PluginBuffer, plugin_buffer::output, raw, symbol,
};
use std::{ffi::c_void, ptr::NonNull};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerProperty {
    PublicKey,
    Guid,
    ExpirationPeriod,
}
impl ContainerProperty {
    fn id(self) -> u32 {
        match self {
            Self::PublicKey => raw::KeyContainerData_keyPublicData,
            Self::Guid => raw::KeyContainerData_guid,
            Self::ExpirationPeriod => raw::KeyContainerData_expTimePeriod,
        }
    }
}
pub struct KeyContainer {
    parent: BaseCrypt,
    ptr: NonNull<c_void>,
    delete: unsafe extern "C" fn(*mut c_void, u32) -> i32,
    // Сохраняем исходные байты на случай, если анализатор заимствует из них данные.
    _bytes: Vec<u8>,
}
impl KeyContainer {
    pub fn from_bytes(parent: &BaseCrypt, bytes: &[u8]) -> Result<Self> {
        let p = parent.0.plugin();
        let create = symbol!(p, KcF_FromBytes);
        let delete = symbol!(p, KcF_DeleteContainer);
        let bytes = bytes.to_vec();
        let len = length(bytes.len())?;
        let mut ptr = std::ptr::null_mut();
        let code = unsafe {
            create(
                parent.0.ptr.as_ptr(),
                raw::KeyContainerType_kkp as u32,
                bytes.as_ptr().cast(),
                len,
                &mut ptr,
            )
        };
        if code != 0 || ptr.is_null() {
            if !ptr.is_null() {
                unsafe {
                    delete(ptr, raw::KeyContainerType_kkp as u32);
                }
            }
            return Err(Error::Native {
                operation: "KcF_FromBytes",
                code,
            });
        }
        Ok(Self {
            parent: parent.clone(),
            ptr: NonNull::new(ptr).unwrap(),
            delete,
            _bytes: bytes,
        })
    }
    pub fn property(&self, property: ContainerProperty) -> Result<PluginBuffer> {
        let f = symbol!(self.parent.0.plugin(), KcF_GetPublicParam);
        output(&self.parent.0, "KcF_GetPublicParam", |len, error| {
            let mut ptr = std::ptr::null_mut();
            unsafe {
                *error = f(
                    self.ptr.as_ptr(),
                    raw::KeyContainerType_kkp as u32,
                    property.id(),
                    &mut ptr,
                    len,
                );
            }
            ptr
        })
    }
    /// Байты GUID плагина без преобразования в строку или изменения порядка байтов.
    pub fn guid(&self) -> Result<[u8; 16]> {
        self.property(ContainerProperty::Guid)?
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidOutput("GUID property must contain 16 bytes"))
    }
    /// Знаковое значение time_t; единицы измерения и смысл задаёт плагин.
    pub fn expiration_period(&self) -> Result<i64> {
        let bytes = self.property(ContainerProperty::ExpirationPeriod)?;
        match bytes.len() {
            8 => Ok(i64::from_ne_bytes(bytes.as_ref().try_into().unwrap())),
            4 => Ok(i32::from_ne_bytes(bytes.as_ref().try_into().unwrap()) as i64),
            _ => Err(Error::InvalidOutput("Unexpected time_t property length")),
        }
    }
}
impl Drop for KeyContainer {
    fn drop(&mut self) {
        unsafe {
            (self.delete)(self.ptr.as_ptr(), raw::KeyContainerType_kkp as u32);
        }
    }
}
