//! CFAPI callbacks serve authenticated ranges from the encrypted session baseline.
use super::{Archive, wide};
use anyhow::{Result, ensure};
use std::{ffi::OsStr, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::STATUS_CLOUD_FILE_UNSUCCESSFUL,
    Storage::{CloudFilters::*, FileSystem::*},
};

pub fn hr(code: i32) -> Result<()> {
    ensure!(code >= 0, "Cloud Files API HRESULT {code:#010x}");
    Ok(())
}

pub fn register(root: &Path, identity: &[u8; 16]) -> Result<()> {
    let name = wide(OsStr::new("Vault Lab"));
    let version = wide(OsStr::new(env!("CARGO_PKG_VERSION")));
    let registration = CF_SYNC_REGISTRATION {
        StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: name.as_ptr(),
        ProviderVersion: version.as_ptr(),
        SyncRootIdentity: identity.as_ptr().cast(),
        SyncRootIdentityLength: 16,
        ..Default::default()
    };
    let policies = CF_SYNC_POLICIES {
        StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_PARTIAL,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_ALWAYS_FULL,
            Modifier: 0,
        },
        ..Default::default()
    };
    hr(unsafe {
        CfRegisterSyncRoot(
            wide(root).as_ptr(),
            &registration,
            &policies,
            CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT,
        )
    })
}

pub fn unregister(root: &Path) -> Result<()> {
    let result = unsafe { CfUnregisterSyncRoot(wide(root).as_ptr()) };
    // Recovery may restart after successful unregistration and before directory removal.
    use windows_sys::Win32::Foundation::{
        ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT, ERROR_NOT_A_CLOUD_SYNC_ROOT,
    };
    if [
        ERROR_NOT_A_CLOUD_SYNC_ROOT,
        ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT,
    ]
    .iter()
    .any(|code| result as u32 == (0x80070000 | code))
    {
        return Ok(());
    }
    hr(result)
}

pub struct Connection<'a> {
    key: CF_CONNECTION_KEY,
    _archive: &'a Archive,
}

impl<'a> Connection<'a> {
    pub fn open(root: &Path, archive: &'a Archive) -> Result<Self> {
        let table = [
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NONE,
                Callback: None,
            },
        ];
        let mut key = 0;
        hr(unsafe {
            CfConnectSyncRoot(
                wide(root).as_ptr(),
                table.as_ptr(),
                ptr::from_ref(archive).cast(),
                CF_CONNECT_FLAG_NONE,
                &mut key,
            )
        })?;
        Ok(Self {
            key,
            _archive: archive,
        })
    }
}
impl Drop for Connection<'_> {
    fn drop(&mut self) {
        // All callbacks must have returned before the borrowed archive can be freed.
        if unsafe { CfDisconnectSyncRoot(self.key) } < 0 {
            std::process::abort();
        }
    }
}

pub fn placeholder(parent: &Path, name: &str, id: u64, size: u64, directory: bool) -> Result<()> {
    let name = wide(OsStr::new(name));
    let mut entry = CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: name.as_ptr(),
        FileIdentity: ptr::from_ref(&id).cast(),
        FileIdentityLength: 8,
        Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        ..Default::default()
    };
    entry.FsMetadata.FileSize = size.try_into()?;
    entry.FsMetadata.BasicInfo.FileAttributes = if directory {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if directory {
        entry.Flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
    }
    let mut count = 0;
    hr(unsafe {
        CfCreatePlaceholders(
            wide(parent).as_ptr(),
            &mut entry,
            1,
            CF_CREATE_FLAG_STOP_ON_ERROR,
            &mut count,
        )
    })?;
    hr(entry.Result)?;
    ensure!(count == 1, "Placeholder creation incomplete");
    Ok(())
}

unsafe extern "system" fn fetch(
    info: *const CF_CALLBACK_INFO,
    params: *const CF_CALLBACK_PARAMETERS,
) {
    // The platform owns these arguments for the duration of this callback.
    let (info, request) = unsafe { (&*info, (*params).Anonymous.FetchData) };
    let archive = unsafe { &*info.CallbackContext.cast::<Archive>() };
    let offset = request.RequiredFileOffset;
    let length = if request.RequiredLength == -1 {
        info.FileSize - offset
    } else {
        request.RequiredLength
    };
    let transfer = |offset, length, buffer, status| {
        let op = CF_OPERATION_INFO {
            StructSize: size_of::<CF_OPERATION_INFO>() as u32,
            Type: CF_OPERATION_TYPE_TRANSFER_DATA,
            ConnectionKey: info.ConnectionKey,
            TransferKey: info.TransferKey,
            RequestKey: info.RequestKey,
            CorrelationVector: info.CorrelationVector,
            ..Default::default()
        };
        let mut args = CF_OPERATION_PARAMETERS {
            ParamSize: (std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
                + size_of::<CF_OPERATION_PARAMETERS_0_0>()) as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferData: CF_OPERATION_PARAMETERS_0_0 {
                    Flags: 0,
                    CompletionStatus: status,
                    Buffer: buffer,
                    Offset: offset,
                    Length: length,
                },
            },
        };
        hr(unsafe { CfExecute(&op, &mut args) })
    };
    let result = (|| -> Result<()> {
        ensure!(
            info.FileIdentityLength == 8 && !info.FileIdentity.is_null(),
            "Bad placeholder identity"
        );
        let id = unsafe { info.FileIdentity.cast::<u64>().read_unaligned() };
        ensure!(offset >= 0 && length > 0, "Invalid fetch range");
        archive.read_range(id, offset as u64, length as u64, |pos, bytes| {
            transfer(pos as i64, bytes.len() as i64, bytes.as_ptr().cast(), 0)
        })
    })();
    if let Err(error) = result {
        eprintln!("CFAPI read: {error:#}");
        let _ = transfer(offset, length, ptr::null(), STATUS_CLOUD_FILE_UNSUCCESSFUL);
    }
}
