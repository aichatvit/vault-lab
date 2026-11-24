//! Отдельная тестовая библиотека, собираемая ownership.rs через rustc.
//! Реализует часть ABI для наблюдения за владением и имитации ошибок.
use std::{ffi::c_void, sync::atomic::{AtomicI32, AtomicU32, Ordering::SeqCst}};

static PARENTS: AtomicU32 = AtomicU32::new(0);
static CHILDREN: AtomicU32 = AtomicU32::new(0);
static BUFFERS: AtomicU32 = AtomicU32::new(0);
static BAD_ORDER: AtomicU32 = AtomicU32::new(0);
static FAILURE: AtomicI32 = AtomicI32::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn fixture_failure(value: i32) { FAILURE.store(value, SeqCst); }
#[unsafe(no_mangle)]
pub extern "C" fn fixture_state() -> u32 {
    PARENTS.load(SeqCst) | CHILDREN.load(SeqCst) << 8 | BUFFERS.load(SeqCst) << 16 | BAD_ORDER.load(SeqCst) << 24
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn createCryptoContextByParams(_: *const c_void, error: *mut i32) -> *mut c_void {
    unsafe { *error = 0; }
    PARENTS.fetch_add(1, SeqCst);
    Box::into_raw(Box::new(1u8)).cast()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn destroyCryptoContext(ptr: *mut c_void) -> bool {
    if CHILDREN.load(SeqCst) != 0 || BUFFERS.load(SeqCst) != 0 { BAD_ORDER.store(1, SeqCst); }
    unsafe { drop(Box::from_raw(ptr.cast::<u8>())); }
    PARENTS.fetch_sub(1, SeqCst); true
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn destroyMemory(_: *mut c_void, ptr: *mut c_void, len: u32) -> bool {
    if PARENTS.load(SeqCst) == 0 { BAD_ORDER.store(1, SeqCst); }
    unsafe { drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), len as usize))); }
    BUFFERS.fetch_sub(1, SeqCst); true
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn createHashInst(_: *mut c_void, _: i32, _: i32, error: *mut i32) -> *mut c_void {
    unsafe { *error = FAILURE.load(SeqCst); }
    CHILDREN.fetch_add(1, SeqCst); Box::into_raw(Box::new(2u8)).cast()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deleteHashInst(_: *mut c_void, ptr: *mut c_void) -> bool {
    if PARENTS.load(SeqCst) == 0 { BAD_ORDER.store(1, SeqCst); }
    unsafe { drop(Box::from_raw(ptr.cast::<u8>())); }
    CHILDREN.fetch_sub(1, SeqCst); true
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sym_createSymAlgInstance(parent: *mut c_void, alg: i32, mode: i32, error: *mut i32) -> *mut c_void {
    unsafe { createHashInst(parent, alg, mode, error) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sym_deleteInst(parent: *mut c_void, ptr: *mut c_void) -> bool {
    unsafe { deleteHashInst(parent, ptr) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sym_getKey(_: *mut c_void, len: *mut u32, error: *mut i32) -> *mut c_void {
    unsafe { *len = 4; *error = FAILURE.load(SeqCst); }
    BUFFERS.fetch_add(1, SeqCst);
    Box::into_raw(vec![11u8, 22, 33, 44].into_boxed_slice()).cast::<u8>().cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn DiffieHellman_createDiffHellInst(parent: *mut c_void, alg: i32, error: *mut i32) -> *mut c_void {
    unsafe { createHashInst(parent, alg, 0, error) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DiffieHellman_deleteDiffHellInst(parent: *mut c_void, ptr: *mut c_void) -> bool {
    unsafe { deleteHashInst(parent, ptr) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DiffieHellman_deriveKeyMaterial(ctx: *mut c_void, _: *mut c_void, _: u32, len: *mut u32, error: *mut i32, finished: *mut bool) -> *mut c_void {
    unsafe { *finished = true; sym_getKey(ctx, len, error) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DiffieHellman_exportDerivedKeyMaterialByPass(ctx: *mut c_void, _: *const c_void, len: *mut u32, error: *mut i32) -> *mut c_void {
    unsafe { sym_getKey(ctx, len, error) }
}
