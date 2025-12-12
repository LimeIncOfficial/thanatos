//! Hypervisor and security feature detection module.
//!
//! This module detects the presence of:
//! - Virtualization-Based Security (VBS)
//! - Hypervisor-protected Code Integrity (HVCI)
//! - Credential Guard
//! - Common hypervisors (Hyper-V, VMware, VirtualBox, etc.)
//!
//! Detection allows the agent to adjust behavior or exit if running
//! in a hardened security environment.
//!
//! Detectable telemetry generated:
//! - CPUID instruction execution
//! - Registry queries to security-related keys
//! - WMI queries for virtualization info

#![cfg(target_os = "windows")]

use std::arch::asm;

/// Security environment information
#[derive(Debug, Clone, Default)]
pub struct SecurityEnvironment {
    /// Whether running under any hypervisor
    pub hypervisor_present: bool,
    /// Detected hypervisor vendor (if any)
    pub hypervisor_vendor: Option<String>,
    /// VBS (Virtualization-Based Security) enabled
    pub vbs_enabled: bool,
    /// HVCI (Hypervisor-protected Code Integrity) enabled
    pub hvci_enabled: bool,
    /// Credential Guard enabled
    pub credential_guard_enabled: bool,
    /// Running in a VM
    pub is_virtual_machine: bool,
    /// Secure Boot enabled
    pub secure_boot_enabled: bool,
}

impl SecurityEnvironment {
    /// Check if the environment is considered "hardened"
    /// and may require adjusted behavior
    pub fn is_hardened(&self) -> bool {
        self.hvci_enabled || self.credential_guard_enabled || self.vbs_enabled
    }

    /// Check if running in any virtualized environment
    pub fn is_virtualized(&self) -> bool {
        self.hypervisor_present || self.is_virtual_machine
    }
}

/// Detect the security environment
pub fn detect_security_environment() -> SecurityEnvironment {
    let mut env = SecurityEnvironment::default();

    // Check for hypervisor using CPUID
    env.hypervisor_present = check_hypervisor_present();

    if env.hypervisor_present {
        env.hypervisor_vendor = get_hypervisor_vendor();
    }

    // Check for VM indicators
    env.is_virtual_machine = detect_virtual_machine();

    // Check VBS/HVCI status via registry
    #[cfg(target_arch = "x86_64")]
    {
        env.vbs_enabled = check_vbs_enabled();
        env.hvci_enabled = check_hvci_enabled();
        env.credential_guard_enabled = check_credential_guard();
        env.secure_boot_enabled = check_secure_boot();
    }

    env
}

/// Check if a hypervisor is present using CPUID
///
/// CPUID with EAX=1 returns hypervisor present bit in ECX bit 31
fn check_hypervisor_present() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ecx: u32;
        asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            out("eax") _,
            out("ebx") _,
            out("edx") _,
            options(nostack, nomem),
        );
        (ecx & (1 << 31)) != 0
    }

    #[cfg(not(target_arch = "x86_64"))]
    false
}

/// Get hypervisor vendor string using CPUID
///
/// CPUID with EAX=0x40000000 returns hypervisor vendor ID
fn get_hypervisor_vendor() -> Option<String> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ebx: u32;
        let ecx: u32;
        let edx: u32;

        asm!(
            "mov eax, 0x40000000",
            "cpuid",
            out("ebx") ebx,
            out("ecx") ecx,
            out("edx") edx,
            out("eax") _,
            options(nostack, nomem),
        );

        // Convert registers to string
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&ecx.to_le_bytes());
        vendor[8..12].copy_from_slice(&edx.to_le_bytes());

        let vendor_str = String::from_utf8_lossy(&vendor)
            .trim_end_matches('\0')
            .to_string();

        if vendor_str.is_empty() {
            None
        } else {
            Some(match vendor_str.as_str() {
                "Microsoft Hv" => "Hyper-V".to_string(),
                "VMwareVMware" => "VMware".to_string(),
                "VBoxVBoxVBox" => "VirtualBox".to_string(),
                "KVMKVMKVM\0\0\0" | "KVMKVMKVM" => "KVM".to_string(),
                "XenVMMXenVMM" => "Xen".to_string(),
                "prl hyperv  " | "prl hyperv" => "Parallels".to_string(),
                _ => vendor_str,
            })
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    None
}

/// Detect if running in a virtual machine using various indicators
fn detect_virtual_machine() -> bool {
    // Check MAC address prefixes for known VM vendors
    if check_vm_mac_address() {
        return true;
    }

    // Check for VM-specific registry keys
    if check_vm_registry_keys() {
        return true;
    }

    // Check for VM-specific processes
    if check_vm_processes() {
        return true;
    }

    false
}

/// Check MAC address for VM vendor prefixes
fn check_vm_mac_address() -> bool {
    // VM MAC address OUI prefixes
    let vm_prefixes: &[&[u8]] = &[
        &[0x00, 0x0C, 0x29], // VMware
        &[0x00, 0x50, 0x56], // VMware
        &[0x08, 0x00, 0x27], // VirtualBox
        &[0x00, 0x1C, 0x14], // VMware
        &[0x00, 0x15, 0x5D], // Hyper-V
        &[0x00, 0x03, 0xFF], // Microsoft Virtual PC
    ];

    // This would require network interface enumeration
    // For simplicity, we'll rely on other detection methods
    false
}

/// Check for VM-specific registry keys
fn check_vm_registry_keys() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::shared::minwindef::HKEY;
    use std::ptr::null_mut;

    unsafe {
        let mut hkey: HKEY = null_mut();

        // Check for VMware
        let vmware_key = obfstr::obfstr!("SOFTWARE\\VMware, Inc.\\VMware Tools\0");
        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            vmware_key.as_ptr() as *const i8,
            0,
            0x20019, // KEY_READ
            &mut hkey,
        ) == 0 {
            winapi::um::winreg::RegCloseKey(hkey);
            return true;
        }

        // Check for VirtualBox
        let vbox_key = obfstr::obfstr!("SOFTWARE\\Oracle\\VirtualBox Guest Additions\0");
        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            vbox_key.as_ptr() as *const i8,
            0,
            0x20019,
            &mut hkey,
        ) == 0 {
            winapi::um::winreg::RegCloseKey(hkey);
            return true;
        }

        false
    }
}

/// Check for VM-specific processes
fn check_vm_processes() -> bool {
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use winapi::um::handleapi::CloseHandle;

    let vm_processes: &[&str] = &[
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "xenservice.exe",
    ];

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return false;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let process_name: String = entry.szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect::<String>()
                    .to_lowercase();

                for vm_proc in vm_processes {
                    if process_name == *vm_proc {
                        CloseHandle(snapshot);
                        return true;
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        false
    }
}

/// Check if VBS (Virtualization-Based Security) is enabled
#[cfg(target_arch = "x86_64")]
fn check_vbs_enabled() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::shared::minwindef::{DWORD, HKEY};
    use std::ptr::null_mut;

    unsafe {
        let mut hkey: HKEY = null_mut();
        let key_path = obfstr::obfstr!("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0");

        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr() as *const i8,
            0,
            0x20019, // KEY_READ
            &mut hkey,
        ) != 0 {
            return false;
        }

        let value_name = obfstr::obfstr!("EnableVirtualizationBasedSecurity\0");
        let mut value: DWORD = 0;
        let mut value_size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        let result = RegQueryValueExA(
            hkey,
            value_name.as_ptr() as *const i8,
            null_mut(),
            null_mut(),
            &mut value as *mut _ as *mut u8,
            &mut value_size,
        );

        winapi::um::winreg::RegCloseKey(hkey);
        result == 0 && value != 0
    }
}

/// Check if HVCI (Hypervisor-protected Code Integrity) is enabled
#[cfg(target_arch = "x86_64")]
fn check_hvci_enabled() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::shared::minwindef::{DWORD, HKEY};
    use std::ptr::null_mut;

    unsafe {
        let mut hkey: HKEY = null_mut();
        let key_path = obfstr::obfstr!("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\0");

        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr() as *const i8,
            0,
            0x20019,
            &mut hkey,
        ) != 0 {
            return false;
        }

        let value_name = obfstr::obfstr!("Enabled\0");
        let mut value: DWORD = 0;
        let mut value_size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        let result = RegQueryValueExA(
            hkey,
            value_name.as_ptr() as *const i8,
            null_mut(),
            null_mut(),
            &mut value as *mut _ as *mut u8,
            &mut value_size,
        );

        winapi::um::winreg::RegCloseKey(hkey);
        result == 0 && value != 0
    }
}

/// Check if Credential Guard is enabled
#[cfg(target_arch = "x86_64")]
fn check_credential_guard() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::shared::minwindef::{DWORD, HKEY};
    use std::ptr::null_mut;

    unsafe {
        let mut hkey: HKEY = null_mut();
        let key_path = obfstr::obfstr!("SYSTEM\\CurrentControlSet\\Control\\Lsa\0");

        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr() as *const i8,
            0,
            0x20019,
            &mut hkey,
        ) != 0 {
            return false;
        }

        let value_name = obfstr::obfstr!("LsaCfgFlags\0");
        let mut value: DWORD = 0;
        let mut value_size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        let result = RegQueryValueExA(
            hkey,
            value_name.as_ptr() as *const i8,
            null_mut(),
            null_mut(),
            &mut value as *mut _ as *mut u8,
            &mut value_size,
        );

        winapi::um::winreg::RegCloseKey(hkey);
        // Value of 1 or 2 indicates Credential Guard is enabled
        result == 0 && (value == 1 || value == 2)
    }
}

/// Check if Secure Boot is enabled
#[cfg(target_arch = "x86_64")]
fn check_secure_boot() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::shared::minwindef::{DWORD, HKEY};
    use std::ptr::null_mut;

    unsafe {
        let mut hkey: HKEY = null_mut();
        let key_path = obfstr::obfstr!("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\0");

        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr() as *const i8,
            0,
            0x20019,
            &mut hkey,
        ) != 0 {
            return false;
        }

        let value_name = obfstr::obfstr!("UEFISecureBootEnabled\0");
        let mut value: DWORD = 0;
        let mut value_size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        let result = RegQueryValueExA(
            hkey,
            value_name.as_ptr() as *const i8,
            null_mut(),
            null_mut(),
            &mut value as *mut _ as *mut u8,
            &mut value_size,
        );

        winapi::um::winreg::RegCloseKey(hkey);
        result == 0 && value == 1
    }
}

/// Print security environment information (for debugging)
pub fn print_security_info() {
    let env = detect_security_environment();

    println!("Security Environment:");
    println!("  Hypervisor Present: {}", env.hypervisor_present);
    if let Some(ref vendor) = env.hypervisor_vendor {
        println!("  Hypervisor Vendor: {}", vendor);
    }
    println!("  Virtual Machine: {}", env.is_virtual_machine);
    println!("  VBS Enabled: {}", env.vbs_enabled);
    println!("  HVCI Enabled: {}", env.hvci_enabled);
    println!("  Credential Guard: {}", env.credential_guard_enabled);
    println!("  Secure Boot: {}", env.secure_boot_enabled);
    println!("  Hardened Environment: {}", env.is_hardened());
}
