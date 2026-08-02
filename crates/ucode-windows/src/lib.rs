//! Read-only Windows-specific CPU observations.

#![deny(unsafe_op_in_unsafe_fn)]

use ucode_core::RevisionObservation;
#[cfg(not(windows))]
use ucode_core::RevisionSource;

#[cfg(windows)]
mod registry {
    use std::ffi::OsStr;
    use std::iter;
    use std::os::windows::ffi::OsStrExt;

    use ucode_core::{RevisionObservation, RevisionSource};
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text)
            .encode_wide()
            .chain(iter::once(0))
            .collect()
    }

    fn revision_value(cpu: u32, value: &str) -> RevisionObservation {
        let key_name = wide(&format!(
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\{cpu}"
        ));
        let value_name = wide(value);
        let mut key: HKEY = std::ptr::null_mut();
        let open =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_name.as_ptr(), 0, KEY_READ, &mut key) };
        if open == ERROR_FILE_NOT_FOUND {
            return RevisionObservation::unavailable(
                RevisionSource::WindowsRegistry,
                "Update Revision is not present for this logical processor",
            );
        }
        if open != 0 {
            return RevisionObservation::unavailable(
                RevisionSource::WindowsRegistry,
                format!("cannot open processor registry key (Win32 error {open})"),
            );
        }

        let result = (|| {
            let mut kind = 0u32;
            let mut len = 0u32;
            let first = unsafe {
                RegQueryValueExW(
                    key,
                    value_name.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    std::ptr::null_mut(),
                    &mut len,
                )
            };
            if first == ERROR_FILE_NOT_FOUND {
                return RevisionObservation::unavailable(
                    RevisionSource::WindowsRegistry,
                    "Update Revision is not present",
                );
            }
            if first != 0 {
                return RevisionObservation::unavailable(
                    RevisionSource::WindowsRegistry,
                    format!("cannot read Update Revision length (Win32 error {first})"),
                );
            }
            if kind != REG_BINARY {
                return RevisionObservation::invalid(
                    RevisionSource::WindowsRegistry,
                    Vec::new(),
                    format!("Update Revision has registry type {kind}, expected REG_BINARY"),
                );
            }
            let mut bytes = vec![0u8; len as usize];
            let second = unsafe {
                RegQueryValueExW(
                    key,
                    value_name.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    bytes.as_mut_ptr(),
                    &mut len,
                )
            };
            if second != 0 {
                return RevisionObservation::unavailable(
                    RevisionSource::WindowsRegistry,
                    format!("cannot read Update Revision data (Win32 error {second})"),
                );
            }
            bytes.truncate(len as usize);
            decode_update_revision(bytes)
        })();
        unsafe { RegCloseKey(key) };
        result
    }

    pub(super) fn update_revision(cpu: u32) -> RevisionObservation {
        revision_value(cpu, "Update Revision")
    }

    pub(super) fn previous_update_revision(cpu: u32) -> Option<RevisionObservation> {
        let observation = revision_value(cpu, "Previous Update Revision");
        match &observation {
            RevisionObservation::Unavailable { reason, .. } if reason.contains("not present") => {
                None
            }
            _ => Some(observation),
        }
    }

    /// Known `Update Revision` REG_BINARY layouts are a direct four-byte
    /// little-endian revision and the eight-byte form where the revision is
    /// the final u32. Retain all bytes and reject every other length.
    pub(super) fn decode_update_revision(bytes: Vec<u8>) -> RevisionObservation {
        let revision_bytes: [u8; 4] = match bytes.len() {
            4 => bytes[..4].try_into().expect("fixed-length slice"),
            8 => bytes[4..8].try_into().expect("fixed-length slice"),
            _ => {
                return RevisionObservation::invalid(
                    RevisionSource::WindowsRegistry,
                    bytes,
                    "Update Revision has an unrecognized REG_BINARY length; expected 4 or 8 bytes",
                );
            }
        };
        let revision = u32::from_le_bytes(revision_bytes);
        RevisionObservation::known_raw(revision, RevisionSource::WindowsRegistry, bytes)
    }
}

/// Read `HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\<n>\\Update Revision`.
pub fn update_revision(cpu: u32) -> RevisionObservation {
    #[cfg(windows)]
    {
        registry::update_revision(cpu)
    }
    #[cfg(not(windows))]
    {
        let _ = cpu;
        RevisionObservation::unsupported(
            RevisionSource::WindowsRegistry,
            "Windows registry is unavailable on this OS",
        )
    }
}

/// Read `Previous Update Revision` when Windows exposes it. Its semantics are
/// Windows-version-specific, so it is diagnostic context and never policy input.
pub fn previous_update_revision(cpu: u32) -> Option<RevisionObservation> {
    #[cfg(windows)]
    {
        registry::previous_update_revision(cpu)
    }
    #[cfg(not(windows))]
    {
        let _ = cpu;
        None
    }
}

/// Active logical processor count across all Windows processor groups.
pub fn logical_processor_count() -> usize {
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::System::Threading::GetActiveProcessorCount(0xffff) as usize }
    }
    #[cfg(not(windows))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn decodes_only_the_known_eight_byte_layout() {
        let value = super::registry::decode_update_revision(vec![0, 0, 0, 0, 0x34, 0x12, 0, 0]);
        assert_eq!(value.known_revision(), Some(0x1234));
    }

    #[cfg(windows)]
    #[test]
    fn decodes_the_known_four_byte_layout() {
        let value = super::registry::decode_update_revision(vec![0x21, 1, 0, 0]);
        assert_eq!(value.known_revision(), Some(0x121));
    }
}
