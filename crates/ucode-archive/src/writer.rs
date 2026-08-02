use crate::{ALIGNMENT, ArchiveError, MODE_DIR, MODE_FILE, NEWC_MAGIC, Result, TRAILER_NAME};

/// A file to place into the archive.
#[derive(Debug, Clone)]
pub struct CpioFile {
    pub name: String,
    pub data: Vec<u8>,
    pub mode: u32,
}

/// Deterministic newc archive builder.
///
/// Fixed choices, all of them load-bearing for reproducibility:
///   * `mtime` is always 0;
///   * `uid`/`gid` are always 0;
///   * inode numbers are assigned sequentially from 1 in emission order;
///   * `nlink` is 1 for files and 2 for directories;
///   * device and rdev numbers are 0;
///   * the check field is 0 (newc has no checksum; that is `070702`);
///   * hexadecimal fields are lowercase, matching `gen_init_cpio`.
#[derive(Debug, Default)]
pub struct CpioBuilder {
    dirs: Vec<String>,
    files: Vec<CpioFile>,
    emit_parent_dirs: bool,
}

impl CpioBuilder {
    pub fn new() -> Self {
        Self {
            dirs: Vec::new(),
            files: Vec::new(),
            emit_parent_dirs: true,
        }
    }

    /// The Linux early loader looks up the full path directly and does not
    /// need directory records. Some initramfs tooling does expect them, so
    /// they are emitted by default but can be turned off for a minimal image.
    pub fn emit_parent_dirs(mut self, yes: bool) -> Self {
        self.emit_parent_dirs = yes;
        self
    }

    pub fn add_file(&mut self, name: impl Into<String>, data: Vec<u8>) -> Result<&mut Self> {
        let name = name.into();
        validate_member_name(&name)?;
        if self.emit_parent_dirs {
            let mut acc = String::new();
            let mut parts: Vec<&str> = name.split('/').collect();
            parts.pop();
            for part in parts {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(part);
                if !self.dirs.contains(&acc) {
                    self.dirs.push(acc.clone());
                }
            }
        }
        self.files.push(CpioFile {
            name,
            data,
            mode: MODE_FILE | 0o644,
        });
        Ok(self)
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn total_payload_bytes(&self) -> usize {
        self.files.iter().map(|f| f.data.len()).sum()
    }

    /// Serialise the archive. Directories come first in path order, then files
    /// in path order, then the trailer.
    pub fn build(mut self) -> Result<Vec<u8>> {
        self.dirs.sort();
        self.dirs.dedup();
        self.files.sort_by(|a, b| a.name.cmp(&b.name));

        let mut out = Vec::with_capacity(
            self.total_payload_bytes() + (self.files.len() + self.dirs.len() + 1) * 256,
        );
        let mut ino: u32 = 1;

        for dir in &self.dirs {
            write_record(&mut out, ino, MODE_DIR | 0o755, 2, dir, &[]);
            ino = ino.wrapping_add(1);
        }
        for file in &self.files {
            write_record(&mut out, ino, file.mode, 1, &file.name, &file.data);
            ino = ino.wrapping_add(1);
        }
        write_record(&mut out, 0, 0, 1, TRAILER_NAME, &[]);

        // The kernel wants the *whole* early area 4-byte aligned; the trailer
        // padding already guarantees this, but be explicit.
        pad_to(&mut out, ALIGNMENT);
        Ok(out)
    }
}

fn write_record(out: &mut Vec<u8>, ino: u32, mode: u32, nlink: u32, name: &str, data: &[u8]) {
    let namesize = name.len() + 1;
    out.extend_from_slice(NEWC_MAGIC);
    for value in [
        ino,
        mode,
        0, // uid
        0, // gid
        nlink,
        0,                 // mtime - always zero, for reproducibility
        data.len() as u32, // filesize
        0,                 // devmajor
        0,                 // devminor
        0,                 // rdevmajor
        0,                 // rdevminor
        namesize as u32,
        0, // check
    ] {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad_to(out, ALIGNMENT);
    out.extend_from_slice(data);
    pad_to(out, ALIGNMENT);
}

fn pad_to(out: &mut Vec<u8>, alignment: usize) {
    let rem = out.len() % alignment;
    if rem != 0 {
        out.resize(out.len() + (alignment - rem), 0);
    }
}

/// Reject anything that could escape the archive root or confuse the kernel's
/// simple path comparison.
pub fn validate_member_name(name: &str) -> Result<()> {
    let bad = |reason: &'static str| {
        Err(ArchiveError::UnsafeName {
            name: name.to_string(),
            reason,
        })
    };
    if name.is_empty() {
        return bad("empty");
    }
    if name.len() > 4096 {
        return bad("longer than 4096 bytes");
    }
    if name.starts_with('/') {
        return bad("absolute path");
    }
    if name.contains('\0') {
        return bad("contains a NUL byte");
    }
    if name.contains("//") {
        return bad("contains an empty path component");
    }
    for component in name.split('/') {
        if component == ".." {
            return bad("contains a `..` component");
        }
        if component == "." {
            return bad("contains a `.` component");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_is_byte_reproducible() {
        let build = || {
            let mut b = CpioBuilder::new();
            b.add_file("kernel/x86/microcode/GenuineIntel.bin", vec![0xaa; 1024])
                .unwrap();
            b.build().unwrap()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn everything_is_four_byte_aligned() {
        let mut b = CpioBuilder::new();
        b.add_file("kernel/x86/microcode/AuthenticAMD.bin", vec![1, 2, 3])
            .unwrap();
        let out = b.build().unwrap();
        assert_eq!(out.len() % 4, 0);
        assert_eq!(&out[..6], NEWC_MAGIC);
    }

    #[test]
    fn rejects_traversal() {
        let mut b = CpioBuilder::new();
        assert!(b.add_file("../etc/passwd", vec![]).is_err());
    }
}
