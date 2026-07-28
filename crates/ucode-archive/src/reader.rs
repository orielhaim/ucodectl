use ucode_core::limits::Limits;

use crate::{ALIGNMENT, ArchiveError, NEWC_HEADER_SIZE, NEWC_MAGIC, Result, TRAILER_NAME};

#[derive(Debug, Clone)]
pub struct CpioEntry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    /// Offset of the file data within the buffer.
    pub data_offset: u64,
    pub data_len: u32,
}

impl CpioEntry {
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170_000 == crate::MODE_DIR
    }

    pub fn is_file(&self) -> bool {
        self.mode & 0o170_000 == crate::MODE_FILE
    }

    pub fn data<'b>(&self, buf: &'b [u8]) -> Option<&'b [u8]> {
        let start = usize::try_from(self.data_offset).ok()?;
        buf.get(start..start.checked_add(self.data_len as usize)?)
    }
}

/// Streaming-ish reader over an in-memory newc archive.
pub struct CpioReader<'a> {
    buf: &'a [u8],
    cursor: usize,
    limits: Limits,
    count: u32,
    finished: bool,
}

impl<'a> CpioReader<'a> {
    pub fn new(buf: &'a [u8], limits: Limits) -> Self {
        Self {
            buf,
            cursor: 0,
            limits,
            count: 0,
            finished: false,
        }
    }

    pub fn at(buf: &'a [u8], offset: usize, limits: Limits) -> Self {
        Self {
            buf,
            cursor: offset,
            limits,
            count: 0,
            finished: false,
        }
    }

    /// Byte offset just past the TRAILER record, once iteration finished.
    pub fn position(&self) -> usize {
        self.cursor
    }

    pub fn next_entry(&mut self) -> Result<Option<CpioEntry>> {
        if self.finished {
            return Ok(None);
        }
        let start = self.cursor;
        let head = self.buf.get(start..).unwrap_or_default();
        if head.len() < NEWC_HEADER_SIZE {
            return Err(ArchiveError::Truncated {
                offset: start as u64,
                need: NEWC_HEADER_SIZE,
                have: head.len(),
            });
        }
        if head.get(..6) != Some(&NEWC_MAGIC[..]) {
            return Err(ArchiveError::BadMagic {
                offset: start as u64,
            });
        }

        let field = |idx: usize, name: &'static str| -> Result<u32> {
            let off = 6 + idx * 8;
            let raw = head.get(off..off + 8).ok_or(ArchiveError::BadField {
                field: name,
                offset: (start + off) as u64,
            })?;
            let s = std::str::from_utf8(raw).map_err(|_| ArchiveError::BadField {
                field: name,
                offset: (start + off) as u64,
            })?;
            u32::from_str_radix(s.trim(), 16).map_err(|_| ArchiveError::BadField {
                field: name,
                offset: (start + off) as u64,
            })
        };

        let ino = field(0, "c_ino")?;
        let _ = ino;
        let mode = field(1, "c_mode")?;
        let uid = field(2, "c_uid")?;
        let gid = field(3, "c_gid")?;
        let _nlink = field(4, "c_nlink")?;
        let mtime = field(5, "c_mtime")?;
        let filesize = field(6, "c_filesize")?;
        let namesize = field(11, "c_namesize")?;

        if namesize == 0 || namesize as usize > 4097 {
            return Err(ArchiveError::BadField {
                field: "c_namesize",
                offset: start as u64,
            });
        }
        if filesize > self.limits.max_patch_bytes.max(1 << 24) {
            return Err(ArchiveError::LimitExceeded(
                "cpio member larger than allowed",
            ));
        }

        let name_start = start + NEWC_HEADER_SIZE;
        let name_end = name_start
            .checked_add(namesize as usize)
            .ok_or(ArchiveError::BadField {
                field: "c_namesize",
                offset: start as u64,
            })?;
        let name_bytes = self
            .buf
            .get(name_start..name_end)
            .ok_or(ArchiveError::Truncated {
                offset: name_start as u64,
                need: namesize as usize,
                have: self.buf.len().saturating_sub(name_start),
            })?;
        let name = std::str::from_utf8(name_bytes.split_last().map(|(_, s)| s).unwrap_or_default())
            .map_err(|_| ArchiveError::BadField {
                field: "name",
                offset: name_start as u64,
            })?
            .to_string();

        let data_offset = align_up(name_end, ALIGNMENT);
        let data_end =
            data_offset
                .checked_add(filesize as usize)
                .ok_or(ArchiveError::BadField {
                    field: "c_filesize",
                    offset: start as u64,
                })?;
        if data_end > self.buf.len() {
            return Err(ArchiveError::Truncated {
                offset: data_offset as u64,
                need: filesize as usize,
                have: self.buf.len().saturating_sub(data_offset),
            });
        }
        self.cursor = align_up(data_end, ALIGNMENT);

        if name == TRAILER_NAME {
            self.finished = true;
            return Ok(None);
        }

        self.count += 1;
        if self.count > self.limits.max_archive_entries {
            return Err(ArchiveError::LimitExceeded("too many cpio entries"));
        }

        Ok(Some(CpioEntry {
            name,
            mode,
            uid,
            gid,
            mtime,
            data_offset: data_offset as u64,
            data_len: filesize,
        }))
    }

    pub fn entries(mut self) -> Result<(Vec<CpioEntry>, usize)> {
        let mut out = Vec::new();
        while let Some(e) = self.next_entry()? {
            out.push(e);
        }
        if !self.finished {
            return Err(ArchiveError::MissingTrailer);
        }
        Ok((out, self.cursor))
    }
}

fn align_up(v: usize, a: usize) -> usize {
    v.next_multiple_of(a)
}

/// Result of looking for a microcode CPIO at the head of an initrd.
#[derive(Debug, Clone)]
pub struct EarlyCpioScan {
    /// All entries found across every leading uncompressed cpio archive.
    pub entries: Vec<CpioEntry>,
    /// Offset where the leading uncompressed cpio area ends. Everything from
    /// here on is the "real" (possibly compressed) initramfs.
    pub end_offset: u64,
    /// Number of concatenated archives found.
    pub archive_count: u32,
}

/// Walk every concatenated uncompressed newc archive at the start of a buffer.
///
/// Returns `None` when the buffer does not begin with a cpio archive at all,
/// which is the normal case for a plain compressed initramfs with no early
/// microcode area.
pub fn scan_early_cpio(buf: &[u8], limits: &Limits) -> Result<Option<EarlyCpioScan>> {
    if buf.get(..6) != Some(&NEWC_MAGIC[..]) {
        return Ok(None);
    }
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut archive_count = 0u32;

    while buf.get(offset..offset + 6) == Some(&NEWC_MAGIC[..]) {
        let reader = CpioReader::at(buf, offset, *limits);
        let (mut found, end) = reader.entries()?;
        entries.append(&mut found);
        archive_count += 1;
        if end <= offset {
            break;
        }
        offset = end;
        if archive_count > 64 {
            return Err(ArchiveError::LimitExceeded(
                "too many concatenated cpio archives",
            ));
        }
    }

    Ok(Some(EarlyCpioScan {
        entries,
        end_offset: offset as u64,
        archive_count,
    }))
}

/// Offset just past the first archive, or `None` if there is no archive.
pub fn find_first_archive_end(buf: &[u8], limits: &Limits) -> Result<Option<u64>> {
    if buf.get(..6) != Some(&NEWC_MAGIC[..]) {
        return Ok(None);
    }
    let (_, end) = CpioReader::new(buf, *limits).entries()?;
    Ok(Some(end as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::CpioBuilder;

    #[test]
    fn round_trip() {
        let mut b = CpioBuilder::new();
        b.add_file("kernel/x86/microcode/GenuineIntel.bin", vec![7u8; 300])
            .unwrap();
        let blob = b.build().unwrap();

        let scan = scan_early_cpio(&blob, &Limits::default()).unwrap().unwrap();
        assert_eq!(scan.archive_count, 1);
        let file = scan
            .entries
            .iter()
            .find(|e| e.name == "kernel/x86/microcode/GenuineIntel.bin")
            .expect("file present");
        assert_eq!(file.data_len, 300);
        assert_eq!(file.mtime, 0);
        assert_eq!(file.uid, 0);
        assert_eq!(file.data(&blob).unwrap(), &vec![7u8; 300][..]);
    }
}
