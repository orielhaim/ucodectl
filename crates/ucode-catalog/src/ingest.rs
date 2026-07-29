use std::io::Read;
use std::path::{Path, PathBuf};

use tracing::{debug, warn};
use ucode_amd::AmdContainer;
use ucode_core::limits::Limits;
use ucode_core::{PatchMeta, ValidationReport, Vendor};
use ucode_intel::{IntelBundle, IntelValidationMode};

use crate::{Catalog, CatalogError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    IntelBinary,
    IntelDat,
    AmdContainer,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub limits: Limits,
    pub mode: IntelValidationMode,
    /// Keep the raw bytes of every patch. Turn off for pure inspection to
    /// halve peak memory on large release trees.
    pub keep_payloads: bool,
    /// Recurse into directories.
    pub recursive: bool,
    /// Continue after a file fails to parse, recording it in `failures`.
    pub tolerate_failures: bool,
    /// Restrict ingestion to one vendor.
    pub only_vendor: Option<Vendor>,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            mode: IntelValidationMode::Strict,
            keep_payloads: true,
            recursive: true,
            tolerate_failures: true,
            only_vendor: None,
        }
    }
}

/// Provenance record for one ingested file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBlob {
    pub path: PathBuf,
    pub size: u64,
    pub format: DetectedFormat,
    pub sha256: [u8; 32],
    pub patch_count: usize,
}

/// Content sniffing. Extensions are advisory only; the bytes decide.
pub fn detect_format(bytes: &[u8]) -> DetectedFormat {
    if AmdContainer::looks_like_amd(bytes) {
        return DetectedFormat::AmdContainer;
    }
    if IntelBundle::looks_like_intel(bytes) {
        return DetectedFormat::IntelBinary;
    }
    if ucode_intel::dat::looks_like_dat(bytes) {
        return DetectedFormat::IntelDat;
    }
    DetectedFormat::Unknown
}

/// Ingest a file or directory into an existing catalog.
pub fn ingest_path(catalog: &mut Catalog, path: &Path, opts: &IngestOptions) -> Result<()> {
    ingest_inner(catalog, path, opts, 0)?;
    catalog.normalise();
    Ok(())
}

fn ingest_inner(
    catalog: &mut Catalog,
    path: &Path,
    opts: &IngestOptions,
    depth: u32,
) -> Result<()> {
    if depth > opts.limits.max_directory_depth {
        return Err(CatalogError::LimitExceeded("directory recursion depth"));
    }

    let meta = std::fs::symlink_metadata(path).map_err(|e| CatalogError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    if meta.file_type().is_symlink() {
        // Symlinks inside a release tree are common (e.g. distro packaging),
        // but silently following them makes provenance meaningless. Resolve
        // explicitly and record the real path.
        let target = std::fs::canonicalize(path).map_err(|e| CatalogError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        debug!(link = %path.display(), target = %target.display(), "resolving symlink");
        return ingest_inner(catalog, &target, opts, depth + 1);
    }

    if meta.is_dir() {
        if !opts.recursive && depth > 0 {
            return Ok(());
        }
        let mut children: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|e| CatalogError::Io {
                path: path.to_path_buf(),
                source: e,
            })?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        children.sort(); // deterministic traversal
        for child in children {
            if catalog.sources.len() as u32 >= opts.limits.max_catalog_files {
                return Err(CatalogError::LimitExceeded("too many files"));
            }
            match ingest_inner(catalog, &child, opts, depth + 1) {
                Ok(()) => {}
                Err(e) if opts.tolerate_failures => {
                    warn!(path = %child.display(), error = %e, "skipping file");
                    catalog.failures.push((child, e.to_string()));
                }
                Err(e) => return Err(e),
            }
        }
        return Ok(());
    }

    if !meta.is_file() {
        return Ok(());
    }
    if meta.len() == 0 || meta.len() > opts.limits.max_blob_bytes {
        return Ok(());
    }

    let bytes = read_file_nofollow(path, opts.limits.max_blob_bytes)?;
    ingest_bytes(catalog, path, &bytes, opts)
}

fn read_file_nofollow(path: &Path, max: u64) -> Result<Vec<u8>> {
    // Refuse to open if the final path component is a symlink. Parent-dir
    // symlink races are out of scope for v0.1; distro packaging resolves those.
    let meta = std::fs::symlink_metadata(path).map_err(|e| CatalogError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if meta.file_type().is_symlink() {
        return Err(CatalogError::Symlink {
            path: path.to_path_buf(),
        });
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    {
        use rustix::fs::{Mode, OFlags};
        use std::fs::File;
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| CatalogError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::from(e),
        })?;
        let mut file = File::from(fd);
        let mut buf = Vec::new();
        file.by_ref()
            .take(max)
            .read_to_end(&mut buf)
            .map_err(|e| CatalogError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        return Ok(buf);
    }

    #[cfg(not(all(unix, not(target_os = "windows"))))]
    {
        let mut file = std::fs::File::open(path).map_err(|e| CatalogError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut buf = Vec::new();
        file.by_ref()
            .take(max)
            .read_to_end(&mut buf)
            .map_err(|e| CatalogError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(buf)
    }
}

/// Ingest an in-memory blob. Exposed so callers can feed extracted CPIO
/// members or UKI sections without touching the filesystem.
pub fn ingest_bytes(
    catalog: &mut Catalog,
    display_path: &Path,
    bytes: &[u8],
    opts: &IngestOptions,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let format = detect_format(bytes);
    let display = display_path.display().to_string();

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let file_sha: [u8; 32] = hasher.finalize().into();

    let before = catalog.patches.len();

    match format {
        DetectedFormat::Unknown => {
            return Err(CatalogError::UnknownFormat {
                path: display_path.to_path_buf(),
            });
        }

        DetectedFormat::IntelDat => {
            if opts.only_vendor == Some(Vendor::Amd) {
                return Ok(());
            }
            let text = core::str::from_utf8(bytes).map_err(|_| CatalogError::UnknownFormat {
                path: display_path.to_path_buf(),
            })?;
            let binary =
                ucode_intel::dat::dat_to_binary(text).map_err(|e| CatalogError::Intel {
                    path: display_path.to_path_buf(),
                    source: e,
                })?;
            ingest_intel(catalog, &display, &binary, opts, display_path)?;
        }

        DetectedFormat::IntelBinary => {
            if opts.only_vendor == Some(Vendor::Amd) {
                return Ok(());
            }
            ingest_intel(catalog, &display, bytes, opts, display_path)?;
        }

        DetectedFormat::AmdContainer => {
            if opts.only_vendor == Some(Vendor::Intel) {
                return Ok(());
            }
            ingest_amd(catalog, &display, bytes, opts, display_path)?;
        }
    }

    catalog.sources.push(SourceBlob {
        path: display_path.to_path_buf(),
        size: bytes.len() as u64,
        format,
        sha256: file_sha,
        patch_count: catalog.patches.len() - before,
    });

    Ok(())
}

fn ingest_intel(
    catalog: &mut Catalog,
    display: &str,
    bytes: &[u8],
    opts: &IngestOptions,
    path: &Path,
) -> Result<()> {
    let bundle =
        IntelBundle::parse(bytes, opts.mode, &opts.limits).map_err(|e| CatalogError::Intel {
            path: path.to_path_buf(),
            source: e,
        })?;

    catalog.report.extend(bundle.report.clone());

    for entry in &bundle.entries {
        let mut meta: PatchMeta = entry.to_meta(display);
        // Fold per-entry findings into the catalog-level report so that
        // `validate` can report everything from one place.
        let mut entry_report = ValidationReport::default();
        entry_report.extend(entry.report.clone());
        catalog.report.extend(entry_report);

        let payload = if opts.keep_payloads {
            entry.bytes(bytes).unwrap_or_default().to_vec()
        } else {
            Vec::new()
        };
        // Payload length must agree with the declared size or the artifact
        // writer would silently emit a short image.
        if opts.keep_payloads && payload.len() as u32 != meta.total_size {
            meta.total_size = payload.len() as u32;
        }
        catalog.patches.push(meta);
        catalog.payloads.push(payload);
    }
    Ok(())
}

fn ingest_amd(
    catalog: &mut Catalog,
    display: &str,
    bytes: &[u8],
    opts: &IngestOptions,
    path: &Path,
) -> Result<()> {
    let containers =
        AmdContainer::parse_all(bytes, &opts.limits).map_err(|e| CatalogError::Amd {
            path: path.to_path_buf(),
            source: e,
        })?;

    for container in &containers {
        catalog.report.extend(container.report.clone());
        for patch in &container.patches {
            catalog.report.extend(patch.report.clone());

            let meta = patch.to_meta(display);
            let payload = if opts.keep_payloads {
                patch.bytes(bytes).unwrap_or_default().to_vec()
            } else {
                Vec::new()
            };
            catalog.patches.push(meta);
            catalog.payloads.push(payload);
        }
        // Equivalence entries are needed verbatim when rebuilding a container.
        catalog
            .amd_equivalence
            .extend(container.equivalence.entries.iter().copied());
    }
    Ok(())
}
