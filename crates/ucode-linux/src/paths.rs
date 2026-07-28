use std::path::{Path, PathBuf};

/// Canonical firmware directories used by the Linux microcode loaders.
pub fn default_firmware_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/lib/firmware/intel-ucode"),
        PathBuf::from("/lib/firmware/amd-ucode"),
        PathBuf::from("/usr/lib/firmware/intel-ucode"),
        PathBuf::from("/usr/lib/firmware/amd-ucode"),
        PathBuf::from("/usr/share/misc/intel-microcode"),
    ]
}

/// Common locations for the currently installed initrd/initramfs image.
pub fn default_initrd_candidates() -> Vec<PathBuf> {
    let mut out = vec![
        PathBuf::from("/boot/initrd.img"),
        PathBuf::from("/boot/initramfs.img"),
        PathBuf::from("/boot/initrd"),
        PathBuf::from("/boot/initramfs-linux.img"),
        PathBuf::from("/boot/initramfs-linux-lts.img"),
    ];

    // Kernel-versioned names when uname is available.
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let rel = release.trim();
        if !rel.is_empty() {
            out.insert(0, PathBuf::from(format!("/boot/initrd.img-{rel}")));
            out.insert(1, PathBuf::from(format!("/boot/initramfs-{rel}.img")));
            out.insert(2, PathBuf::from(format!("/boot/initrd-{rel}")));
        }
    }
    out
}

/// Standard early-loader blob path for a vendor under a firmware root.
pub fn firmware_blob_for_vendor(root: &Path, vendor_dir: &str, file: &str) -> PathBuf {
    root.join(vendor_dir).join(file)
}
