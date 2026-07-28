use miette::Result;
use serde::Serialize;
use ucode_boot::{inspect_initrd, inspect_uki};
use ucode_core::limits::Limits;

use super::{InspectBootArgs, OutputFormat};
use crate::output::emit;

#[derive(Serialize)]
struct BootJson {
    kind: String,
    path: String,
    file_size: u64,
    has_microcode: bool,
    patch_count: usize,
    details: serde_json::Value,
    findings: Vec<String>,
}

pub fn run(args: InspectBootArgs, format: OutputFormat) -> Result<i32> {
    let limits = Limits::default();
    let is_uki = args.uki
        || args
            .path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("efi") || e.eq_ignore_ascii_case("uki"))
            .unwrap_or(false);

    let json = if is_uki {
        let insp = inspect_uki(&args.path, &limits).map_err(|e| miette::miette!("{e}"))?;
        BootJson {
            kind: "uki".into(),
            path: insp.path.clone(),
            file_size: insp.file_size,
            has_microcode: insp.has_ucode_section,
            patch_count: insp.patch_count,
            details: serde_json::json!({
                "sections": insp.sections,
                "ucode_size": insp.ucode_size,
                "ucode_sha256": insp.ucode_sha256,
                "has_authenticode": insp.has_authenticode,
            }),
            findings: insp.findings,
        }
    } else {
        let insp = inspect_initrd(&args.path, &limits).map_err(|e| miette::miette!("{e}"))?;
        BootJson {
            kind: "initrd".into(),
            path: insp.path.clone(),
            file_size: insp.file_size,
            has_microcode: insp.has_early_cpio && !insp.embedded.is_empty(),
            patch_count: insp.patch_count,
            details: serde_json::json!({
                "has_early_cpio": insp.has_early_cpio,
                "early_end_offset": insp.early_end_offset,
                "archive_count": insp.archive_count,
                "embedded": insp.embedded,
            }),
            findings: insp.findings,
        }
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "boot artifact: {} ({})\n  size={}  microcode={}  patches={}\n",
            json.path, json.kind, json.file_size, json.has_microcode, json.patch_count
        ));
        out.push_str(&format!(
            "  details: {}\n",
            serde_json::to_string_pretty(&json.details).unwrap_or_default()
        ));
        for f in &json.findings {
            out.push_str(&format!("  note: {f}\n"));
        }
        out
    });

    Ok(0)
}
