use miette::Result;
use serde::Serialize;
use ucode_boot::{inspect_initrd, inspect_uki, looks_like_uki};
use ucode_core::limits::Limits;

use super::{BootInputType, InspectBootArgs, OutputFormat};
use crate::output::emit;

#[derive(Serialize)]
struct BootJson {
    schema_version: u32,
    command: &'static str,
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
    if let Err(error) = std::fs::metadata(&args.path) {
        return Err(crate::error::input_io("inspect-boot", &args.path, &error));
    }
    let is_uki = match args.input_type {
        BootInputType::Uki => true,
        BootInputType::Initrd => false,
        BootInputType::Auto => {
            let bytes = std::fs::read(&args.path)
                .map_err(|e| crate::error::input_io("inspect-boot", &args.path, &e))?;
            looks_like_uki(&bytes)
        }
    };

    let json = if is_uki {
        let insp = inspect_uki(&args.path, &limits).map_err(|e| miette::miette!("{e}"))?;
        BootJson {
            schema_version: 1,
            command: "inspect-boot",
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
            schema_version: 1,
            command: "inspect-boot",
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
