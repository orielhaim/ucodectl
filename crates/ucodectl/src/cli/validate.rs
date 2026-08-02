use miette::Result;
use serde::Serialize;
use ucode_core::Severity;

use super::{OutputFormat, ValidateArgs};
use crate::output::emit;
use crate::util::{default_limits, load_catalog_named};

#[derive(Serialize)]
struct ValidateJson {
    schema_version: u32,
    command: &'static str,
    ok: bool,
    errors: usize,
    warnings: usize,
    infos: usize,
    patch_count: usize,
    findings: Vec<FindingJson>,
}

#[derive(Serialize)]
struct FindingJson {
    severity: String,
    code: String,
    offset: u64,
    message: String,
    source: Option<String>,
}

pub fn run(args: ValidateArgs, format: OutputFormat) -> Result<i32> {
    let catalog = load_catalog_named(
        "validate: failed to load validation source",
        &args.paths,
        default_limits(),
        false,
        true,
    )?;
    let errors = catalog.report.count(Severity::Error);
    let warnings = catalog.report.count(Severity::Warning);
    let infos = catalog.report.count(Severity::Info);

    let findings: Vec<FindingJson> = catalog
        .report
        .findings
        .iter()
        .map(|f| FindingJson {
            severity: format!("{:?}", f.severity).to_lowercase(),
            code: format!("{:?}", f.code),
            offset: f.offset,
            message: f.message.clone(),
            source: None,
        })
        .collect();

    let ok = errors == 0 && (!args.warnings_as_errors || warnings == 0);
    let json = ValidateJson {
        schema_version: 1,
        command: "validate",
        ok,
        errors,
        warnings,
        infos,
        patch_count: catalog.len(),
        findings,
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "validate: {}  patches={} errors={errors} warnings={warnings} infos={infos}\n",
            if ok { "OK" } else { "FAIL" },
            catalog.len()
        ));
        for f in &catalog.report.findings {
            out.push_str(&format!(
                "  [{:?}] +0x{:x} {:?}: {}\n",
                f.severity, f.offset, f.code, f.message
            ));
        }
        out
    });

    Ok(if ok { 0 } else { 1 })
}
