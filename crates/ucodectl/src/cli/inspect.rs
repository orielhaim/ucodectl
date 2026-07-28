use miette::Result;
use serde::Serialize;
use ucode_catalog::Manifest;
use ucode_core::Severity;

use super::{InspectArgs, OutputFormat};
use crate::output::emit;
use crate::util::{apply_amd_sidecar, default_limits, load_catalog};

#[derive(Serialize)]
struct InspectJson {
    manifest: Manifest,
    findings: Vec<FindingJson>,
    sources: Vec<SourceJson>,
    failures: Vec<String>,
}

#[derive(Serialize)]
struct FindingJson {
    severity: String,
    code: String,
    offset: u64,
    message: String,
}

#[derive(Serialize)]
struct SourceJson {
    path: String,
    size: u64,
    format: String,
    patch_count: usize,
}

pub fn run(args: InspectArgs, format: OutputFormat) -> Result<i32> {
    let mut catalog = load_catalog(&args.paths, default_limits(), true)?;
    let _ = apply_amd_sidecar(&mut catalog, args.amd_readme.as_deref())?;
    let manifest = Manifest::from_catalog(&catalog, "ucodectl");

    let findings: Vec<FindingJson> = catalog
        .report
        .findings
        .iter()
        .map(|f| FindingJson {
            severity: format!("{:?}", f.severity).to_lowercase(),
            code: format!("{:?}", f.code),
            offset: f.offset,
            message: f.message.clone(),
        })
        .collect();

    let sources: Vec<SourceJson> = catalog
        .sources
        .iter()
        .map(|s| SourceJson {
            path: s.path.display().to_string(),
            size: s.size,
            format: format!("{:?}", s.format),
            patch_count: s.patch_count,
        })
        .collect();

    let failures: Vec<String> = catalog
        .failures
        .iter()
        .map(|(p, e)| format!("{}: {e}", p.display()))
        .collect();

    let json = InspectJson {
        manifest,
        findings,
        sources,
        failures: failures.clone(),
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "patches: {}  sources: {}  failures: {}\n",
            catalog.len(),
            catalog.sources.len(),
            catalog.failures.len()
        ));
        for e in &json.manifest.entries {
            out.push_str(&format!(
                "  {:5} {} pf={} rev={} date={} size={} sha={}\n",
                e.vendor,
                e.signature,
                e.platform_mask,
                e.revision,
                e.date.as_deref().unwrap_or("-"),
                e.size,
                e.sha256.as_deref().unwrap_or("-"),
            ));
            if !e.additional_signatures.is_empty() {
                out.push_str(&format!(
                    "        +{}\n",
                    e.additional_signatures.join(", ")
                ));
            }
        }
        for f in &catalog.report.findings {
            let sev = match f.severity {
                Severity::Error => "ERR",
                Severity::Warning => "WRN",
                Severity::Info => "INF",
            };
            out.push_str(&format!("  [{sev}] +0x{:x}: {}\n", f.offset, f.message));
        }
        for fail in &failures {
            out.push_str(&format!("  fail: {fail}\n"));
        }
        out
    });

    Ok(if catalog.report.has_errors() { 2 } else { 0 })
}
