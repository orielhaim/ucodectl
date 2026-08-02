use miette::Result;
use serde::Serialize;
use ucode_core::{CpuSignature, Vendor};

use super::{ListArgs, OutputFormat};
use crate::output::emit;
use crate::util::{default_limits, load_catalog};

#[derive(Serialize)]
struct ListJson {
    schema_version: u32,
    command: &'static str,
    patches: Vec<Row>,
    count: usize,
}

#[derive(Serialize)]
struct Row {
    vendor: String,
    signature: String,
    platform_mask: String,
    revision: String,
    date: Option<String>,
    size: u32,
    source: String,
    offset: u64,
}

pub fn run(args: ListArgs, format: OutputFormat) -> Result<i32> {
    let catalog = load_catalog(&args.paths, default_limits(), false)?;
    let vendor_filter: Option<Vendor> = args.vendor.map(Into::into);
    let signature_filter = args.signature.map(CpuSignature);

    let mut rows = Vec::new();
    for p in &catalog.patches {
        if let Some(v) = vendor_filter
            && p.vendor != v
        {
            continue;
        }
        if let Some(signature) = signature_filter
            && !p.matches.iter().any(|m| m.signature == signature)
        {
            continue;
        }
        let primary = p.primary_match();
        rows.push(Row {
            vendor: p.vendor.to_string(),
            signature: primary.map(|m| m.signature.to_string()).unwrap_or_default(),
            platform_mask: primary
                .map(|m| m.platform_mask.to_string())
                .unwrap_or_default(),
            revision: format!("0x{:08x}", p.revision),
            date: p.date.map(|d| d.to_string()),
            size: p.total_size,
            source: p.origin.source.clone(),
            offset: p.origin.offset,
        });
    }

    if args.latest_only {
        rows.sort_by(|a, b| {
            a.vendor
                .cmp(&b.vendor)
                .then_with(|| a.signature.cmp(&b.signature))
                .then_with(|| a.platform_mask.cmp(&b.platform_mask))
                .then_with(|| b.revision.cmp(&a.revision))
        });
        rows.dedup_by(|a, b| {
            a.vendor == b.vendor && a.signature == b.signature && a.platform_mask == b.platform_mask
        });
    }

    let json = ListJson {
        schema_version: 1,
        command: "list",
        count: rows.len(),
        patches: rows,
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "{:<6} {:<12} {:<6} {:<12} {:<12} {:>8}  {}\n",
            "VENDOR", "SIGNATURE", "PF", "REVISION", "DATE", "SIZE", "SOURCE"
        ));
        for r in &json.patches {
            out.push_str(&format!(
                "{:<6} {:<12} {:<6} {:<12} {:<12} {:>8}  {}+0x{:x}\n",
                r.vendor,
                r.signature,
                r.platform_mask,
                r.revision,
                r.date.as_deref().unwrap_or("-"),
                r.size,
                r.source,
                r.offset,
            ));
        }
        out.push_str(&format!("total: {}\n", json.count));
        out
    });

    Ok(0)
}
