use miette::Result;
use serde::Serialize;

use super::{MatchArgs, OutputFormat};
use crate::output::{emit, hex_rev};
use crate::util::{default_limits, load_catalog, resolve_system};

#[derive(Serialize)]
struct MatchJson {
    cpu: CpuJson,
    best: Option<PatchJson>,
    applicable: Vec<PatchJson>,
    ambiguous: bool,
    considered: usize,
}

#[derive(Serialize)]
struct CpuJson {
    vendor: String,
    signature: String,
    platform_mask: Option<String>,
    current_revision: Option<String>,
}

#[derive(Serialize)]
struct PatchJson {
    revision: String,
    date: Option<String>,
    size: u32,
    source: String,
    sha256: Option<String>,
}

pub fn run(args: MatchArgs, format: OutputFormat) -> Result<i32> {
    let system = resolve_system(args.signature, args.vendor, args.platform_id, args.revision)?;
    let identity = system
        .primary_identity()
        .cloned()
        .ok_or_else(|| miette::miette!("no CPU identity available"))?;
    let catalog = load_catalog(&args.paths, default_limits(), false)?;
    let sel = catalog.select(&identity);

    let to_pj = |p: &ucode_core::PatchMeta| PatchJson {
        revision: hex_rev(p.revision),
        date: p.date.map(|d| d.to_string()),
        size: p.total_size,
        source: p.origin.source.clone(),
        sha256: p
            .sha256
            .map(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>()),
    };

    let json = MatchJson {
        cpu: CpuJson {
            vendor: identity.vendor.to_string(),
            signature: identity.signature.to_string(),
            platform_mask: identity.platform_mask.map(|m| m.to_string()),
            current_revision: identity.current_revision.map(hex_rev),
        },
        best: sel.best.map(to_pj),
        applicable: sel.applicable.iter().map(|p| to_pj(p)).collect(),
        ambiguous: sel.is_ambiguous(),
        considered: sel.considered.len(),
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "CPU: {} {} pf={} run={}\n",
            json.cpu.vendor,
            json.cpu.signature,
            json.cpu.platform_mask.as_deref().unwrap_or("?"),
            json.cpu.current_revision.as_deref().unwrap_or("-"),
        ));
        if let Some(b) = &json.best {
            out.push_str(&format!(
                "best: {} date={} size={} from {}\n",
                b.revision,
                b.date.as_deref().unwrap_or("-"),
                b.size,
                b.source
            ));
        } else {
            out.push_str("best: (none)\n");
        }
        out.push_str(&format!(
            "applicable: {}  ambiguous: {}  considered: {}\n",
            json.applicable.len(),
            json.ambiguous,
            json.considered
        ));
        for a in &json.applicable {
            out.push_str(&format!(
                "  {}  {}  {}\n",
                a.revision,
                a.date.as_deref().unwrap_or("-"),
                a.source
            ));
        }
        out
    });

    Ok(if sel.best.is_some() { 0 } else { 1 })
}
