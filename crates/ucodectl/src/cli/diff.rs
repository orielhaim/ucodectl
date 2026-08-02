use miette::Result;
use serde::Serialize;
use ucode_catalog::diff_catalogs;

use super::{DiffArgs, OutputFormat};
use crate::output::emit;
use crate::util::{default_limits, load_catalog};

#[derive(Serialize)]
struct DiffJson {
    schema_version: u32,
    command: &'static str,
    #[serde(flatten)]
    diff: ucode_catalog::CatalogDiff,
}

pub fn run(args: DiffArgs, format: OutputFormat) -> Result<i32> {
    let old = load_catalog(std::slice::from_ref(&args.old), default_limits(), false)?;
    let new = load_catalog(std::slice::from_ref(&args.new), default_limits(), false)?;
    let diff = diff_catalogs(&old, &new, args.include_unchanged);

    let json = DiffJson {
        schema_version: 1,
        command: "diff",
        diff,
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "diff: +{} -{} ↑{} ↓{} ~{} ={}\n",
            json.diff.added,
            json.diff.removed,
            json.diff.upgraded,
            json.diff.downgraded,
            json.diff.changed,
            json.diff.unchanged
        ));
        for e in &json.diff.entries {
            out.push_str(&format!(
                "  [{:?}] {} {} pf={}  {} → {}\n",
                e.kind,
                e.vendor,
                e.signature,
                e.platform_mask,
                e.old_revision.as_deref().unwrap_or("-"),
                e.new_revision.as_deref().unwrap_or("-"),
            ));
        }
        out
    });

    Ok(0)
}
