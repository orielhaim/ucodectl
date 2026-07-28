use miette::Result;
use ucode_catalog::diff_catalogs;

use super::{DiffArgs, OutputFormat};
use crate::output::emit;
use crate::util::{default_limits, load_catalog};

pub fn run(args: DiffArgs, format: OutputFormat) -> Result<i32> {
    let old = load_catalog(&[args.old.clone()], default_limits(), false)?;
    let new = load_catalog(&[args.new.clone()], default_limits(), false)?;
    let diff = diff_catalogs(&old, &new, args.include_unchanged);

    emit(format, &diff, || {
        let mut out = String::new();
        out.push_str(&format!(
            "diff: +{} -{} ↑{} ↓{} ~{} ={}\n",
            diff.added, diff.removed, diff.upgraded, diff.downgraded, diff.changed, diff.unchanged
        ));
        for e in &diff.entries {
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
