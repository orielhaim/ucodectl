use miette::Result;
use ucode_boot::inspect_initrd;
use ucode_core::limits::Limits;
use ucode_policy::{PlanInput, evaluate};

use super::{OutputFormat, PlanArgs};
use crate::output::{emit, hex_opt};
use crate::util::{default_limits, load_catalog, resolve_system};

pub fn run(args: PlanArgs, format: OutputFormat) -> Result<i32> {
    let system = resolve_system(None, None, args.platform_id, None)?;
    let available = load_catalog(&args.paths, default_limits(), true)?;
    let limits = Limits::default();
    let embedded_insp = if let Some(boot) = &args.boot {
        Some(inspect_initrd(boot, &limits).map_err(|e| miette::miette!("{e}"))?)
    } else {
        None
    };

    let plan = evaluate(&PlanInput {
        system: &system,
        available: &available,
        embedded: embedded_insp.as_ref().map(|i| &i.catalog),
        allow_downgrade: args.allow_downgrade,
        want_early_image: args.want_early,
        early_output: Some(args.early_output.display().to_string()),
    });

    emit(format, &plan, || {
        let mut out = String::new();
        out.push_str(&format!(
            "plan v{}  status={}  action={:?}  would_change={}\n",
            plan.plan_version,
            plan.overall_status.as_str(),
            plan.action,
            plan.would_change
        ));
        for c in &plan.cpus {
            out.push_str(&format!(
                "  cpu{}: {} run={} best={} emb={}  [{}]\n",
                c.processor,
                c.identity.signature,
                hex_opt(c.running_revision),
                hex_opt(c.best_available_revision),
                hex_opt(c.embedded_revision),
                c.status.as_str(),
            ));
            for r in &c.reasons {
                out.push_str(&format!("    - {r}\n"));
            }
        }
        for w in &plan.writes {
            out.push_str(&format!("  write: {w:?}\n"));
        }
        for m in &plan.messages {
            out.push_str(&format!("  note: {m}\n"));
        }
        out
    });

    Ok(0)
}
