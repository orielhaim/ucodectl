use miette::Result;
use ucode_boot::inspect_initrd;
use ucode_core::limits::Limits;
use ucode_policy::{PlanInput, evaluate};

use super::{OutputFormat, PlanArgs};
use crate::cli::plan_artifact::PlanArtifact;
use crate::output::{emit, hex_opt};
use crate::util::{default_limits, load_catalog_with_options, resolve_system};

pub fn run(args: PlanArgs, format: OutputFormat) -> Result<i32> {
    let system = resolve_system(None, None, args.intel_platform_id, None)?;
    let available = load_catalog_with_options(&args.paths, default_limits(), true, false)?;
    let limits = Limits::default();
    let embedded_insp = if let Some(boot) = &args.boot {
        Some(inspect_initrd(boot, &limits).map_err(|e| miette::miette!("{e}"))?)
    } else {
        None
    };

    let early_output = if args.early_output.is_absolute() {
        args.early_output.clone()
    } else {
        std::env::current_dir()
            .map_err(|e| miette::miette!("resolve plan output: {e}"))?
            .join(&args.early_output)
    };
    let plan = evaluate(&PlanInput {
        system: &system,
        available: &available,
        embedded: embedded_insp.as_ref().map(|i| &i.catalog),
        allow_downgrade: args.consider_downgrade,
        want_early_image: !matches!(args.deployment, super::DeploymentMode::None),
        early_output: Some(early_output.display().to_string()),
    });

    let artifact = PlanArtifact::create(
        plan.clone(),
        &args.paths,
        system.unique_identities.clone(),
        system.os.clone(),
        serde_json::to_value(system.virtualization)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string()),
        false,
    )?;
    if let Some(path) = &args.output_plan {
        artifact.write_to(path)?;
    }

    emit(format, &artifact, || {
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
        out.push_str(&format!("  plan id: {}\n", artifact.plan_id));
        if let Some(path) = &args.output_plan {
            out.push_str(&format!("  plan artifact: {}\n", path.display()));
        }
        out
    });

    Ok(0)
}
