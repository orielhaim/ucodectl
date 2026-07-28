use miette::Result;
use serde::Serialize;
use ucode_policy::{PlanInput, evaluate};

use super::{OutputFormat, VerifyArgs};
use crate::output::{emit, hex_opt, hex_rev};
use crate::util::{default_limits, load_catalog, resolve_system};

#[derive(Serialize)]
struct VerifyJson {
    ok: bool,
    overall_status: String,
    cpus: Vec<CpuV>,
    messages: Vec<String>,
}

#[derive(Serialize)]
struct CpuV {
    processor: u32,
    running: Option<String>,
    expected_min: Option<String>,
    best_available: Option<String>,
    ok: bool,
}

pub fn run(args: VerifyArgs, format: OutputFormat) -> Result<i32> {
    let system = resolve_system(None, None, args.platform_id, None)?;
    let available = if args.sources.is_empty() {
        ucode_catalog::Catalog::default()
    } else {
        load_catalog(&args.sources, default_limits(), false)?
    };

    let plan = evaluate(&PlanInput {
        system: &system,
        available: &available,
        embedded: None,
        allow_downgrade: false,
        want_early_image: false,
        early_output: None,
    });

    let mut all_ok = true;
    let mut cpus = Vec::new();
    for c in &plan.cpus {
        let mut ok = true;
        if let Some(expect) = args.expect_revision {
            match c.running_revision {
                Some(run) if run >= expect => {}
                Some(_) | None => ok = false,
            }
        } else {
            // Default: running should match best when catalog given.
            if let (Some(run), Some(best)) = (c.running_revision, c.best_available_revision) {
                if run < best {
                    ok = false;
                }
            }
        }
        if !ok {
            all_ok = false;
        }
        cpus.push(CpuV {
            processor: c.processor,
            running: c.running_revision.map(hex_rev),
            expected_min: args.expect_revision.map(hex_rev),
            best_available: c.best_available_revision.map(hex_rev),
            ok,
        });
    }

    let json = VerifyJson {
        ok: all_ok,
        overall_status: plan.overall_status.as_str().to_string(),
        cpus,
        messages: plan.messages,
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "verify: {}  overall={}\n",
            if json.ok { "OK" } else { "FAIL" },
            json.overall_status
        ));
        for c in &json.cpus {
            out.push_str(&format!(
                "  cpu{} run={} best={} expect={}  {}\n",
                c.processor,
                c.running.as_deref().unwrap_or("-"),
                c.best_available.as_deref().unwrap_or("-"),
                c.expected_min.as_deref().unwrap_or("-"),
                if c.ok { "ok" } else { "FAIL" },
            ));
        }
        // silence unused
        let _ = hex_opt(None);
        out
    });

    Ok(if all_ok { 0 } else { 1 })
}
