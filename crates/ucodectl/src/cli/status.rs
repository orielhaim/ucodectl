use miette::Result;
use serde::Serialize;
use ucode_boot::inspect_initrd;
use ucode_catalog::Catalog;
use ucode_core::limits::Limits;
use ucode_linux::paths::default_firmware_paths;
use ucode_policy::{PlanInput, evaluate};

use super::{OutputFormat, StatusArgs};
use crate::output::{emit, hex_opt};
use crate::util::{load_catalog, resolve_system};

#[derive(Serialize)]
struct StatusJson {
    source: String,
    os: String,
    kernel_release: Option<String>,
    virtualization: String,
    virtualization_reason: String,
    hypervisor_vendor: Option<String>,
    hypervisor_bit: bool,
    hyperv_root: bool,
    mixed_signature: bool,
    mixed_revision: bool,
    cpus: Vec<CpuJson>,
    overall_status: String,
    messages: Vec<String>,
    available_patches: usize,
    embedded_patches: Option<usize>,
}

#[derive(Serialize)]
struct CpuJson {
    processor: u32,
    vendor: String,
    brand: Option<String>,
    signature: String,
    family: u32,
    model: u32,
    stepping: u32,
    platform_mask: Option<String>,
    running_revision: Option<String>,
    best_available: Option<String>,
    embedded_revision: Option<String>,
    status: String,
}

pub fn run(args: StatusArgs, format: OutputFormat) -> Result<i32> {
    let system = resolve_system(None, None, args.platform_id, None)?;
    let limits = Limits::default();

    let sources = if args.sources.is_empty() {
        default_firmware_paths()
            .into_iter()
            .filter(|p| p.exists())
            .collect()
    } else {
        args.sources.clone()
    };

    let available = if sources.is_empty() {
        Catalog::default()
    } else {
        load_catalog(&sources, limits, false)?
    };

    let embedded_catalog = if let Some(boot) = &args.boot {
        Some(inspect_initrd(boot, &limits).map_err(|e| miette::miette!("{e}"))?)
    } else {
        None
    };
    let embedded = embedded_catalog.as_ref().map(|i| &i.catalog);

    let plan = evaluate(&PlanInput {
        system: &system,
        available: &available,
        embedded,
        allow_downgrade: false,
        want_early_image: false,
        early_output: None,
    });

    let json = StatusJson {
        source: system.source.clone(),
        os: system.os.clone(),
        kernel_release: system.kernel_release.clone(),
        virtualization: format!("{:?}", system.virtualization),
        virtualization_reason: system.virtualization_info.reason.clone(),
        hypervisor_vendor: system.virtualization_info.hypervisor_vendor.clone(),
        hypervisor_bit: system.virtualization_info.hypervisor_bit,
        hyperv_root: system.virtualization_info.hyperv_root,
        mixed_signature: system.mixed_signature,
        mixed_revision: system.mixed_revision,
        overall_status: plan.overall_status.as_str().to_string(),
        messages: plan.messages.clone(),
        available_patches: available.len(),
        embedded_patches: embedded.map(|c| c.len()),
        cpus: plan
            .cpus
            .iter()
            .zip(system.cpus.iter())
            .map(|(c, host)| CpuJson {
                processor: c.processor,
                vendor: c.identity.vendor.to_string(),
                brand: host.brand.clone(),
                signature: c.identity.signature.to_string(),
                family: c.identity.family(),
                model: c.identity.model(),
                stepping: c.identity.stepping(),
                platform_mask: c.identity.platform_mask.map(|m| m.to_string()),
                running_revision: c.running_revision.map(crate::output::hex_rev),
                best_available: c.best_available_revision.map(crate::output::hex_rev),
                embedded_revision: c.embedded_revision.map(crate::output::hex_rev),
                status: c.status.as_str().to_string(),
            })
            .collect(),
    };

    emit(format, &json, || {
        let mut out = String::new();
        out.push_str(&format!(
            "ucodectl status  (os: {}, discovery: {}, virt: {:?})\n",
            system.os, system.source, system.virtualization
        ));
        out.push_str(&format!(
            "virt detail: {}{}\n",
            system.virtualization_info.reason,
            system
                .virtualization_info
                .hypervisor_vendor
                .as_ref()
                .map(|v| format!(" [hv={v}]"))
                .unwrap_or_default()
        ));
        if let Some(rel) = &system.kernel_release {
            out.push_str(&format!("kernel: {rel}\n"));
        }
        out.push_str(&format!("overall: {}\n", plan.overall_status.as_str()));
        out.push_str(&format!(
            "available patches: {}  embedded: {}\n",
            available.len(),
            embedded
                .map(|c| c.len().to_string())
                .unwrap_or_else(|| "-".into())
        ));
        out.push_str("\nCPUs:\n");
        for (c, host) in plan.cpus.iter().zip(system.cpus.iter()) {
            if let Some(brand) = &host.brand {
                out.push_str(&format!("  cpu{}  {brand}\n", c.processor));
            }
            out.push_str(&format!(
                "  cpu{:<3} {} sig={} f/m/s={}/{}/{} run={} best={} emb={}  [{}]\n",
                c.processor,
                c.identity.vendor,
                c.identity.signature,
                c.identity.family(),
                c.identity.model(),
                c.identity.stepping(),
                hex_opt(c.running_revision),
                hex_opt(c.best_available_revision),
                hex_opt(c.embedded_revision),
                c.status.as_str(),
            ));
        }
        for m in &plan.messages {
            out.push_str(&format!("note: {m}\n"));
        }
        out
    });

    Ok(0)
}
