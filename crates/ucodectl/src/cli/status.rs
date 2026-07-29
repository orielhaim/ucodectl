use miette::Result;
use serde::Serialize;
use ucode_boot::inspect_initrd;
use ucode_catalog::Catalog;
use ucode_core::RevisionObservation;
use ucode_core::limits::Limits;
use ucode_linux::{SystemState, VirtualizationKind};
use ucode_policy::{PlanInput, SystemStatus, evaluate};

use super::{OutputFormat, StatusArgs};
use crate::output::{emit, hex_rev};
use crate::util::{load_catalog, resolve_system};

#[derive(Serialize)]
struct StatusJson {
    os: String,
    kernel_release: Option<String>,
    environment: String,
    environment_reason: String,
    microcode_authority: String,
    hypervisor_vendor: Option<String>,
    sources: SourcesJson,
    catalog: CatalogJson,
    boot_artifact: BootJson,
    processors: Vec<ProcessorGroupJson>,
    result: ResultJson,
}

#[derive(Serialize)]
struct SourcesJson {
    identity: String,
    topology: String,
    active_revision: String,
    environment: String,
}

#[derive(Serialize)]
struct CatalogJson {
    state: String,
    patches: Option<usize>,
    matching_patches: Option<usize>,
}

#[derive(Serialize)]
struct BootJson {
    state: String,
    detail: String,
    embedded_patches: Option<usize>,
}

#[derive(Serialize)]
struct ProcessorGroupJson {
    logical_processors: Vec<u32>,
    logical_processor_count: usize,
    vendor: String,
    brand: Option<String>,
    signature: String,
    family: u32,
    model: u32,
    stepping: u32,
    platform_mask: Option<String>,
    active_revision: RevisionObservation,
    previous_revision: Option<RevisionObservation>,
    previous_revision_observations: usize,
    best_available_revision: Option<String>,
    embedded_revision: Option<String>,
    update_status: String,
}

#[derive(Serialize)]
struct ResultJson {
    state: String,
    reason: String,
}

struct Group<'a> {
    cpus: Vec<&'a ucode_linux::HostCpu>,
    evaluation: &'a ucode_policy::CpuEvaluation,
}

pub fn run(args: StatusArgs, format: OutputFormat, verbose: u8) -> Result<i32> {
    let system = resolve_system(None, None, args.platform_id, None)?;
    let limits = Limits::default();
    let sources = if args.sources.is_empty() {
        ucode_linux::paths::default_firmware_paths()
            .into_iter()
            .filter(|p| p.exists())
            .collect::<Vec<_>>()
    } else {
        args.sources.clone()
    };
    let catalog_loaded = !sources.is_empty();
    let available = if catalog_loaded {
        load_catalog(&sources, limits, false)?
    } else {
        Catalog::default()
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

    let catalog_state = if catalog_loaded {
        "loaded"
    } else {
        "not_loaded"
    };
    let matching =
        catalog_loaded.then(|| plan.cpus.iter().filter(|c| c.best_patch.is_some()).count());
    let (boot_state, boot_detail) = boot_state(&system, embedded_catalog.is_some());
    let (result_state, result_reason) = result_state(&system, catalog_loaded, &plan.overall_status);
    let groups = groups(&system, &plan, args.per_cpu);
    let json = StatusJson {
        os: system.os.clone(),
        kernel_release: system.kernel_release.clone(),
        environment: format!("{:?}", system.virtualization),
        environment_reason: system.virtualization_info.reason.clone(),
        microcode_authority: format!("{:?}", system.virtualization_info.authority),
        hypervisor_vendor: system.virtualization_info.hypervisor_vendor.clone(),
        sources: source_summary(&system),
        catalog: CatalogJson {
            state: catalog_state.into(),
            patches: catalog_loaded.then_some(available.len()),
            matching_patches: matching,
        },
        boot_artifact: BootJson {
            state: boot_state.into(),
            detail: boot_detail.into(),
            embedded_patches: embedded.map(|c| c.len()),
        },
        processors: groups.iter().map(group_json).collect(),
        result: ResultJson {
            state: result_state.into(),
            reason: result_reason.into(),
        },
    };

    emit(format, &json, || human(&json, &groups, args.raw, verbose));
    Ok(0)
}

fn source_summary(system: &SystemState) -> SourcesJson {
    SourcesJson {
        identity: system.source.clone(),
        topology: if system.source == "proc" {
            "procfs/sysfs".into()
        } else {
            "Windows processor APIs".into()
        },
        active_revision: if cfg!(windows) {
            "Windows registry".into()
        } else if system.source == "proc" {
            "/proc/cpuinfo, sysfs when available".into()
        } else {
            "unavailable".into()
        },
        environment: if system.source == "proc" {
            "kernel markers + CPUID".into()
        } else {
            "CPUID".into()
        },
    }
}

fn boot_state(system: &SystemState, inspected: bool) -> (&'static str, &'static str) {
    if inspected {
        return ("inspected", "an explicit initrd or UKI was inspected");
    }
    if system.virtualization == VirtualizationKind::VirtualMachineGuest {
        return (
            "not_applicable",
            "WSL/guest does not control the physical machine early-boot path",
        );
    }
    if system.os != "linux" {
        return (
            "not_applicable",
            "Linux early-boot artifacts are not applicable on this OS",
        );
    }
    (
        "not_inspected",
        "pass --boot <initrd-or-uki> to inspect an artifact",
    )
}

fn result_state(
    system: &SystemState,
    catalog_loaded: bool,
    policy: &SystemStatus,
) -> (&'static str, &'static str) {
    if system.virtualization == VirtualizationKind::VirtualMachineGuest {
        return (
            "host_managed",
            "this guest can inspect microcode files but cannot evaluate or deploy the physical CPU microcode",
        );
    }
    if !catalog_loaded {
        return ("not_evaluable", "no microcode catalog was loaded");
    }
    (policy.as_str(), "catalog evaluation completed")
}

fn groups<'a>(
    system: &'a SystemState,
    plan: &'a ucode_policy::Plan,
    per_cpu: bool,
) -> Vec<Group<'a>> {
    let mut out: Vec<Group<'a>> = Vec::new();
    for (cpu, evaluation) in system.cpus.iter().zip(plan.cpus.iter()) {
        if !per_cpu {
            if let Some(existing) = out.iter_mut().find(|g| {
                let first = g.cpus[0];
                first.identity == cpu.identity
                    && first.brand == cpu.brand
                    && same_revision_observation(&first.revision, &cpu.revision)
                    && g.evaluation.status == evaluation.status
                    && g.evaluation.best_available_revision == evaluation.best_available_revision
                    && g.evaluation.embedded_revision == evaluation.embedded_revision
            }) {
                existing.cpus.push(cpu);
                continue;
            }
        }
        out.push(Group {
            cpus: vec![cpu],
            evaluation,
        });
    }
    out
}

fn same_revision_observation(left: &RevisionObservation, right: &RevisionObservation) -> bool {
    left.known_revision() == right.known_revision() && left.source() == right.source()
}

fn group_json(group: &Group<'_>) -> ProcessorGroupJson {
    let cpu = group.cpus[0];
    ProcessorGroupJson {
        logical_processors: group.cpus.iter().map(|c| c.processor).collect(),
        logical_processor_count: group.cpus.len(),
        vendor: cpu.identity.vendor.to_string(),
        brand: cpu.brand.clone(),
        signature: cpu.identity.signature.to_string(),
        family: cpu.identity.family(),
        model: cpu.identity.model(),
        stepping: cpu.identity.stepping(),
        platform_mask: cpu.identity.platform_mask.map(|m| m.to_string()),
        active_revision: cpu.revision.clone(),
        previous_revision: cpu.previous_revision.clone(),
        previous_revision_observations: group
            .cpus
            .iter()
            .filter(|cpu| cpu.previous_revision.is_some())
            .count(),
        best_available_revision: group.evaluation.best_available_revision.map(hex_rev),
        embedded_revision: group.evaluation.embedded_revision.map(hex_rev),
        update_status: group.evaluation.status.as_str().into(),
    }
}

fn human(json: &StatusJson, groups: &[Group<'_>], raw: bool, verbose: u8) -> String {
    let mut out = String::from("ucodectl status\n\nSystem\n");
    out.push_str(&format!("  OS: {}\n", json.os));
    if let Some(kernel) = &json.kernel_release {
        out.push_str(&format!("  Kernel: {kernel}\n"));
    }
    out.push_str(&format!(
        "  Environment: {}\n",
        display_name(&json.environment)
    ));
    if let Some(hv) = &json.hypervisor_vendor {
        out.push_str(&format!("  Hypervisor: {hv}\n"));
    }
    out.push_str(&format!(
        "  Microcode authority: {}\n",
        display_name(&json.microcode_authority)
    ));
    if verbose > 0 {
        out.push_str(&format!(
            "  Environment evidence: {}\n",
            json.environment_reason
        ));
    }

    out.push_str("\nProcessor\n");
    for (index, group) in groups.iter().enumerate() {
        let cpu = group.cpus[0];
        out.push_str(&format!("  CPU group {index}\n"));
        if let Some(brand) = &cpu.brand {
            out.push_str(&format!("    Model: {brand}\n"));
        }
        out.push_str(&format!("    Vendor: {}\n    Signature: {}\n    Family / model / stepping: {} / {} / {}\n    Logical processors: {}\n", cpu.identity.vendor, cpu.identity.signature, cpu.identity.family(), cpu.identity.model(), cpu.identity.stepping(), group.cpus.len()));
        out.push_str(&format!(
            "    Active revision: {}\n",
            revision_text(&cpu.revision)
        ));
        out.push_str(&format!(
            "    Revision source: {}\n",
            display_name(&format!("{:?}", cpu.revision.source()))
        ));
        if let Some(previous) = &cpu.previous_revision {
            out.push_str(&format!(
                "    Previous update revision: {} (available on {}/{})\n",
                revision_text(previous),
                group
                    .cpus
                    .iter()
                    .filter(|cpu| cpu.previous_revision.is_some())
                    .count(),
                group.cpus.len(),
            ));
        }
        if raw {
            out.push_str(&format!(
                "    Raw observation: {}\n",
                raw_revision(&cpu.revision)
            ));
        }
        if let Some(best) = group.evaluation.best_available_revision {
            out.push_str(&format!("    Best matching revision: {}\n", hex_rev(best)));
        }
    }

    out.push_str("\nCatalog\n");
    out.push_str(&format!("  State: {}\n", display_name(&json.catalog.state)));
    match json.catalog.patches {
        Some(count) => out.push_str(&format!(
            "  Patches: {count}\n  Matching patches: {}\n",
            json.catalog.matching_patches.unwrap_or(0)
        )),
        None => out.push_str("  Matching update: not evaluated\n"),
    }
    out.push_str("\nBoot deployment\n");
    out.push_str(&format!(
        "  State: {}\n  {}\n",
        display_name(&json.boot_artifact.state),
        json.boot_artifact.detail
    ));
    out.push_str("\nResult\n");
    out.push_str(&format!(
        "  State: {}\n  Reason: {}\n",
        display_name(&json.result.state),
        json.result.reason
    ));
    if json.catalog.state == "not_loaded" {
        out.push_str("\nNext:\n  ucodectl status --source <microcode-release>\n");
    }
    out
}

fn revision_text(value: &RevisionObservation) -> String {
    match value {
        RevisionObservation::Known { revision, .. } => hex_rev(*revision),
        RevisionObservation::Unavailable { reason, .. } => format!("unavailable ({reason})"),
        RevisionObservation::Unsupported { reason, .. } => format!("unsupported ({reason})"),
        RevisionObservation::Invalid { reason, .. } => format!("invalid ({reason})"),
    }
}

fn raw_revision(value: &RevisionObservation) -> String {
    match value {
        RevisionObservation::Known {
            raw_value: Some(bytes),
            ..
        }
        | RevisionObservation::Invalid {
            raw_value: bytes, ..
        } => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        _ => "(none)".into(),
    }
}

fn display_name(value: &str) -> String {
    match value {
        "HypervisorRoot" => return "Hyper-V root partition".into(),
        "VirtualMachineGuest" => return "Virtual machine guest".into(),
        "FirmwareAndOperatingSystem" => return "Firmware and operating system".into(),
        "HypervisorHost" => return "Hypervisor host".into(),
        _ => {}
    }
    let mut out = String::new();
    for (i, word) in value.split('_').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    out
}
