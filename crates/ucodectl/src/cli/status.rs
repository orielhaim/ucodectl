use miette::Result;
use serde::Serialize;
use ucode_boot::inspect_initrd;
use ucode_catalog::Catalog;
use ucode_core::limits::Limits;
use ucode_core::{ObservationScope, RevisionObservation, RevisionSource};
use ucode_linux::{MicrocodeAuthority, SystemState, VirtualizationKind, WindowsMicrocodeMetadata};
use ucode_policy::{PlanInput, SystemStatus, evaluate};

use super::{OutputFormat, StatusArgs};
use crate::output::{emit, hex_rev};
use crate::util::{load_catalog, resolve_system};

const STATUS_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct StatusJson {
    schema_version: u32,
    command: &'static str,
    tool: ToolJson,
    os: String,
    kernel_release: Option<String>,
    environment: String,
    environment_reason: String,
    microcode_authority: String,
    hypervisor_vendor: Option<String>,
    overrides: OverridesJson,
    sources: SourcesJson,
    catalog: CatalogJson,
    boot_artifact: BootJson,
    windows_microcode: Option<WindowsMicrocodeJson>,
    processors: Vec<ProcessorGroupJson>,
    result: ResultJson,
}

#[derive(Serialize)]
struct ToolJson {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct OverridesJson {
    intel_platform_id: Option<u32>,
    scope: Option<&'static str>,
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
    source_state: String,
    patches: Option<usize>,
    matching_patches: Option<usize>,
    failures: usize,
}

#[derive(Serialize)]
struct BootJson {
    state: String,
    detail: String,
    embedded_patches: Option<usize>,
}

#[derive(Serialize)]
struct WindowsMicrocodeJson {
    current_revision: Option<RevisionObservation>,
    previous_revision: Option<RevisionObservation>,
    registry_keys_observed: usize,
    logical_processor_count: usize,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    active_revision: Option<RevisionObservation>,
    best_available_revision: Option<String>,
    embedded_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_evaluation: Option<UpdateEvaluationJson>,
}

#[derive(Serialize)]
struct UpdateEvaluationJson {
    state: String,
    reason: &'static str,
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
    let system = resolve_system(None, None, args.intel_platform_id, None)?;
    let limits = Limits::default();
    let source_supplied = !args.sources.is_empty();
    let sources = if source_supplied {
        args.sources.clone()
    } else {
        ucode_linux::paths::default_firmware_paths()
            .into_iter()
            .filter(|p| p.exists())
            .collect::<Vec<_>>()
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
    let source_state = catalog_source_state(source_supplied, catalog_loaded, &available);
    let matching =
        catalog_loaded.then(|| plan.cpus.iter().filter(|c| c.best_patch.is_some()).count());
    let (boot_state, boot_detail) = boot_state(&system, embedded_catalog.is_some());
    let (result_state, result_reason) = result_state(
        &system,
        catalog_loaded,
        source_supplied,
        &plan.overall_status,
    );
    let groups = groups(&system, &plan, args.per_cpu);
    let json = StatusJson {
        schema_version: STATUS_SCHEMA_VERSION,
        command: "status",
        tool: ToolJson {
            name: "ucodectl",
            version: env!("CARGO_PKG_VERSION"),
        },
        os: system.os.clone(),
        kernel_release: system.kernel_release.clone(),
        environment: environment_key(system.virtualization),
        environment_reason: system.virtualization_info.reason.clone(),
        microcode_authority: authority_key(system.virtualization_info.authority),
        hypervisor_vendor: system
            .virtualization_info
            .hypervisor_vendor
            .as_deref()
            .map(hypervisor_vendor_key),
        overrides: OverridesJson {
            intel_platform_id: args.intel_platform_id,
            scope: args.intel_platform_id.map(|_| "matching_diagnostics_only"),
        },
        sources: source_summary(&system),
        catalog: CatalogJson {
            state: catalog_state.into(),
            source_state: source_state.into(),
            patches: catalog_loaded.then_some(available.len()),
            matching_patches: matching,
            failures: available.failures.len(),
        },
        boot_artifact: BootJson {
            state: boot_state.into(),
            detail: boot_detail.into(),
            embedded_patches: embedded.map(|c| c.len()),
        },
        windows_microcode: system
            .windows_microcode
            .as_ref()
            .map(windows_microcode_json),
        processors: groups
            .iter()
            .map(|group| group_json(group, catalog_loaded))
            .collect(),
        result: ResultJson {
            state: result_state.into(),
            reason: result_reason.into(),
        },
    };

    emit(format, &json, || {
        human(&json, &groups, args.per_cpu, args.raw, verbose)
    });
    Ok(0)
}

fn catalog_source_state(
    source_supplied: bool,
    catalog_loaded: bool,
    catalog: &Catalog,
) -> &'static str {
    if !catalog_loaded {
        return "no_source_supplied_and_no_default_discovered";
    }
    if !catalog.failures.is_empty() && catalog.sources.is_empty() {
        return if source_supplied {
            "explicit_source_parse_failed"
        } else {
            "default_source_parse_failed"
        };
    }
    if !catalog.sources.is_empty() && catalog.is_empty() {
        return "catalog_loaded_empty";
    }
    if source_supplied {
        "explicit_source_supplied"
    } else {
        "default_sources_discovered"
    }
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
    source_supplied: bool,
    policy: &SystemStatus,
) -> (&'static str, &'static str) {
    if system.virtualization == VirtualizationKind::VirtualMachineGuest {
        return (
            "host_managed",
            "this guest can inspect microcode files but cannot evaluate or deploy the physical CPU microcode",
        );
    }
    if !catalog_loaded {
        return if source_supplied {
            (
                "not_evaluable",
                "the supplied microcode source did not produce a catalog",
            )
        } else {
            (
                "not_evaluable",
                "no microcode source was supplied and no default catalog was discovered",
            )
        };
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
        if !per_cpu
            && let Some(existing) = out.iter_mut().find(|g| {
                let first = g.cpus[0];
                first.identity == cpu.identity
                    && first.brand == cpu.brand
                    && same_revision_observation(&first.revision, &cpu.revision)
                    && g.evaluation.status == evaluation.status
                    && g.evaluation.best_available_revision == evaluation.best_available_revision
                    && g.evaluation.embedded_revision == evaluation.embedded_revision
            })
        {
            existing.cpus.push(cpu);
            continue;
        }
        out.push(Group {
            cpus: vec![cpu],
            evaluation,
        });
    }
    out
}

fn same_revision_observation(left: &RevisionObservation, right: &RevisionObservation) -> bool {
    left.known_revision() == right.known_revision()
        && left.source() == right.source()
        && left.scope() == right.scope()
        && left.confidence() == right.confidence()
}

fn windows_microcode_json(metadata: &WindowsMicrocodeMetadata) -> WindowsMicrocodeJson {
    WindowsMicrocodeJson {
        current_revision: metadata.current_revision.clone(),
        previous_revision: metadata.previous_revision.clone(),
        registry_keys_observed: metadata.registry_keys_observed,
        logical_processor_count: metadata.logical_processor_count,
    }
}

fn group_json(group: &Group<'_>, catalog_loaded: bool) -> ProcessorGroupJson {
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
        active_revision: (!cfg!(windows)).then(|| cpu.revision.clone()),
        best_available_revision: group.evaluation.best_available_revision.map(hex_rev),
        embedded_revision: group.evaluation.embedded_revision.map(hex_rev),
        update_evaluation: catalog_loaded.then_some(UpdateEvaluationJson {
            state: group.evaluation.status.as_str().into(),
            reason: "catalog_evaluated",
        }),
    }
}

fn human(json: &StatusJson, groups: &[Group<'_>], per_cpu: bool, raw: bool, verbose: u8) -> String {
    let mut out = String::from("ucodectl status\n\nSystem\n");
    out.push_str(&format!("  OS: {}\n", os_label(&json.os)));
    if let Some(kernel) = &json.kernel_release {
        out.push_str(&format!("  Kernel: {kernel}\n"));
    }
    out.push_str(&format!(
        "  Environment: {}\n",
        environment_label(&json.environment)
    ));
    if let Some(hv) = &json.hypervisor_vendor {
        out.push_str(&format!("  Hypervisor: {}\n", hypervisor_vendor_label(hv)));
    }
    out.push_str(&format!(
        "  Microcode authority: {}\n",
        authority_label(&json.microcode_authority)
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
        let field_indent = if per_cpu || groups.len() > 1 {
            "    "
        } else {
            "  "
        };
        if per_cpu {
            out.push_str(&format!("  Logical processor {}\n", cpu.processor));
        } else if groups.len() > 1 {
            out.push_str(&format!("  Processor group {index}\n"));
        }
        if let Some(brand) = &cpu.brand {
            out.push_str(&format!("{field_indent}Model: {brand}\n"));
        }
        out.push_str(&format!(
            "{field_indent}Vendor: {}\n{field_indent}Signature: {}\n{field_indent}Family / model / stepping: {} / {} / {}\n",
            cpu.identity.vendor,
            cpu.identity.signature,
            cpu.identity.family(),
            cpu.identity.model(),
            cpu.identity.stepping(),
        ));
        if !per_cpu {
            out.push_str(&format!(
                "{field_indent}Logical processors: {}\n",
                group.cpus.len()
            ));
        }
        if !cfg!(windows) {
            out.push_str(&format!(
                "{field_indent}Active revision: {}\n{field_indent}Source: {}\n{field_indent}Scope: {}\n",
                revision_text(&cpu.revision),
                revision_source_label(cpu.revision.source()),
                scope_label(cpu.revision.scope()),
            ));
            if raw {
                out.push_str(&format!(
                    "{field_indent}Raw observation: {}\n",
                    raw_revision(&cpu.revision)
                ));
            }
        }
        if let Some(best) = group.evaluation.best_available_revision {
            out.push_str(&format!(
                "{field_indent}Best matching revision: {}\n",
                hex_rev(best)
            ));
        }
        if group.evaluation.best_available_revision.is_none()
            && !json.catalog.state.eq("not_loaded")
        {
            out.push_str(&format!(
                "{field_indent}Update evaluation: no applicable patch\n"
            ));
        }
    }

    if let Some(metadata) = &json.windows_microcode {
        out.push_str("\nWindows microcode metadata\n");
        if let Some(current) = &metadata.current_revision {
            out.push_str(&format!(
                "  Current update revision: {}\n",
                revision_text(current)
            ));
        }
        if let Some(previous) = &metadata.previous_revision {
            out.push_str(&format!(
                "  Previous update revision: {}\n",
                revision_text(previous)
            ));
        }
        out.push_str(&format!(
            "  Registry entries observed: {} of {}\n",
            metadata.registry_keys_observed, metadata.logical_processor_count
        ));
        if same_known_revision(
            metadata.current_revision.as_ref(),
            metadata.previous_revision.as_ref(),
        ) {
            out.push_str("  Windows reports the same previous and current revision\n");
            if verbose > 0 {
                out.push_str("  No transition can be inferred from these registry values alone\n");
            }
        }
    }

    if let Some(id) = json.overrides.intel_platform_id {
        out.push_str("\nOverride\n");
        out.push_str(&format!("  Intel platform ID: {id}\n"));
        out.push_str("  Scope: matching diagnostics only\n");
    }

    out.push_str("\nCatalog\n");
    if json.catalog.state == "not_loaded" {
        out.push_str("  Not loaded\n");
    } else {
        out.push_str(&format!(
            "  Patches: {}\n",
            json.catalog.patches.unwrap_or(0)
        ));
        out.push_str(&format!(
            "  Matching patches: {}\n",
            json.catalog.matching_patches.unwrap_or(0)
        ));
        if json.catalog.failures > 0 {
            out.push_str(&format!("  Source failures: {}\n", json.catalog.failures));
        }
    }
    out.push_str("\nBoot deployment\n");
    out.push_str(&format!(
        "  State: {}\n  {}\n",
        state_label(&json.boot_artifact.state),
        json.boot_artifact.detail
    ));
    out.push_str("\nResult\n");
    out.push_str(&format!(
        "  State: {}\n  Reason: {}\n",
        state_label(&json.result.state),
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
        RevisionObservation::Known { raw: Some(raw), .. }
        | RevisionObservation::Invalid { raw, .. } => {
            format!("{} {}", raw.encoding, raw.hex)
        }
        _ => "(none)".into(),
    }
}

fn same_known_revision(
    current: Option<&RevisionObservation>,
    previous: Option<&RevisionObservation>,
) -> bool {
    current
        .and_then(RevisionObservation::known_revision)
        .zip(previous.and_then(RevisionObservation::known_revision))
        .is_some_and(|(left, right)| left == right)
}

fn environment_key(value: VirtualizationKind) -> String {
    match value {
        VirtualizationKind::Native => "native",
        VirtualizationKind::HypervisorRoot => "hypervisor_root",
        VirtualizationKind::VirtualMachineGuest => "virtual_machine_guest",
        VirtualizationKind::Container => "container",
        VirtualizationKind::Unknown => "unknown",
    }
    .into()
}

fn authority_key(value: MicrocodeAuthority) -> String {
    match value {
        MicrocodeAuthority::OperatingSystem => "operating_system",
        MicrocodeAuthority::FirmwareAndOperatingSystem => "firmware_and_operating_system",
        MicrocodeAuthority::HypervisorHost => "hypervisor_host",
        MicrocodeAuthority::FirmwareOnly => "firmware_only",
        MicrocodeAuthority::Unknown => "unknown",
    }
    .into()
}

fn hypervisor_vendor_key(value: &str) -> String {
    match value {
        "HyperV" => "hyper_v".into(),
        "KVM" => "kvm".into(),
        "VMware" => "vmware".into(),
        "QEMU" => "qemu".into(),
        "Xen" => "xen".into(),
        "Bhyve" => "bhyve".into(),
        "QNX" => "qnx".into(),
        "ACRN" => "acrn".into(),
        other => other
            .chars()
            .enumerate()
            .flat_map(|(index, ch)| {
                if ch.is_uppercase() && index > 0 {
                    vec!['_', ch.to_ascii_lowercase()]
                } else {
                    vec![ch.to_ascii_lowercase()]
                }
            })
            .collect(),
    }
}

fn environment_label(value: &str) -> &'static str {
    match value {
        "hypervisor_root" => "Hyper-V root partition",
        "virtual_machine_guest" => "Virtual machine guest",
        "native" => "Native",
        "container" => "Container",
        _ => "Unknown",
    }
}

fn os_label(value: &str) -> &'static str {
    match value {
        "windows" => "Windows",
        "linux" => "Linux",
        "macos" => "macOS",
        _ => "Unknown",
    }
}

fn authority_label(value: &str) -> &'static str {
    match value {
        "firmware_and_operating_system" => "firmware and operating system",
        "operating_system" => "operating system",
        "hypervisor_host" => "hypervisor host",
        "firmware_only" => "firmware only",
        _ => "unknown",
    }
}

fn hypervisor_vendor_label(value: &str) -> &'static str {
    match value {
        "hyper_v" => "Hyper-V",
        _ => "unknown",
    }
}

fn revision_source_label(value: RevisionSource) -> &'static str {
    match value {
        RevisionSource::ProcCpuinfo => "/proc/cpuinfo",
        RevisionSource::LinuxSysfs => "Linux sysfs",
        RevisionSource::WindowsRegistry => "Windows registry",
        RevisionSource::Manual => "manual identity",
        RevisionSource::Unavailable => "unavailable",
    }
}

fn scope_label(value: ObservationScope) -> &'static str {
    match value {
        ObservationScope::System => "system",
        ObservationScope::ProcessorPackage => "processor package",
        ObservationScope::Core => "core",
        ObservationScope::LogicalProcessor => "logical processor",
        ObservationScope::VirtualCpu => "virtual CPU",
        ObservationScope::Unknown => "unknown",
    }
}

fn state_label(value: &str) -> String {
    match value {
        "not_applicable" => "Not applicable".into(),
        "not_inspected" => "Not inspected".into(),
        "not_evaluable" => "Not evaluable".into(),
        "not_loaded" => "Not loaded".into(),
        "host_managed" => "Host managed".into(),
        other => display_title_case(other),
    }
}

fn display_title_case(value: &str) -> String {
    value
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => format!(
                    "{}{}",
                    first.to_ascii_uppercase(),
                    chars.collect::<String>()
                ),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
