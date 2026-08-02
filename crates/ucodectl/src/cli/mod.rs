pub mod apply;
pub mod build_early;
pub mod completions;
pub mod diff;
pub mod inspect;
pub mod inspect_boot;
pub mod list;
pub mod manpages;
pub mod match_cmd;
pub mod plan;
pub mod plan_artifact;
pub mod schema;
pub mod status;
pub mod validate;
pub mod verify;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::util::VendorArg;

/// ucodectl - Inspect, validate and manage CPU microcode.
#[derive(Debug, Parser)]
#[command(
    name = "ucodectl",
    bin_name = "ucodectl",
    version,
    about = "Inspect, validate and manage CPU microcode",
    long_about = "Cross-platform microcode inspection and diagnostics, with Linux early-boot deployment support.",
    propagate_version = true
)]
pub struct Cli {
    /// Increase log verbosity on stderr (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the host's CPU microcode state.
    Status(StatusArgs),
    /// Decode microcode files and display detailed metadata.
    Inspect(InspectArgs),
    /// Check files for structural and semantic problems.
    Validate(ValidateArgs),
    /// Show a compact inventory of microcode patches.
    List(ListArgs),
    /// Select applicable patches for the host or an explicit CPU identity.
    Match(MatchArgs),
    /// Compare two microcode releases or catalogs.
    Diff(DiffArgs),
    /// Inspect microcode embedded in an initrd or UKI.
    InspectBoot(InspectBootArgs),
    /// Build a deterministic early-load CPIO.
    BuildEarly(BuildEarlyArgs),
    /// Produce an explained change plan (read-only).
    Plan(PlanArgs),
    /// Apply a plan (writes files; use --dry-run first).
    Apply(ApplyArgs),
    /// Verify post-reboot microcode state.
    Verify(VerifyArgs),
    /// Emit JSON Schema for machine-readable outputs.
    Schema(SchemaArgs),
    /// Generate shell completions for ucodectl and its subcommands.
    Completions(CompletionsArgs),
    /// Generate manual pages for ucodectl and its subcommands.
    Manpages(ManpagesArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct OutputArgs {
    /// Output format for data-producing commands.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
    /// Write the completion script to a file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ManpagesArgs {
    /// Output directory for generated manual pages.
    #[arg(long, default_value = "man")]
    pub out_dir: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Microcode files or release directories used to evaluate available updates.
    #[arg(long = "source", short = 's', value_name = "PATH", num_args = 1..)]
    pub sources: Vec<PathBuf>,
    /// Initrd/UKI to compare against.
    #[arg(long, value_name = "PATH")]
    pub boot: Option<PathBuf>,
    /// Override the detected Intel platform ID for matching and diagnostics.
    #[arg(long, value_name = "ID", value_parser = parse_platform_id)]
    pub intel_platform_id: Option<u32>,
    /// Show one entry for every logical processor instead of grouping identical observations.
    #[arg(long)]
    pub per_cpu: bool,
    /// Include raw observation data for diagnostics and bug reports.
    #[arg(long)]
    pub raw: bool,
}

#[derive(Debug, clap::Args)]
pub struct InspectArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Files or directories to inspect. Directories are scanned recursively; symlinks are resolved and unrecognized files are skipped.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,
    /// Override the AMD release metadata source.
    #[arg(long, value_name = "PATH", help_heading = "Advanced options")]
    pub amd_metadata: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Files or directories to validate. Directories are scanned recursively; symlinks are resolved and unrecognized files are skipped.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,
    /// Return a non-zero exit status when warnings are found.
    #[arg(long = "warnings-as-errors", alias = "strict")]
    pub warnings_as_errors: bool,
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Files or directories to list. Directories are scanned recursively; symlinks are resolved and unrecognized files are skipped.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,
    /// Restrict to a vendor.
    #[arg(long, value_enum)]
    pub vendor: Option<VendorArg>,
    /// Restrict results to patches covering this CPUID signature.
    #[arg(long, value_name = "SIGNATURE", value_parser = parse_u32)]
    pub signature: Option<u32>,
    /// Show only the newest patch for each primary target.
    #[arg(long)]
    pub latest_only: bool,
}

#[derive(Debug, clap::Args)]
pub struct MatchArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Microcode files or release directories to search. Directories are scanned recursively; symlinks are resolved and unrecognized files are skipped.
    #[arg(value_name = "SOURCE", required = true, num_args = 1..)]
    pub sources: Vec<PathBuf>,
    /// Explicit CPU signature (CPUID.1:EAX), e.g. 0x000806c1.
    #[arg(long, value_parser = parse_u32, requires = "vendor")]
    pub signature: Option<u32>,
    /// CPU vendor. Host detection identifies the vendor automatically; required with --signature.
    #[arg(long, value_enum)]
    pub vendor: Option<VendorArg>,
    /// Intel platform ID used for patch matching.
    #[arg(long, value_name = "ID", value_parser = parse_platform_id)]
    pub intel_platform_id: Option<u32>,
    /// Override the currently active microcode revision.
    #[arg(long = "active-revision", value_name = "REVISION", value_parser = parse_u32)]
    pub active_revision: Option<u32>,
}

#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Old release path.
    pub old: PathBuf,
    /// New release path.
    pub new: PathBuf,
    /// Include unchanged targets.
    #[arg(long)]
    pub include_unchanged: bool,
}

#[derive(Debug, clap::Args)]
pub struct InspectBootArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Path to initrd, initramfs, or UKI.
    pub path: PathBuf,
    /// Input type. Auto-detection is the default.
    #[arg(long = "type", value_enum, default_value_t = BootInputType::Auto)]
    pub input_type: BootInputType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum BootInputType {
    #[default]
    Auto,
    Initrd,
    Uki,
}

#[derive(Debug, clap::Args)]
pub struct BuildEarlyArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Microcode files or release directories. Directories are scanned recursively; symlinks are not followed by default and unrecognized files are skipped. By default, the newest patch for every supported target is included.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,
    /// Output path for the early CPIO.
    #[arg(short, long, default_value = "ucode-early.cpio")]
    pub output: PathBuf,
    /// Only include patches for the host (or --signature) CPU.
    #[arg(long, conflicts_with = "signature")]
    pub match_host: bool,
    /// Explicit CPU target. Requires --vendor.
    #[arg(long, value_parser = parse_u32, requires = "vendor")]
    pub signature: Option<u32>,
    #[arg(long, value_enum)]
    pub vendor: Option<VendorArg>,
    #[arg(long, value_name = "ID", value_parser = parse_platform_id, requires = "vendor")]
    pub intel_platform_id: Option<u32>,
    /// Include all revisions, not only the newest per target.
    #[arg(long)]
    pub all_revisions: bool,
    /// Allow explicitly requested symlinks, subject to input-root checks.
    #[arg(long)]
    pub follow_symlinks: bool,
    /// Permit host matching when the host is a VM/WSL guest whose microcode is host-managed.
    #[arg(long)]
    pub allow_virtual_cpu_target: bool,
    #[arg(long, value_name = "PATH", help_heading = "Advanced options")]
    pub amd_metadata: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct PlanArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Available microcode sources.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,
    #[arg(long)]
    pub boot: Option<PathBuf>,
    /// Intel platform ID override used for planning diagnostics.
    #[arg(long, value_name = "ID", value_parser = parse_platform_id)]
    pub intel_platform_id: Option<u32>,
    #[arg(long)]
    /// Consider a downgrade only when policy has an exact compatible target and provenance.
    #[arg(long = "consider-downgrade")]
    pub consider_downgrade: bool,
    #[arg(long, default_value = "ucode-early.cpio")]
    pub early_output: PathBuf,
    /// Deployment target for the generated plan.
    #[arg(long, value_enum, default_value_t = DeploymentMode::Auto)]
    pub deployment: DeploymentMode,
    /// Write the immutable machine-readable plan artifact.
    #[arg(long, value_name = "PATH")]
    pub output_plan: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum DeploymentMode {
    #[default]
    Auto,
    #[value(name = "early-cpio")]
    EarlyCpio,
    None,
}

#[derive(Debug, clap::Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Immutable plan artifact created by `ucodectl plan --output-plan`.
    pub plan: PathBuf,
    /// Do not write; only show what would happen.
    #[arg(long)]
    pub dry_run: bool,
    /// Directory for backups of replaced files.
    #[arg(long)]
    pub backup_dir: Option<PathBuf>,
    /// Transaction journal path. Defaults to `/var/lib/ucodectl/transactions/<plan-id>.json` on Linux.
    #[arg(long)]
    pub journal: Option<PathBuf>,
    /// Assume yes and skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// High-assurance non-interactive confirmation; must equal the plan ID.
    #[arg(long)]
    pub confirm: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub output_options: OutputArgs,
    /// Plan artifact whose targets and expected outcomes should be verified.
    pub plan: Option<PathBuf>,
    /// Explicit transaction ID. Without this, the latest pending transaction is used.
    #[arg(long)]
    pub transaction: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct SchemaArgs {
    /// Which schema to emit.
    #[arg(value_enum)]
    pub kind: SchemaKind,
    /// Write one schema to a file.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Write all schemas as separate files into this directory.
    #[arg(long, value_name = "DIR")]
    pub out_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SchemaKind {
    All,
    #[value(name = "catalog-manifest")]
    CatalogManifest,
    Inspection,
    Validation,
    Catalog,
    Match,
    BootInspection,
    BuildResult,
    Plan,
    Diff,
    Status,
    Transaction,
    Receipt,
    Verification,
    Error,
}

fn parse_u32(s: &str) -> std::result::Result<u32, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())
    }
}

fn parse_platform_id(s: &str) -> std::result::Result<u32, String> {
    let value = parse_u32(s)?;
    if value <= 7 {
        Ok(value)
    } else {
        Err("Intel platform ID must be in the range 0-7".into())
    }
}
