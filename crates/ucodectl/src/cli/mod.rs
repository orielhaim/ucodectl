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
pub mod schema;
pub mod status;
pub mod validate;
pub mod verify;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::util::VendorArg;

/// ucodectl — Inspect, validate, build and verify CPU microcode for Linux.
#[derive(Debug, Parser)]
#[command(
    name = "ucodectl",
    version,
    about = "Inspect, validate, build and verify CPU microcode for Linux",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Increase log verbosity on stderr (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    pub format: OutputFormat,

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
    /// Show the current system microcode status.
    Status(StatusArgs),
    /// Inspect a microcode bundle or container.
    Inspect(InspectArgs),
    /// Validate structural and semantic integrity.
    Validate(ValidateArgs),
    /// List patches in one or more sources.
    List(ListArgs),
    /// Show which patches match a CPU or the host.
    Match(MatchArgs),
    /// Compare two releases / catalogs.
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
    /// Generate shell completions.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Generate man pages into a directory.
    Manpages {
        #[arg(long, default_value = "man")]
        out_dir: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Microcode source paths (firmware dirs or files). Optional.
    #[arg(long = "source", short = 's')]
    pub sources: Vec<PathBuf>,
    /// Initrd/UKI to compare against.
    #[arg(long)]
    pub boot: Option<PathBuf>,
    /// Force Intel platform ID (0-7).
    #[arg(long)]
    pub platform_id: Option<u32>,
}

#[derive(Debug, clap::Args)]
pub struct InspectArgs {
    /// Files or directories to inspect.
    pub paths: Vec<PathBuf>,
    /// AMD linux-firmware README for min-base-revision metadata.
    #[arg(long)]
    pub amd_readme: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Files or directories to validate.
    pub paths: Vec<PathBuf>,
    /// Exit non-zero on warnings as well as errors.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// Files or directories to list.
    pub paths: Vec<PathBuf>,
    /// Restrict to a vendor.
    #[arg(long, value_enum)]
    pub vendor: Option<VendorArg>,
}

#[derive(Debug, clap::Args)]
pub struct MatchArgs {
    /// Microcode sources.
    pub paths: Vec<PathBuf>,
    /// Explicit CPU signature (CPUID.1:EAX), e.g. 0x000806c1.
    #[arg(long, value_parser = parse_u32)]
    pub signature: Option<u32>,
    #[arg(long, value_enum)]
    pub vendor: Option<VendorArg>,
    #[arg(long)]
    pub platform_id: Option<u32>,
    /// Currently running revision (optional override).
    #[arg(long, value_parser = parse_u32)]
    pub revision: Option<u32>,
}

#[derive(Debug, clap::Args)]
pub struct DiffArgs {
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
    /// Path to initrd, initramfs, or UKI.
    pub path: PathBuf,
    /// Treat the file as a UKI PE image.
    #[arg(long)]
    pub uki: bool,
}

#[derive(Debug, clap::Args)]
pub struct BuildEarlyArgs {
    /// Microcode sources.
    pub paths: Vec<PathBuf>,
    /// Output path for the early CPIO.
    #[arg(short, long, default_value = "ucode-early.cpio")]
    pub output: PathBuf,
    /// Only include patches for the host (or --signature) CPU.
    #[arg(long)]
    pub match_host: bool,
    #[arg(long, value_parser = parse_u32)]
    pub signature: Option<u32>,
    #[arg(long, value_enum)]
    pub vendor: Option<VendorArg>,
    #[arg(long)]
    pub platform_id: Option<u32>,
    /// Include all revisions, not only the newest per target.
    #[arg(long)]
    pub all_revisions: bool,
    #[arg(long)]
    pub amd_readme: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct PlanArgs {
    /// Available microcode sources.
    pub paths: Vec<PathBuf>,
    #[arg(long)]
    pub boot: Option<PathBuf>,
    #[arg(long)]
    pub platform_id: Option<u32>,
    #[arg(long)]
    pub allow_downgrade: bool,
    #[arg(long, default_value = "ucode-early.cpio")]
    pub early_output: PathBuf,
    /// Always plan an early image rebuild.
    #[arg(long, default_value_t = true)]
    pub want_early: bool,
}

#[derive(Debug, clap::Args)]
pub struct ApplyArgs {
    /// Available microcode sources.
    pub paths: Vec<PathBuf>,
    #[arg(long)]
    pub boot: Option<PathBuf>,
    #[arg(long)]
    pub platform_id: Option<u32>,
    #[arg(long)]
    pub allow_downgrade: bool,
    #[arg(long, default_value = "ucode-early.cpio")]
    pub early_output: PathBuf,
    /// Do not write; only show what would happen.
    #[arg(long)]
    pub dry_run: bool,
    /// Directory for backups of replaced files.
    #[arg(long, default_value = ".ucodectl-backup")]
    pub backup_dir: PathBuf,
    /// Journal path.
    #[arg(long, default_value = ".ucodectl-journal.json")]
    pub journal: PathBuf,
    /// Require an explicit confirmation token for non-dry-run applies.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    /// Expected minimum revision (optional).
    #[arg(long, value_parser = parse_u32)]
    pub expect_revision: Option<u32>,
    #[arg(long)]
    pub platform_id: Option<u32>,
    /// Optional sources to compare against.
    #[arg(long = "source", short = 's')]
    pub sources: Vec<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct SchemaArgs {
    /// Which schema to emit.
    #[arg(value_enum, default_value_t = SchemaKind::All)]
    pub kind: SchemaKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum SchemaKind {
    #[default]
    All,
    Manifest,
    Plan,
    Diff,
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
