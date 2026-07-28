#![forbid(unsafe_code)]

//! ucodectl — Inspect, validate, build and verify CPU microcode for Linux.

mod cli;
mod output;
mod util;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(e);
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Status(args) => cli::status::run(args, cli.format),
        Command::Inspect(args) => cli::inspect::run(args, cli.format),
        Command::Validate(args) => cli::validate::run(args, cli.format),
        Command::List(args) => cli::list::run(args, cli.format),
        Command::Match(args) => cli::match_cmd::run(args, cli.format),
        Command::Diff(args) => cli::diff::run(args, cli.format),
        Command::InspectBoot(args) => cli::inspect_boot::run(args, cli.format),
        Command::BuildEarly(args) => cli::build_early::run(args, cli.format),
        Command::Plan(args) => cli::plan::run(args, cli.format),
        Command::Apply(args) => cli::apply::run(args, cli.format),
        Command::Verify(args) => cli::verify::run(args, cli.format),
        Command::Schema(args) => cli::schema::run(args),
        Command::Completions { shell } => {
            cli::completions::run(shell);
            Ok(0)
        }
        Command::Manpages { out_dir } => {
            cli::manpages::run(&out_dir).into_diagnostic()?;
            Ok(0)
        }
    }
}
