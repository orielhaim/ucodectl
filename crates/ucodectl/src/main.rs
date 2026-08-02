#![forbid(unsafe_code)]

//! ucodectl - Inspect, validate and manage CPU microcode.

mod cli;
mod error;
mod output;
mod util;

use clap::Parser;
use miette::Result;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let json_errors = json_error_requested();
    let code = match run(cli) {
        Ok(code) => code,
        Err(error) if json_errors => {
            if let Some(cli_error) = error.downcast_ref::<crate::error::CliError>() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&crate::error::json_envelope(cli_error))
                        .unwrap_or_default()
                );
                1
            } else {
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn json_error_requested() -> bool {
    let args: Vec<String> = std::env::args().collect();
    args.iter().any(|arg| arg == "--format=json")
        || args
            .windows(2)
            .any(|pair| pair[0] == "--format" && pair[1] == "json")
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
        Command::Status(args) => {
            let format = args.output_options.format;
            cli::status::run(args, format, cli.verbose)
        }
        Command::Inspect(args) => {
            let format = args.output_options.format;
            cli::inspect::run(args, format)
        }
        Command::Validate(args) => {
            let format = args.output_options.format;
            cli::validate::run(args, format)
        }
        Command::List(args) => {
            let format = args.output_options.format;
            cli::list::run(args, format)
        }
        Command::Match(args) => {
            let format = args.output_options.format;
            cli::match_cmd::run(args, format)
        }
        Command::Diff(args) => {
            let format = args.output_options.format;
            cli::diff::run(args, format)
        }
        Command::InspectBoot(args) => {
            let format = args.output_options.format;
            cli::inspect_boot::run(args, format)
        }
        Command::BuildEarly(args) => {
            let format = args.output_options.format;
            cli::build_early::run(args, format)
        }
        Command::Plan(args) => {
            let format = args.output_options.format;
            cli::plan::run(args, format)
        }
        Command::Apply(args) => {
            let format = args.output_options.format;
            cli::apply::run(args, format)
        }
        Command::Verify(args) => {
            let format = args.output_options.format;
            cli::verify::run(args, format)
        }
        Command::Schema(args) => cli::schema::run(args),
        Command::Completions(args) => {
            cli::completions::run(&args)?;
            Ok(0)
        }
        Command::Manpages(args) => {
            cli::manpages::run(&args.out_dir)?;
            Ok(0)
        }
    }
}
