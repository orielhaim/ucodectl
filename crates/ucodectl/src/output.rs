use serde::Serialize;

use crate::cli::OutputFormat;

/// Emit a value as human text or JSON on stdout.
pub fn emit<T: Serialize>(format: OutputFormat, value: &T, human: impl FnOnce() -> String) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(value) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("error: failed to serialise JSON: {e}"),
        },
        OutputFormat::Human => {
            print!("{}", human());
        }
    }
}

pub fn hex_rev(rev: u32) -> String {
    format!("0x{rev:08x}")
}

pub fn hex_opt(rev: Option<u32>) -> String {
    rev.map(hex_rev).unwrap_or_else(|| "-".to_string())
}
