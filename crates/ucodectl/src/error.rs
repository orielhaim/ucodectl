use std::path::Path;

use miette::{Diagnostic, Report};
use thiserror::Error;
use ucode_catalog::CatalogError;

/// Stable operational error envelope used by the CLI reporter. The code is
/// deliberately independent of platform-specific OS error text.
#[derive(Debug, Error, Diagnostic)]
#[error("{message}")]
pub struct CliError {
    pub code: String,
    pub message: String,
    #[help]
    pub help: String,
    pub path: Option<String>,
    pub os_error: Option<i32>,
}

pub fn report(code: &str, message: impl Into<String>, help: impl Into<String>) -> Report {
    report_with_details(code, message, help, None, None)
}

fn report_with_details(
    code: &str,
    message: impl Into<String>,
    help: impl Into<String>,
    path: Option<&Path>,
    os_error: Option<i32>,
) -> Report {
    Report::new(CliError {
        code: code.to_string(),
        message: message.into(),
        help: help.into(),
        path: path.map(|path| path.display().to_string()),
        os_error,
    })
}

pub fn input_io(command: &str, path: &Path, error: &std::io::Error) -> Report {
    let (code, detail, help) = match error.kind() {
        std::io::ErrorKind::NotFound => (
            "input_not_found",
            "input path does not exist",
            "verify the path or pass an existing microcode file or directory",
        ),
        std::io::ErrorKind::PermissionDenied => (
            "permission_denied",
            "permission denied while reading input",
            "check file permissions and access the source with an appropriate account",
        ),
        _ => (
            "source_scan_failed",
            "failed to read input source",
            "verify the path and check the underlying filesystem",
        ),
    };
    report_with_details(
        code,
        format!("{command}: {detail}: {}", path.display()),
        help,
        Some(path),
        error.raw_os_error(),
    )
}

pub fn catalog(command: &str, error: &CatalogError) -> Report {
    match error {
        CatalogError::Io { path, source } => input_io(command, path, source),
        CatalogError::UnknownFormat { path } => report_with_details(
            "unsupported_file",
            format!("{command}: unsupported microcode input: {}", path.display()),
            "pass an Intel or AMD microcode file, or a directory containing supported files",
            Some(path),
            None,
        ),
        CatalogError::Intel { path, .. } | CatalogError::Amd { path, .. } => report_with_details(
            "malformed_microcode",
            format!("{command}: malformed microcode input: {}", path.display()),
            "run validate for structural details or provide a complete release file",
            Some(path),
            None,
        ),
        CatalogError::LimitExceeded(detail) => report(
            "source_scan_failed",
            format!("{command}: source scan limit exceeded: {detail}"),
            "reduce the source tree or adjust the configured resource limits",
        ),
        CatalogError::Symlink { path } => report_with_details(
            "source_scan_failed",
            format!("{command}: refusing to follow symlink: {}", path.display()),
            "resolve the symlink explicitly or pass a source tree without symlinks",
            Some(path),
            None,
        ),
        CatalogError::Sidecar(detail) => report(
            "malformed_microcode",
            format!("{command}: invalid release metadata: {detail}"),
            "provide a valid AMD metadata source",
        ),
    }
}

pub fn output_io(command: &str, path: &Path, error: &std::io::Error) -> Report {
    let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
        "output_exists"
    } else {
        "output_write_failed"
    };
    report_with_details(
        code,
        format!("{command}: failed to write output: {}", path.display()),
        "choose a writable output path or remove the existing artifact",
        Some(path),
        error.raw_os_error(),
    )
}

pub fn json_envelope(error: &CliError) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "error": {
            "code": error.code,
            "message": error.message,
            "path": error.path,
            "os_error": error.os_error,
        }
    })
}
