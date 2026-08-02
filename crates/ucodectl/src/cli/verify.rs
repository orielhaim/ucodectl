use std::path::{Path, PathBuf};

use miette::{Result, miette};
use serde::Serialize;
use ucode_transaction::{ApplyReport, journal::sha256_hex};

use super::{OutputFormat, VerifyArgs};
use crate::cli::plan_artifact::PlanArtifact;
use crate::output::emit;
use crate::util::resolve_system;

#[derive(Serialize)]
struct VerifyJson {
    schema_version: u32,
    command: &'static str,
    ok: bool,
    plan_id: Option<String>,
    transaction_id: Option<String>,
    transaction_committed: Option<bool>,
    processors: Vec<ProcessorVerification>,
    messages: Vec<String>,
}

#[derive(Serialize)]
struct ProcessorVerification {
    processor: u32,
    running_revision: Option<String>,
    expected_revision: Option<String>,
    ok: bool,
}

pub fn run(args: VerifyArgs, format: OutputFormat) -> Result<i32> {
    let receipt = if let Some(id) = &args.transaction {
        Some(read_receipt_for_id(id)?)
    } else if args.plan.is_none() {
        latest_receipt()?
    } else {
        None
    };

    let artifact = args
        .plan
        .as_deref()
        .map(PlanArtifact::read_from)
        .transpose()?;
    if let Some(artifact) = &artifact {
        artifact.verify_inputs()?;
    }

    let system = resolve_system(None, None, None, None)?;
    let mut messages = Vec::new();
    let mut all_ok = true;
    let mut processors = Vec::new();

    if let Some(receipt) = &receipt {
        if receipt.schema_version != 1 {
            all_ok = false;
            messages.push(format!(
                "unsupported transaction receipt schema {}",
                receipt.schema_version
            ));
        }
        if !receipt.committed {
            all_ok = false;
            messages.push("transaction receipt is not committed".to_string());
        }
        for result in &receipt.results {
            match std::fs::read(&result.path) {
                Ok(bytes) => {
                    let hash = sha256_hex(&bytes);
                    if hash != result.sha256 || bytes.len() as u64 != result.bytes {
                        all_ok = false;
                        messages.push(format!(
                            "artifact verification failed for {}: receipt hash/size does not match",
                            result.path
                        ));
                    }
                }
                Err(error) => {
                    all_ok = false;
                    messages.push(format!(
                        "artifact verification failed for {}: {error}",
                        result.path
                    ));
                }
            }
        }
    }

    if let Some(artifact) = &artifact {
        let identities_match = artifact.target.identities.len() == system.unique_identities.len()
            && artifact
                .target
                .identities
                .iter()
                .all(|identity| system.unique_identities.contains(identity));
        if !identities_match {
            all_ok = false;
            messages.push("current CPU identities differ from the plan target".to_string());
        }

        for expected in &artifact.plan.cpus {
            let current = system
                .cpus
                .iter()
                .find(|cpu| cpu.processor == expected.processor)
                .and_then(|cpu| cpu.identity.current_revision);
            let ok = match expected.best_available_revision {
                Some(wanted) => current.is_some_and(|running| running >= wanted),
                None => true,
            };
            if !ok {
                all_ok = false;
            }
            processors.push(ProcessorVerification {
                processor: expected.processor,
                running_revision: current.map(hex_rev),
                expected_revision: expected.best_available_revision.map(hex_rev),
                ok,
            });
        }
        if artifact.plan.writes.is_empty() {
            messages.push("plan contains no deployment writes".to_string());
        } else if receipt.is_none() {
            all_ok = false;
            messages.push(
                "plan has deployment writes but no committed transaction receipt was found"
                    .to_string(),
            );
        }
    } else if receipt.is_some() {
        messages.push(
            "transaction receipt verified; pass the original plan path to verify CPU targets and boot artifacts"
                .to_string(),
        );
    } else {
        return Err(miette::miette!(
            "no plan or transaction found; pass a plan path or run `verify --transaction <ID>`"
        ));
    }

    let json = VerifyJson {
        schema_version: 1,
        command: "verify",
        ok: all_ok,
        plan_id: artifact
            .as_ref()
            .map(|artifact| artifact.plan_id.clone())
            .or_else(|| receipt.as_ref().map(|r| r.plan_id.clone())),
        transaction_id: receipt.as_ref().map(|r| r.transaction_id.clone()),
        transaction_committed: receipt.as_ref().map(|r| r.committed),
        processors,
        messages,
    };

    emit(format, &json, || {
        let mut out = format!(
            "verify: {}\n  plan: {}\n  transaction: {}\n",
            if json.ok { "OK" } else { "FAIL" },
            json.plan_id.as_deref().unwrap_or("-"),
            json.transaction_id.as_deref().unwrap_or("-"),
        );
        for cpu in &json.processors {
            out.push_str(&format!(
                "  cpu{} running={} expected={} {}\n",
                cpu.processor,
                cpu.running_revision.as_deref().unwrap_or("-"),
                cpu.expected_revision.as_deref().unwrap_or("-"),
                if cpu.ok { "ok" } else { "FAIL" },
            ));
        }
        for message in &json.messages {
            out.push_str(&format!("  note: {message}\n"));
        }
        out
    });

    Ok(if all_ok { 0 } else { 1 })
}

fn hex_rev(revision: u32) -> String {
    format!("0x{revision:08x}")
}

fn receipt_path(id: &str) -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from(format!("/var/lib/ucodectl/transactions/{id}.receipt.json"))
    } else {
        PathBuf::from(format!(".ucodectl-transactions/{id}.receipt.json"))
    }
}

fn read_receipt_for_id(id: &str) -> Result<ApplyReport> {
    let path = receipt_path(id);
    read_receipt(&path)
}

fn read_receipt(path: &Path) -> Result<ApplyReport> {
    let bytes = std::fs::read(path).map_err(|e| miette!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| miette!("parse receipt {}: {e}", path.display()))
}

fn latest_receipt() -> Result<Option<ApplyReport>> {
    let dir = if cfg!(target_os = "linux") {
        PathBuf::from("/var/lib/ucodectl/transactions")
    } else {
        PathBuf::from(".ucodectl-transactions")
    };
    if !dir.exists() {
        return Ok(None);
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| miette!("{}: {e}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .filter(|path| path.to_string_lossy().ends_with(".receipt.json"))
        .collect();
    paths.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
    });
    paths.last().map(|path| read_receipt(path)).transpose()
}
