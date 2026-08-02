use std::path::Path;

use miette::Result;
use serde_json::{Value, json};

use super::{SchemaArgs, SchemaKind};

/// Emit versioned JSON Schema documents for the machine-readable interfaces.
pub fn run(args: SchemaArgs) -> Result<i32> {
    if matches!(args.kind, SchemaKind::All) {
        let Some(dir) = args.out_dir else {
            return Err(crate::error::report(
                "output_required",
                "schema all requires --out-dir",
                "use `ucodectl schema all --out-dir schemas` to write one file per schema",
            ));
        };
        if args.output.is_some() {
            return Err(crate::error::report(
                "invalid_arguments",
                "schema all cannot be combined with --output",
                "use --out-dir for the all-schemas export",
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|e| crate::error::output_io("schema", &dir, &e))?;
        for (name, schema) in schema_documents() {
            let path = dir.join(format!("{name}.schema.json"));
            write_schema(&path, &schema)?;
        }
        return Ok(0);
    }

    if args.out_dir.is_some() {
        return Err(crate::error::report(
            "invalid_arguments",
            "--out-dir is only valid with `schema all`",
            "use --output when exporting one schema",
        ));
    }

    let schema = schema_for(args.kind);
    if let Some(path) = args.output {
        write_schema(&path, &schema)?;
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&schema).unwrap_or_default()
        );
    }
    Ok(0)
}

fn write_schema(path: &Path, schema: &Value) -> Result<()> {
    let bytes =
        serde_json::to_vec_pretty(schema).map_err(|e| miette::miette!("serialize schema: {e}"))?;
    std::fs::write(path, bytes).map_err(|e| crate::error::output_io("schema", path, &e))?;
    Ok(())
}

fn schema_for(kind: SchemaKind) -> Value {
    match kind {
        SchemaKind::CatalogManifest => include_json("schemas/manifest.schema.json"),
        SchemaKind::Plan => include_json("schemas/plan.schema.json"),
        SchemaKind::Diff => include_json("schemas/diff.schema.json"),
        SchemaKind::Status => include_json("schemas/status.schema.json"),
        SchemaKind::All => unreachable!(),
        SchemaKind::Inspection => generic("inspect", "ucodectl inspection result"),
        SchemaKind::Validation => generic("validate", "ucodectl validation result"),
        SchemaKind::Catalog => generic("catalog", "ucodectl catalog result"),
        SchemaKind::Match => generic("match", "ucodectl match result"),
        SchemaKind::BootInspection => generic("inspect-boot", "ucodectl boot inspection result"),
        SchemaKind::BuildResult => generic("build-early", "ucodectl early build result"),
        SchemaKind::Transaction => generic("apply", "ucodectl transaction journal"),
        SchemaKind::Receipt => generic("apply", "ucodectl transaction receipt"),
        SchemaKind::Verification => generic("verification", "ucodectl verification result"),
        SchemaKind::Error => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://ucodectl.dev/schema/v1/error.json",
            "title": "ucodectl error envelope",
            "type": "object",
            "required": ["schema_version", "error"],
            "properties": {
                "schema_version": { "type": "integer", "const": 1 },
                "error": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" },
                        "path": { "type": ["string", "null"] },
                        "os_error": { "type": ["integer", "null"] }
                    },
                    "additionalProperties": false
                }
            },
            "additionalProperties": false
        }),
    }
}

fn schema_documents() -> Vec<(&'static str, Value)> {
    vec![
        ("catalog_manifest", schema_for(SchemaKind::CatalogManifest)),
        ("inspection", schema_for(SchemaKind::Inspection)),
        ("validation", schema_for(SchemaKind::Validation)),
        ("catalog", schema_for(SchemaKind::Catalog)),
        ("match", schema_for(SchemaKind::Match)),
        ("boot_inspection", schema_for(SchemaKind::BootInspection)),
        ("build_result", schema_for(SchemaKind::BuildResult)),
        ("plan", schema_for(SchemaKind::Plan)),
        ("diff", schema_for(SchemaKind::Diff)),
        ("status", schema_for(SchemaKind::Status)),
        ("transaction", schema_for(SchemaKind::Transaction)),
        ("receipt", schema_for(SchemaKind::Receipt)),
        ("verification", schema_for(SchemaKind::Verification)),
        ("error", schema_for(SchemaKind::Error)),
    ]
}

fn generic(command: &str, title: &str) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("https://ucodectl.dev/schema/v1/{command}.json"),
        "title": title,
        "type": "object",
        "required": ["schema_version", "command"],
        "properties": {
            "schema_version": { "type": "integer", "const": 1 },
            "command": { "type": "string", "const": command }
        },
        "additionalProperties": true
    })
}

fn include_json(path: &str) -> Value {
    match path {
        "schemas/manifest.schema.json" => {
            serde_json::from_str(include_str!("schemas/manifest.schema.json")).unwrap()
        }
        "schemas/plan.schema.json" => {
            serde_json::from_str(include_str!("schemas/plan.schema.json")).unwrap()
        }
        "schemas/diff.schema.json" => {
            serde_json::from_str(include_str!("schemas/diff.schema.json")).unwrap()
        }
        "schemas/status.schema.json" => {
            serde_json::from_str(include_str!("schemas/status.schema.json")).unwrap()
        }
        _ => unreachable!(),
    }
}
