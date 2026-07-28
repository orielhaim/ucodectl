use miette::Result;

use super::{SchemaArgs, SchemaKind};

/// Emit versioned JSON Schema documents for the stable machine interface.
///
/// Schemas are hand-maintained so the library crates stay free of a schemars
/// dependency; the CLI is the only publisher of the contract.
pub fn run(args: SchemaArgs) -> Result<i32> {
    let manifest = include_str!("schemas/manifest.schema.json");
    let plan = include_str!("schemas/plan.schema.json");
    let diff = include_str!("schemas/diff.schema.json");

    match args.kind {
        SchemaKind::All => {
            let all = serde_json::json!({
                "schema_version": 1,
                "generator": "ucodectl",
                "schemas": {
                    "manifest": serde_json::from_str::<serde_json::Value>(manifest).unwrap(),
                    "plan": serde_json::from_str::<serde_json::Value>(plan).unwrap(),
                    "diff": serde_json::from_str::<serde_json::Value>(diff).unwrap(),
                }
            });
            println!("{}", serde_json::to_string_pretty(&all).unwrap());
        }
        SchemaKind::Manifest => println!("{manifest}"),
        SchemaKind::Plan => println!("{plan}"),
        SchemaKind::Diff => println!("{diff}"),
    }
    Ok(0)
}
