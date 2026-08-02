use clap::CommandFactory;
use clap_complete::generate;
use std::io;

use super::Cli;
use super::CompletionsArgs;

pub fn run(args: &CompletionsArgs) -> miette::Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    if let Some(path) = &args.output {
        let mut file = std::fs::File::create(path)
            .map_err(|error| crate::error::output_io("completions", path, &error))?;
        generate(args.shell, &mut cmd, name, &mut file);
    } else {
        generate(args.shell, &mut cmd, name, &mut io::stdout());
    }
    Ok(())
}
