use std::fs;
use std::path::Path;

use clap::CommandFactory;

use super::Cli;

pub fn run(out_dir: &Path) -> miette::Result<()> {
    fs::create_dir_all(out_dir)
        .map_err(|error| crate::error::output_io("manpages", out_dir, &error))?;
    let root = Cli::command();
    let subcommands: Vec<clap::Command> = root.get_subcommands().cloned().collect();
    write_page(out_dir, root, "ucodectl")?;
    for subcommand in subcommands {
        let name = subcommand.get_name().to_string();
        write_page(out_dir, subcommand, &format!("ucodectl-{name}"))?;
    }
    Ok(())
}

fn write_page(out_dir: &Path, command: clap::Command, stem: &str) -> miette::Result<()> {
    let man = clap_mangen::Man::new(command);
    let mut buffer = Vec::<u8>::new();
    man.render(&mut buffer)
        .map_err(|error| crate::error::output_io("manpages", out_dir, &error))?;
    let output = out_dir.join(format!("{stem}.1"));
    fs::write(&output, buffer)
        .map_err(|error| crate::error::output_io("manpages", &output, &error))?;
    println!("wrote {}", output.display());
    Ok(())
}
