use std::fs;
use std::path::Path;

use clap::CommandFactory;

use super::Cli;

pub fn run(out_dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(out_dir)?;
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::<u8>::new();
    man.render(&mut buffer)?;
    fs::write(out_dir.join("ucodectl.1"), buffer)?;
    println!("wrote {}", out_dir.join("ucodectl.1").display());
    Ok(())
}
