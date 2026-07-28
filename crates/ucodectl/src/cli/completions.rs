use clap::CommandFactory;
use clap_complete::generate;
use std::io;

use super::Cli;

pub fn run(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut io::stdout());
}
