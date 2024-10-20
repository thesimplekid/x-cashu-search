use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(about = "A cashu mint written in rust", author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"))]
pub struct CLIArgs {
    #[arg(
        short,
        long,
        help = "Use the <directory> as the location of the database",
        required = false
    )]
    pub work_dir: Option<PathBuf>,
    #[arg(
        short,
        long,
        help = "Use the <file name> as the location of the config file",
        required = false
    )]
    pub config: Option<PathBuf>,
}
