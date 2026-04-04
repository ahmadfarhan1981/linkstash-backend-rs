pub mod bootstrap;

use clap::{Parser, Subcommand};

use crate::app_data::AppData;

#[derive(Parser)]
#[command(name = "linkstash")]
pub struct Cli {
    #[arg(long, global = true, default_value = ".env")]
    pub env_file: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Bootstrap,
}

pub async fn execute_command(
    command: Commands,
    app_data: &AppData,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Bootstrap => bootstrap::run(&app_data.connections.auth).await,
    }
}
