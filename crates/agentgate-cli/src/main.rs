//! AgentGate command-line entry point.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "agentgate", version, about = "Security firewall for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the supported MCP protocol version.
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Version) {
        Command::Version => println!(
            "agentgate {} (MCP {})",
            env!("CARGO_PKG_VERSION"),
            agentgate_protocol::SUPPORTED_MCP_VERSION
        ),
    }
}
