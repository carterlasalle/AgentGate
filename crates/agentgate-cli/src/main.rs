//! AgentGate command-line entry point.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use agentgate_audit::{replay, verify, verifying_key_from_file};
use agentgate_policy::CompiledPolicy;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "agentgate", version, about = "Security firewall for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the local stdio MCP gateway.
    Run(RunArgs),
    /// Validate policy without executing tools.
    Policy(PolicyArgs),
    /// Verify or replay signed audit evidence.
    Audit(AuditArgs),
    /// Check configuration, policy, and local state without starting a server.
    Doctor(DoctorArgs),
    /// Print build and protocol versions.
    Version,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Strict AgentGate YAML policy.
    #[arg(long)]
    policy: PathBuf,
    /// Configured server ID; defaults to the first server.
    #[arg(long)]
    server: Option<String>,
    /// Local trust, key, and audit directory.
    #[arg(long, default_value = ".agentgate")]
    state_dir: PathBuf,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Parse, lint, compile, and print the stable policy digest.
    Check {
        /// Strict AgentGate YAML policy.
        #[arg(long)]
        policy: PathBuf,
    },
    /// Execute version-controlled data-only decision fixtures.
    Test {
        /// Strict AgentGate YAML policy.
        #[arg(long)]
        policy: PathBuf,
        /// YAML policy test suite.
        #[arg(long)]
        cases: PathBuf,
    },
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verify hash chain and Ed25519 checkpoints offline.
    Verify {
        /// Audit JSONL path.
        path: PathBuf,
        /// Optional trusted raw AgentGate signing-key file.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Verify and summarize metadata without launching tools or making network calls.
    Replay {
        /// Audit JSONL path.
        path: PathBuf,
        /// Optional trusted raw AgentGate signing-key file.
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Strict AgentGate YAML policy.
    #[arg(long)]
    policy: PathBuf,
    /// Local state directory to inspect.
    #[arg(long, default_value = ".agentgate")]
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Version) {
        Command::Run(args) => {
            agentgate::run_stdio(&args.policy, args.server.as_deref(), &args.state_dir).await?;
        }
        Command::Policy(PolicyArgs {
            command: PolicyCommand::Check { policy },
        }) => {
            let policy = CompiledPolicy::from_path(&policy)?;
            println!(
                "valid policy '{}' v{}\ndigest: {}\nservers: {}",
                policy.document().metadata.name,
                policy.document().metadata.version,
                policy.digest(),
                policy.document().servers.len()
            );
        }
        Command::Policy(PolicyArgs {
            command: PolicyCommand::Test { policy, cases },
        }) => {
            let policy = CompiledPolicy::from_path(&policy)?;
            let source = std::fs::read_to_string(cases)?;
            let report = policy.test_yaml(&source)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Audit(AuditArgs {
            command: AuditCommand::Verify { path, key },
        }) => {
            let public = key.as_deref().map(verifying_key_from_file).transpose()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verify(&path, public.as_ref())?)?
            );
        }
        Command::Audit(AuditArgs {
            command: AuditCommand::Replay { path, key },
        }) => {
            let public = key.as_deref().map(verifying_key_from_file).transpose()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&replay(&path, public.as_ref())?)?
            );
        }
        Command::Doctor(args) => {
            let policy = CompiledPolicy::from_path(&args.policy)?;
            println!("policy: valid ({})", policy.digest());
            println!("protocol: {}", agentgate_protocol::SUPPORTED_MCP_VERSION);
            println!("state directory: {}", args.state_dir.display());
            for server in &policy.document().servers {
                println!(
                    "server {}: executable={} args={} environment_allowlist={}",
                    server.id,
                    server.command.executable,
                    server.command.args.len(),
                    server.command.inherit_environment.len()
                );
            }
            println!("configuration uses AgentGate as the stdio process boundary");
        }
        Command::Version => println!(
            "agentgate {} (MCP {})",
            env!("CARGO_PKG_VERSION"),
            agentgate_protocol::SUPPORTED_MCP_VERSION
        ),
    }
    Ok(())
}
