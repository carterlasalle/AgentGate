//! AgentGate command-line entry point.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::PathBuf;

use agentgate_audit::{
    create_detached_anchor, export_public_key, replay, rotate_signing_key, verify,
    verify_detached_anchor, verifying_key_from_public_file,
};
use agentgate_policy::{CompiledPolicy, migrate_v1alpha1_to_v1};
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
    /// Delete audit logs older than this many days before a session starts.
    #[arg(long, default_value_t = 30)]
    audit_retention_days: u64,
    /// Cap aggregate retained audit JSONL bytes before a session starts.
    #[arg(long, default_value_t = 536_870_912)]
    audit_maximum_bytes: u64,
    /// Dedicated raw 32-byte key shared with a trusted host-lineage adapter.
    #[arg(long)]
    lineage_key: Option<PathBuf>,
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
    /// Migrate a preview v1alpha1 policy to stable v1 without activating it.
    Migrate {
        /// Preview AgentGate YAML policy.
        #[arg(long)]
        policy: PathBuf,
        /// Destination for the stable policy; refuses to overwrite.
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare two policies by canonical digest and stable identities.
    Diff {
        /// Currently active stable policy.
        #[arg(long)]
        current: PathBuf,
        /// Candidate stable policy.
        #[arg(long)]
        candidate: PathBuf,
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
        /// Optional trusted raw public Ed25519 key file.
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// Verify and summarize metadata without launching tools or making network calls.
    Replay {
        /// Audit JSONL path.
        path: PathBuf,
        /// Optional trusted raw public Ed25519 key file.
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// Rotate the installation key and archive the old verifier material.
    RotateKey {
        /// Active raw AgentGate signing-key file.
        key: PathBuf,
    },
    /// Export a shareable public verifier from the installation signing key.
    ExportKey {
        /// Active raw AgentGate signing-key file.
        #[arg(long)]
        signing_key: PathBuf,
        /// New raw public-key destination; refuses to overwrite.
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a detached signed checkpoint for independent publication.
    Anchor {
        /// Audit JSONL path.
        path: PathBuf,
        /// Active raw AgentGate signing-key file.
        #[arg(long)]
        signing_key: PathBuf,
        /// New detached-anchor JSON destination; refuses to overwrite.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a detached checkpoint against an exact audit log.
    VerifyAnchor {
        /// Audit JSONL path.
        path: PathBuf,
        /// Detached-anchor JSON path.
        #[arg(long)]
        anchor: PathBuf,
        /// Optional independently trusted raw public key.
        #[arg(long)]
        public_key: Option<PathBuf>,
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
            agentgate::run_stdio(
                &args.policy,
                args.server.as_deref(),
                &args.state_dir,
                args.audit_retention_days,
                args.audit_maximum_bytes,
                args.lineage_key.as_deref(),
            )
            .await?;
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
        Command::Policy(PolicyArgs {
            command: PolicyCommand::Migrate { policy, output },
        }) => {
            let source = std::fs::read_to_string(policy)?;
            let migrated = migrate_v1alpha1_to_v1(&source)?;
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            let mut file = options.open(&output)?;
            file.write_all(migrated.as_bytes())?;
            file.sync_all()?;
            println!("wrote stable v1 policy: {}", output.display());
        }
        Command::Policy(PolicyArgs {
            command: PolicyCommand::Diff { current, candidate },
        }) => {
            let current = CompiledPolicy::from_path(&current)?;
            let candidate = CompiledPolicy::from_path(&candidate)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&current.diff(&candidate))?
            );
        }
        Command::Audit(AuditArgs {
            command: AuditCommand::Verify { path, public_key },
        }) => {
            let public = public_key
                .as_deref()
                .map(verifying_key_from_public_file)
                .transpose()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verify(&path, public.as_ref())?)?
            );
        }
        Command::Audit(AuditArgs {
            command: AuditCommand::Replay { path, public_key },
        }) => {
            let public = public_key
                .as_deref()
                .map(verifying_key_from_public_file)
                .transpose()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&replay(&path, public.as_ref())?)?
            );
        }
        Command::Audit(AuditArgs {
            command: AuditCommand::RotateKey { key },
        }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&rotate_signing_key(&key)?)?
            );
        }
        Command::Audit(AuditArgs {
            command:
                AuditCommand::ExportKey {
                    signing_key,
                    output,
                },
        }) => {
            let key_id = export_public_key(&signing_key, &output)?;
            println!("exported public key {} to {}", key_id, output.display());
        }
        Command::Audit(AuditArgs {
            command:
                AuditCommand::Anchor {
                    path,
                    signing_key,
                    output,
                },
        }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&create_detached_anchor(
                    &path,
                    &signing_key,
                    &output
                )?)?
            );
        }
        Command::Audit(AuditArgs {
            command:
                AuditCommand::VerifyAnchor {
                    path,
                    anchor,
                    public_key,
                },
        }) => {
            let public = public_key
                .as_deref()
                .map(verifying_key_from_public_file)
                .transpose()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verify_detached_anchor(
                    &path,
                    &anchor,
                    public.as_ref()
                )?)?
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
