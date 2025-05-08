use clap::{Parser, Subcommand};
mod contract_interaction;

mod commands;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Set DNS records
    #[command(name = "set-dns")]
    SetDns {
        /// Domain
        #[arg(long)]
        domain: String,
        
        /// Enclave IP address
        #[arg(long)]
        enclave_ip: String,
        
        /// Smart contract address
        #[arg(long)]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long)]
        wallet_private_key: String,
    },
    
    /// Set WHOIS delegation address
    #[command(name = "set-whois")]
    SetWhois {
        /// Domain ID
        #[arg(long)]
        domain: String,
        
        /// Delegate wallet address
        #[arg(long)]
        delegate_wallet_address: String,
        
        /// Smart contract address
        #[arg(long)]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long)]
        wallet_private_key: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::SetDns { domain, enclave_ip, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_set_dns_records(domain, enclave_ip, contract_address, wallet_private_key).await {
                eprintln!("Error setting DNS records: {}", e);
            }
        },
        Some(Commands::SetWhois { domain, delegate_wallet_address, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_set_whois_delegation(domain, delegate_wallet_address, contract_address, wallet_private_key).await {
                eprintln!("Error setting WHOIS delegation: {}", e);
            }
        },
        None => {
            println!("No command provided. Use --help for usage information.");
        }
    }
}
