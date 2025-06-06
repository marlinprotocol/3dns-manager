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
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
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
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    },

    /// Transfer domain ownership
    #[command(name = "transfer-domain")]
    TransferDomain {
        /// Domain ID
        #[arg(long, short)]
        domain: String,
        
        /// New owner wallet address
        #[arg(long, short)]
        new_owner_wallet_address: String,

        /// Smart contract address for domain controller
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    },

    /// Set KMS contract address
    #[command(name = "set-kms-contract")]
    SetKms {
        /// Domain ID
        #[arg(long)]
        domain: String,

        /// KMS contract address
        #[arg(long, short='k')]
        kms_contract_address: String,
        
        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    },

    /// Set KMS key
    #[command(name = "set-kms-key")]
    SetKmsKey {
        /// Domain
        #[arg(long)]
        domain: String,

        /// KMS signer address
        #[arg(long)]
        kms_signer_address: String,

        /// Proof
        #[arg(long)]
        proof: String,

        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    }
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
        Some(Commands::TransferDomain { domain, new_owner_wallet_address, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_transfer_domain(domain, new_owner_wallet_address,  contract_address, wallet_private_key).await {
                eprintln!("Error transferring domain: {}", e);
            }
        },
        Some(Commands::SetKms { domain, kms_contract_address, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_set_kms(domain, kms_contract_address, contract_address, wallet_private_key).await {
                eprintln!("Error setting KMS contract address: {}", e);
            }
        },
        Some(Commands::SetKmsKey { domain, kms_signer_address, proof, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_set_kms_key(domain, kms_signer_address, proof, contract_address, wallet_private_key).await {
                eprintln!("Error setting KMS key: {}", e);
            }
        },
        None => {
            println!("No command provided. Use --help for usage information.");
        }
    }
}
