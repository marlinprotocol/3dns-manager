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

        /// TTL for A record
        #[arg(long, default_value = "3600")]
        a_ttl: u32,

        /// TTL for CAA record
        #[arg(long, default_value = "3600")]
        caa_ttl: u32,
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
    },

    /// Check if an account has a role
    #[command(name = "has-role")]
    HasRole {
        /// Role identifier (bytes32)
        #[arg(long)]
        role: String,
        
        /// Account address to check
        #[arg(long)]
        account: String,
        
        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
    },

    /// Grant a role to an account
    #[command(name = "grant-role")]
    GrantRole {
        /// Role identifier (bytes32)
        #[arg(long)]
        role: String,
        
        /// Account address to grant the role to
        #[arg(long)]
        account: String,
        
        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    },

    /// Revoke a role from an account
    #[command(name = "revoke-role")]
    RevokeRole {
        /// Role identifier (bytes32)
        #[arg(long)]
        role: String,
        
        /// Account address to revoke the role from
        #[arg(long)]
        account: String,
        
        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
        
        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    },

    /// Get domain owner role identifier
    #[command(name = "get-owner-role")]
    GetDomainOwnerRole {
        /// Domain ID (bytes32)
        #[arg(long)]
        domain_id: String,
        
        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
    },

    /// Get domain manager role identifier
    #[command(name = "get-manager-role")]
    GetDomainManagerRole {
        /// Domain ID (bytes32)
        #[arg(long)]
        domain_id: String,
        
        /// Smart contract address
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,
    },

    /// Compute domain ID (namehash)  
    #[command(name = "compute-domain-id")]
    ComputeDomainId {
        /// Domain name
        #[arg(long)]
        domain: String,
    },

    /// Retrieve domain from contract
    #[command(name = "retrieve-domain")]
    RetrieveDomain {
        /// Domain name
        #[arg(long)]
        domain: String,

        /// Destination address to retrieve the domain to
        #[arg(long)]
        to: String,

        /// Smart contract address 
        #[arg(long, default_value = "0x63f90A1b481a039CE1f7f350F74fFD6E56CFDe54")]
        contract_address: String,

        /// Wallet private key
        #[arg(long, short='p')]
        wallet_private_key: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::SetDns { domain, enclave_ip, contract_address, wallet_private_key, a_ttl, caa_ttl }) => {
            if let Err(e) = commands::handle_set_dns_records(domain, enclave_ip, contract_address, wallet_private_key, *a_ttl, *caa_ttl).await {
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
        Some(Commands::HasRole { role, account, contract_address }) => {
            if let Err(e) = commands::handle_has_role(role, account, contract_address).await {
                eprintln!("Error checking role: {}", e);
            }
        },
        Some(Commands::GrantRole { role, account, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_grant_role(role, account, contract_address, wallet_private_key).await {
                eprintln!("Error granting role: {}", e);
            }
        },
        Some(Commands::RevokeRole { role, account, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_revoke_role(role, account, contract_address, wallet_private_key).await {
                eprintln!("Error revoking role: {}", e);
            }
        },
        Some(Commands::GetDomainOwnerRole { domain_id, contract_address }) => {
            if let Err(e) = commands::handle_get_domain_owner_role(domain_id, contract_address).await {
                eprintln!("Error getting domain owner role: {}", e);
            }
        },
        Some(Commands::GetDomainManagerRole { domain_id, contract_address }) => {
            if let Err(e) = commands::handle_get_domain_manager_role(domain_id, contract_address).await {
                eprintln!("Error getting domain manager role: {}", e);
            }
        },
        Some(Commands::ComputeDomainId { domain }) => {
            if let Err(e) = commands::handle_compute_domain_id(domain).await {
                eprintln!("Error computing domain ID: {}", e);
            }
        },
        Some(Commands::RetrieveDomain { domain, to, contract_address, wallet_private_key }) => {
            if let Err(e) = commands::handle_retrieve_domain(domain, to, contract_address, wallet_private_key).await {
                eprintln!("Error retrieving domain: {}", e);
            }
        },
        None => {
            println!("No command provided. Use --help for usage information.");
        }
    }
}
