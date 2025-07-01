use std::str::FromStr;

use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use hex;
use reqwest;
use url::Url;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    DnsManager,
    "src/abis/DomainManager.json"
);

sol! {
    #[sol(rpc)]
    interface DomainController {
        function safeTransferFrom(address from, address to, uint256 tokenId, uint256 amount, bytes data) external;
    }
}

pub fn namehash(domain: &str) -> B256 {
    let mut node = B256::ZERO;
    if domain.is_empty() {
        return node;
    }

    let labels: Vec<&str> = domain.split('.').rev().collect();

    for label in labels {
        let label_hash = keccak256(label.as_bytes());

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(node.as_slice());
        combined[32..].copy_from_slice(label_hash.as_slice());

        node = keccak256(&combined);
    }

    node
}

pub async fn set_whois_delegatee(
    domain: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
    delegate_address: String,
) -> Result<()> {
    // Create domain id by hashing the domain
    // let domain_id = keccak256(domain.as_bytes());
    let domain_id = namehash(&domain);
    println!("Domain ID: {:?}", domain_id);

    // Parse delegate address
    let delegatee = delegate_address
        .parse::<Address>()
        .expect("Failed to parse delegate address");

    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Create contract instance
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call the setWhoIsDelegatee function
    println!("Setting WHOIS delegatee for domain: {}", domain);
    let tx_hash = dns_manager
        .setWhoIsDelegatee(domain_id, delegatee)
        .send()
        .await?
        .watch()
        .await?;

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }

    println!(
        "Successfully set WHOIS delegatee. Transaction hash: {:?}",
        tx_hash
    );
    Ok(())
}

pub async fn call_set_dns_records(
    domain: String,
    encoded_records: String,
    signature: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Create domain id by hashing the domain
    let domain_id = namehash(&domain);

    // Convert encoded_records to bytes
    let records_bytes = Bytes::from_str(&encoded_records)?;
    println!("Contract DNS records: {:?}", records_bytes);

    // Convert signature to bytes
    let signature_bytes = Bytes::from(hex::decode(signature).expect("Failed to decode signature"));
    println!("Signature bytes: {:?}", signature_bytes);

    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Create contract instance
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call the setDNSRecords function
    println!("Calling setDNSRecords for domain: {}", domain);
    let tx_hash = dns_manager
        .setDNSRecords(domain_id, records_bytes, signature_bytes) // 40 gwei
        .send()
        .await?
        .watch()
        .await?;

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }

    println!(
        "Successfully updated DNS records. Transaction hash: {:?}",
        tx_hash
    );
    Ok(())
}

pub async fn transfer_domain(
    domain: String,
    new_owner_wallet_address: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Create domain id by hashing the domain
    let domain_id = namehash(&domain);

    // Parse new owner address
    let new_owner = new_owner_wallet_address
        .parse::<Address>()
        .expect("Failed to parse new owner address");

    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer wallet
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let signer_address = signer.address();
    println!("Signer address: {:?}", signer_address);
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Create a DnsManager instance
    let domain_controller = DomainController::new(contract_addr, provider.clone());

    // Call the transferDomain function
    println!(
        "Transferring domain: {} from {} to new owner: {}",
        domain, signer_address, new_owner
    );
    // Convert domain_id (B256) to U256 for the tokenId parameter
    let token_id = U256::from_be_bytes(domain_id.0);
    println!("Token ID: {:?}", token_id);
    let tx_hash = domain_controller
        .safeTransferFrom(
            signer_address,
            new_owner,
            token_id,
            U256::from(1),
            "".into(),
        ) // 40 gwei
        .send()
        .await?
        .watch()
        .await?;
    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;
    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }
    println!(
        "Successfully transferred domain. Transaction hash: {:?}",
        tx_hash
    );
    Ok(())
}

pub async fn set_kms_contract(
    domain: String,
    kms_contract_address: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Create domain id by hashing the domain
    let domain_id = namehash(&domain);

    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Parse KMS contract address
    let kms_contract_addr = kms_contract_address
        .parse::<Address>()
        .expect("Failed to parse KMS contract address");

    // Call the setKMSContract function
    println!("Setting KMS contract for domain: {}", domain);
    let tx_hash = dns_manager
        .setKMSContract(domain_id, kms_contract_addr)
        .send()
        .await?
        .watch()
        .await?;
    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;
    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }
    println!(
        "Successfully set KMS contract. Transaction hash: {:?}",
        tx_hash
    );
    Ok(())
}

pub async fn set_kms_key(
    domain: String,
    kms_contract_address: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Create domain id by hashing the domain
    let domain_id = namehash(&domain);

    // Make API call to derive KMS signer address
    let api_url = format!(
        "http://arbone-v4.kms.box:1101/derive/secp256k1/address/ethereum?address={}&path=DNS-RECORD-SIGNER-{}",
        kms_contract_address, domain_id
    );

    let client = reqwest::Client::new();
    let response = client.get(&api_url).send().await?;

    if !response.status().is_success() {
        return Err(eyre::eyre!(
            "API call failed with status: {}",
            response.status()
        ));
    }

    // Extract proof from response header
    let proof = response
        .headers()
        .get("x-marlin-kms-signature")
        .ok_or_else(|| eyre::eyre!("Missing x-marlin-kms-signature header"))?
        .to_str()
        .map_err(|_| eyre::eyre!("Invalid x-marlin-kms-signature header"))?
        .to_string();

    // Parse response body to get KMS signer address
    let kms_signer_address = response.text().await?;

    // Decode proof to bytes
    let proof_bytes =
        Bytes::from(hex::decode(proof).map_err(|_| eyre::eyre!("Failed to decode proof"))?);

    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Parse KMS signer address
    let kms_signer_addr = kms_signer_address
        .parse::<Address>()
        .expect("Failed to parse KMS signer address");

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call setKMSKey on the contract
    println!("Setting KMS key for domain: {}", domain);
    let tx = match dns_manager
        .setKMSKey(domain_id, kms_signer_addr, proof_bytes)
        .send()
        .await
    {
        Ok(tx) => tx.watch().await?,
        Err(e) => {
            return Err(eyre::eyre!("Failed to set KMS key: {}", e));
        }
    };

    // Get and verify the receipt
    let receipt = provider
        .get_transaction_receipt(tx)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }

    println!("Successfully set KMS key. Transaction hash: {:?}", tx);
    Ok(())
}

pub async fn has_role(
    role: String,
    account: String,
    contract_address: String,
    rpc_url: String,
) -> Result<bool> {
    // Create provider without wallet since this is a read-only call
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Parse account address
    let account_addr = account
        .parse::<Address>()
        .expect("Failed to parse account address");

    println!("Checking role: {} for account: {}", role, account);

    // Parse role bytes32 - strip 0x prefix if present and decode from hex
    let role_bytes = B256::from_slice(
        &hex::decode(role.strip_prefix("0x").unwrap_or(&role))
            .expect("Failed to decode role bytes32"),
    );

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call hasRole function
    let has_role = dns_manager
        .hasRole(role_bytes, account_addr)
        .call()
        .await?
        ._0;

    Ok(has_role)
}

pub async fn grant_role(
    role: String,
    account: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Parse account address
    let account_addr = account
        .parse::<Address>()
        .expect("Failed to parse account address");

    // Parse role bytes32
    let role_bytes = B256::from_slice(
        &hex::decode(role.strip_prefix("0x").unwrap_or(&role))
            .expect("Failed to decode role bytes32"),
    );

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call grantRole function
    let tx_hash = dns_manager
        .grantRole(role_bytes, account_addr)
        .send()
        .await?
        .watch()
        .await?;

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }

    println!("Successfully granted role. Transaction hash: {:?}", tx_hash);
    Ok(())
}

pub async fn revoke_role(
    role: String,
    account: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Parse account address
    let account_addr = account
        .parse::<Address>()
        .expect("Failed to parse account address");

    // Parse role bytes32
    let role_bytes = B256::from_slice(
        &hex::decode(role.strip_prefix("0x").unwrap_or(&role))
            .expect("Failed to decode role bytes32"),
    );

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call revokeRole function
    let tx_hash = dns_manager
        .revokeRole(role_bytes, account_addr)
        .send()
        .await?
        .watch()
        .await?;

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }

    println!("Successfully revoked role. Transaction hash: {:?}", tx_hash);
    Ok(())
}

pub async fn get_domain_owner_role(
    domain_id: String,
    contract_address: String,
    rpc_url: String,
) -> Result<B256> {
    // Create provider without wallet since this is a read-only call
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Parse domain_id bytes32
    let domain_id_bytes = B256::from_slice(
        &hex::decode(domain_id.strip_prefix("0x").unwrap_or(&domain_id))
            .expect("Failed to decode domain_id bytes32"),
    );

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call getDomainOwnerRole function
    let role = dns_manager
        .getDomainOwnerRole(domain_id_bytes)
        .call()
        .await?
        ._0;

    Ok(role)
}

pub async fn get_domain_manager_role(
    domain_id: String,
    contract_address: String,
    rpc_url: String,
) -> Result<B256> {
    // Create provider without wallet since this is a read-only call
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Parse domain_id bytes32
    let domain_id_bytes = B256::from_slice(
        &hex::decode(domain_id.strip_prefix("0x").unwrap_or(&domain_id))
            .expect("Failed to decode domain_id bytes32"),
    );

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call getDomainManagerRole function
    let role = dns_manager
        .getDomainManagerRole(domain_id_bytes)
        .call()
        .await?
        ._0;

    Ok(role)
}

pub async fn retrieve_domain(
    domain_id: String,
    to: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
) -> Result<()> {
    // Parse domain_id bytes32
    let domain_id_bytes = B256::from_slice(
        &hex::decode(domain_id.strip_prefix("0x").unwrap_or(&domain_id))
            .expect("Failed to decode domain_id bytes32"),
    );

    // Parse destination address
    let to_addr = to
        .parse::<Address>()
        .expect("Failed to parse destination address");

    // Decode private key
    let private_key =
        B256::from_slice(&hex::decode(wallet_private_key).expect("Failed to decode private key"));

    // Create signer
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .expect("Failed to create signer from private key");
    let signer_address = signer.address();
    println!("Signer address: {:?}", signer_address);
    let wallet = EthereumWallet::from(signer);

    // Create provider
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse::<Url>().expect("Failed to parse RPC URL"));

    // Parse contract address
    let contract_addr = contract_address
        .parse::<Address>()
        .expect("Failed to parse contract address");

    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call the retrieveDomain function
    println!("Retrieving domain ID: {} to address: {}", domain_id, to);
    let tx_hash = dns_manager
        .retrieveDomain(domain_id_bytes, to_addr)
        .send()
        .await?
        .watch()
        .await?;

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "Transaction failed - check contract interaction"
        ));
    }

    println!(
        "Successfully retrieved domain. Transaction hash: {:?}",
        tx_hash
    );
    Ok(())
}
