use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, Bytes, B256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use url::Url;
use hex;

// Define the ABI for the setDNSRecords function
// Replace with your actual contract ABI loading mechanism if needed
sol! {
    #[sol(rpc)]
    interface DnsManager {
        function setDNSRecords(bytes32 domain_id, bytes memory records, bytes memory sig) external;
        function setWhoIsDelegatee(bytes32 domain_id, address delegatee) external;
    }
}

pub async fn set_whois_delegatee(
    domain: String,
    contract_address: String,
    rpc_url: String,
    wallet_private_key: String,
    delegate_address: String,
) -> Result<()> {
    // Create domain id by hashing the domain
    let domain_id = keccak256(domain.as_bytes());

    // Parse delegate address
    let delegatee = delegate_address.parse::<Address>()
        .expect("Failed to parse delegate address");

    // Decode private key
    let private_key = B256::from_slice(
        &hex::decode(wallet_private_key).expect("Failed to decode private key"),
    );

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
    let contract_addr = contract_address.parse::<Address>()
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
        return Err(eyre::eyre!("Transaction failed - check contract interaction"));
    }

    println!("Successfully set WHOIS delegatee. Transaction hash: {:?}", tx_hash);
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
    let domain_id = keccak256(domain.as_bytes());

    // Convert encoded_records to bytes
    let records_bytes = Bytes::from(encoded_records.as_bytes().to_vec());
    
    // Convert signature to bytes
    let signature_bytes = Bytes::from(signature.as_bytes().to_vec());

    // Decode private key
    let private_key = B256::from_slice(
        &hex::decode(wallet_private_key).expect("Failed to decode private key"),
    );

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
    let contract_addr = contract_address.parse::<Address>()
        .expect("Failed to parse contract address");
    
    // Create a DnsManager instance
    let dns_manager = DnsManager::new(contract_addr, provider.clone());

    // Call the setDNSRecords function
    println!("Calling setDNSRecords for domain: {}", domain);
    let tx_hash = dns_manager
        .setDNSRecords(domain_id, records_bytes, signature_bytes)
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
        return Err(eyre::eyre!("Transaction failed - check contract interaction"));
    }

    println!("Successfully updated DNS records. Transaction hash: {:?}", tx_hash);
    Ok(())
}

