use crate::contract_interaction;
use eyre::Result;
use reqwest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct DnsRecordResponse {
    #[serde(rename = "dns-record")]
    dns_record: String,
    signature: String,
}

/// Handles the "set dns-records" command
pub async fn handle_set_dns_records(
    domain: &str,
    enclave_ip: &str,
    contract_address: &str,
    wallet_private_key: &str,
    a_ttl: u32,
    _caa_ttl: u32,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Process DNS records
    if let Err(e) = query_and_set_dns_record(
        enclave_ip,
        "dns-records",
        domain,
        contract_address,
        rpc_url,
        wallet_private_key,
        a_ttl,
    )
    .await
    {
        eprintln!("Error processing A record: {}", e);
    } else {
        println!("Successfully set DNS records for domain: {}", domain);
    }

    Ok(())
}

/// Query a DNS record from the enclave and set it in the contract
async fn query_and_set_dns_record(
    enclave_ip: &str,
    record_type: &str,
    domain: &str,
    contract_address: &str,
    rpc_url: &str,
    wallet_private_key: &str,
    ttl: u32,
) -> Result<()> {
    let url = format!("http://{}:8004/{}?ttl={}", enclave_ip, record_type, ttl);

    // Query the record from the enclave
    println!("Querying {} from {}", record_type, url);
    let response = reqwest::get(&url).await?;

    if !response.status().is_success() {
        return Err(eyre::eyre!(
            "Failed to get record from enclave: {}",
            response.status()
        ));
    }

    let response_text = response.text().await?;
    println!("Response: {}", response_text);

    // Parse the response which is in format "data:signature"
    let parts: Vec<&str> = response_text.split(':').collect();
    if parts.len() != 2 {
        return Err(eyre::eyre!(
            "Invalid response format, expected 'data:signature'"
        ));
    }

    let dns_record = parts[0].to_string();
    let signature = parts[1].to_string();

    println!("Received record: {}", dns_record);
    println!("Received signature: {}", signature);

    // Call the contract to set the DNS record
    contract_interaction::call_set_dns_records(
        domain.to_string(),
        dns_record,
        signature,
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    Ok(())
}

/// Handles the "set whois-delegation" command
pub async fn handle_set_whois_delegation(
    domain: &str,
    delegate_wallet_address: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    contract_interaction::set_whois_delegatee(
        domain.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
        delegate_wallet_address.to_string(),
    )
    .await?;

    Ok(())
}

/// Handles the "transfer domain" command
pub async fn handle_transfer_domain(
    domain: &str,
    new_owner_wallet_address: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    contract_interaction::transfer_domain(
        domain.to_string(),
        new_owner_wallet_address.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    Ok(())
}

/// Handles the "set kms" command
pub async fn handle_set_kms(
    domain: &str,
    kms_contract_address: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    contract_interaction::set_kms_contract(
        domain.to_string(),
        kms_contract_address.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    Ok(())
}

/// Handles the "set kms key" command
pub async fn handle_set_kms_key(
    domain_id: &str,
    kms_contract_address: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    contract_interaction::set_kms_key(
        domain_id.to_string(),
        kms_contract_address.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    Ok(())
}

/// Handles the "has-role" command
pub async fn handle_has_role(role: &str, account: &str, contract_address: &str) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    let has_role = contract_interaction::has_role(
        role.to_string(),
        account.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
    )
    .await?;

    println!(
        "Account {} {} role {}",
        account,
        if has_role { "has" } else { "does not have" },
        role
    );

    Ok(())
}

/// Handles the "grant-role" command
pub async fn handle_grant_role(
    role: &str,
    account: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    contract_interaction::grant_role(
        role.to_string(),
        account.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    println!("Successfully granted role {} to account {}", role, account);
    Ok(())
}

/// Handles the "revoke-role" command
pub async fn handle_revoke_role(
    role: &str,
    account: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    contract_interaction::revoke_role(
        role.to_string(),
        account.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    println!(
        "Successfully revoked role {} from account {}",
        role, account
    );
    Ok(())
}

/// Handles the "get-owner-role" command
pub async fn handle_get_domain_owner_role(domain_id: &str, contract_address: &str) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    let role = contract_interaction::get_domain_owner_role(
        domain_id.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
    )
    .await?;

    println!(
        "Domain owner role for domain_id {}: 0x{}",
        domain_id,
        hex::encode(role)
    );
    Ok(())
}

/// Handles the "get-manager-role" command
pub async fn handle_get_domain_manager_role(domain_id: &str, contract_address: &str) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Call the contract interaction function
    let role = contract_interaction::get_domain_manager_role(
        domain_id.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
    )
    .await?;

    println!(
        "Domain manager role for domain_id {}: 0x{}",
        domain_id,
        hex::encode(role)
    );
    Ok(())
}

/// Handles the "compute-domain-id" command
pub async fn handle_compute_domain_id(domain: &str) -> Result<()> {
    let domain_id = contract_interaction::namehash(domain);
    println!("Domain ID for {}: 0x{}", domain, hex::encode(domain_id));
    Ok(())
}

/// Handles the "retrieve-domain" command
pub async fn handle_retrieve_domain(
    domain: &str,
    to: &str,
    contract_address: &str,
    wallet_private_key: &str,
) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";

    // Compute the domain ID using namehash
    let domain_id = contract_interaction::namehash(domain);
    let domain_id_hex = hex::encode(domain_id);

    // Call the contract interaction function
    contract_interaction::retrieve_domain(
        domain_id_hex,
        to.to_string(),
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    )
    .await?;

    Ok(())
}
