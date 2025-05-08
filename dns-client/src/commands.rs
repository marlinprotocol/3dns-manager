use crate::contract_interaction;
use eyre::Result;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Deserialize, Serialize)]
struct DnsRecordResponse {
    #[serde(rename = "dns-record")]
    dns_record: String,
    signature: String,
}

/// Handles the "set dns-records" command
pub async fn handle_set_dns_records(domain: &str, enclave_ip: &str, contract_address: &str, wallet_private_key: &str) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";
    
    // Process A record
    if let Err(e) = query_and_set_dns_record(enclave_ip, "a-record", domain, contract_address, rpc_url, wallet_private_key).await {
        eprintln!("Error processing A record: {}", e);
    } else {
        println!("Successfully processed A record");
    }
    
    // Process CAA record
    if let Err(e) = query_and_set_dns_record(enclave_ip, "caa-record", domain, contract_address, rpc_url, wallet_private_key).await {
        eprintln!("Error processing CAA record: {}", e);
    } else {
        println!("Successfully processed CAA record");
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
    wallet_private_key: &str
) -> Result<()> {
    let url = format!("http://{}:8004/{}", enclave_ip, record_type);
    
    // Query the record from the enclave
    println!("Querying {} from {}", record_type, url);
    let response = reqwest::get(&url).await?;
    
    if !response.status().is_success() {
        return Err(eyre::eyre!("Failed to get record from enclave: {}", response.status()));
    }

    let response_text = response.text().await?;
    println!("Response: {}", response_text);
    
    let record_data: DnsRecordResponse = serde_json::from_str(&response_text)?;
    println!("Received record: {}", record_data.dns_record);
    
    // Call the contract to set the DNS record
    contract_interaction::call_set_dns_records(
        domain.to_string(),
        record_data.dns_record,
        record_data.signature,
        contract_address.to_string(),
        rpc_url.to_string(),
        wallet_private_key.to_string(),
    ).await?;
    
    Ok(())
}

/// Handles the "set whois-delegation" command
pub async fn handle_set_whois_delegation(domain: &str, delegate_wallet_address: &str, contract_address: &str, wallet_private_key: &str) -> Result<()> {
    let rpc_url = "https://mainnet.optimism.io";
    
    // Call the contract interaction function
    contract_interaction::set_whois_delegatee(
        domain.to_string(), 
        contract_address.to_string(), 
        rpc_url.to_string(), 
        wallet_private_key.to_string(),
        delegate_wallet_address.to_string()
    ).await?;
    
    Ok(())
} 