use anyhow::{Context, Result};
use alloy::{
    primitives::{address, keccak256}, signers::{local::PrivateKeySigner, SignerSync}, sol
};
use alloy::sol_types::eip712_domain;
use std::env;

use crate::namehash;

#[derive(Debug)]
pub struct MessageSigner {
    key: Option<[u8; 32]>,
}

// Define the EIP-712 struct that matches your Solidity contract
sol! {
    #[derive(Debug)]
    struct setDNSRecords {
        bytes32 domain_id;
        bytes32 recordsHash;
    }
}

impl MessageSigner {
    pub fn new() -> Self {
        Self { key: None }
    }

    pub async fn init(&mut self) -> Result<()> {
        let domain_id = env::var("DOMAIN_ID").context("DOMAIN_ID environment variable not set")?;
        
        let path = format!("http://127.0.0.1:1101/derive/secp256k1?path=DNS-RECORD-SIGNER-{}", domain_id);

        println!("Requesting key from KMS at: {}", path);
        
        let key_bytes: [u8; 32] =
            ureq::get(path)
                .call()
                .context("Failed to send KMS request")?
                .into_body()
                .read_to_vec()
                .context("Failed to read body")?[0..32]
                .try_into()
                .context("Failed to convert bytes")?;

        self.key = Some(key_bytes);

        Ok(())
    }


    pub async fn sign_message(&self, message: &str, domain_name: &str) -> Result<String> {
        println!("In the sign message section");
        let key = self.key.as_ref().context("Signer not initialized")?;
        let signer = PrivateKeySigner::from_bytes(key.into())?;

        let signer_address = signer.address();
        println!("Signer address: {}", signer_address);
    
        let domain_id = namehash(domain_name); 
        let records_hash = keccak256(message.as_bytes());
    
        // Create the struct instance
        let set_dns_records = setDNSRecords {
            domain_id: domain_id,
            recordsHash: records_hash,
        };
    
        // Create EIP-712 domain - this should match your contract's domain
        let eip712_domain_obj = eip712_domain! {
            name: "DNS Manager",
            version: "1", 
            chain_id: 10,
            verifying_contract: address!("0xB5e7d42440738df2270749E336329fA1A360C313"),
        };
    
        // Sign the typed data
        let signature = signer.sign_typed_data_sync(&set_dns_records, &eip712_domain_obj)?;
    
        Ok(hex::encode(signature.as_bytes()))
    }
    
    // Alternative implementation if you prefer manual struct creation:
    pub async fn _sign_message_manual(&self, message: &str, domain_name: &str) -> Result<String> {
        println!("In the sign message manual section");
        let key = self.key.as_ref().context("Signer not initialized")?;
        let signer = PrivateKeySigner::from_bytes(key.into())?;
    
        let domain_id = namehash(domain_name); 
        let records_hash = keccak256(message.as_bytes());
    
        // Manual EIP-712 encoding to match Solidity exactly
        let type_hash = keccak256("SetDNSRecords(bytes32 domain_id,bytes32 recordsHash)");
        
        // This matches: abi.encode(SET_RECORDS_TYPEHASH, domain_id, keccak256(records))
        let struct_hash = keccak256(
            [
                type_hash.as_slice(),
                domain_id.as_slice(), 
                records_hash.as_slice()
            ].concat()
        );
    
        // Create EIP-712 domain
        let eip712_domain_obj = eip712_domain! {
            name: "DNS Manager",
            version: "1",
            chain_id: 10, 
            verifying_contract: address!("0xB5e7d42440738df2270749E336329fA1A360C313"),
        };
    
        // Get domain separator
        let domain_separator = eip712_domain_obj.hash_struct();
        
        // Create typed data hash: keccak256("\x19\x01" + domain_separator + struct_hash)
        let typed_data_hash = keccak256(
            [
                b"\x19\x01".as_slice(),
                domain_separator.as_slice(),
                struct_hash.as_slice()
            ].concat()
        );
    
        // Sign the hash
        let signature = signer.sign_hash_sync(&typed_data_hash)?;
    
        println!("Signer address: {}", signer.address());
    
        Ok(hex::encode(signature.as_bytes()))
    }
}
