use alloy::sol_types::eip712_domain;
use alloy::{
    primitives::{address, keccak256, B256},
    signers::{local::PrivateKeySigner, Signer, SignerSync},
    sol,
    sol_types::SolStruct,
};
use anyhow::{Context, Result};
use serde::Serialize;
use std::env;

use crate::namehash;

#[derive(Debug)]
pub struct MessageSigner {
    key: Option<[u8; 32]>,
}

// Define the EIP-712 struct that matches your Solidity contract
sol! {
    #[derive(Serialize)]
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

        let path = format!(
            "http://127.0.0.1:1101/derive/secp256k1?path=DNS-RECORD-SIGNER-{}",
            domain_id
        );

        println!("Requesting key from KMS at: {}", path);

        let key_bytes: [u8; 32] = ureq::get(path)
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
        let records_hash = keccak256(message);

        println!("Domain ID: {:?}", domain_id);
        println!("Records Hash: {:?}", records_hash);

        // Create the struct instance
        let set_dns_records = setDNSRecords {
            domain_id: domain_id,
            recordsHash: records_hash,
        };

        // Create EIP-712 domain - this should match your contract's domain
        let eip712_domain_obj = eip712_domain! {
        name: "DomainManager",
        version: "1.0.0",
        };

        println!("EIP-712 Domain: {:?}", eip712_domain_obj);

        println!(
            "EIP-712 seperator: {}",
            eip712_domain_obj.separator()
        );

        let hash = set_dns_records.eip712_signing_hash(&eip712_domain_obj);
        println!("Signing hash: {:?}", hash);
        let signature = signer
            .sign_hash_sync(&hash)?;

        println!(
            "Recovered wallet address: {}",
            signature.recover_address_from_prehash(&hash)?
        );

        Ok(signature.to_string())
    }
}
