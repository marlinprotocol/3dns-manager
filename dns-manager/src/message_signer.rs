use alloy::primitives::B256;
use alloy::sol_types::eip712_domain;
use alloy::{
    primitives::{address, keccak256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::SolStruct,
};
use anyhow::{Context, Result};
use std::env;
use std::hash::Hash;

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
        let records_hash = keccak256(hex::decode(message)?);

        // Create the struct instance
        let set_dns_records = setDNSRecords {
            domain_id: domain_id,
            recordsHash: records_hash,
        };

        // Debug: Check what EIP-712 encode type generates
        let eip712_type_string = setDNSRecords::eip712_encode_type();
        println!("EIP-712 type string: {}", eip712_type_string);
        println!(
            "EIP-712 type hash: {:?}",
            setDNSRecords::eip712_type_hash(&set_dns_records)
        );

        // Create EIP-712 domain - this should match your contract's domain
        let eip712_domain_obj = eip712_domain! {
            name: "DomainManager",
            version: "1.0.0",
            chain_id: 10,
            verifying_contract: address!("0xB5e7d42440738df2270749E336329fA1A360C313"),
            salt: B256::ZERO,

        };

        // Debug: Print the struct hash to verify encoding
        let struct_hash = set_dns_records.eip712_hash_struct();
        println!("Struct hash: {:?}", struct_hash);

        // Sign the typed data
        let signature = signer.sign_typed_data_sync(&set_dns_records, &eip712_domain_obj)?;
        let encoded_signature = hex::encode(signature.as_bytes());
        println!("Encoded signature: {}", encoded_signature);
        Ok(encoded_signature)
    }
}
