use anyhow::{Context, Result};
use alloy::{
    dyn_abi::DynSolValue, primitives::{address, keccak256, Address, B256, U256}, signers::{local::PrivateKeySigner, SignerSync}, sol
};
use alloy::sol_types::eip712_domain;
use warp::filters::body::bytes;
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
            name: "DomainManager",
            version: "1.0.0", 
            chain_id: 10,
            verifying_contract: address!("0xB5e7d42440738df2270749E336329fA1A360C313"),
        };
    
        // Sign the typed data
        let signature = signer.sign_typed_data_sync(&set_dns_records, &eip712_domain_obj)?;
    
        Ok(hex::encode(signature.as_bytes()))
    }
    
    // Alternative implementation if you prefer manual struct creation:
    pub async fn _sign_message_manual(&self, message: &str, domain_name: &str) -> Result<String> {
        let key = self.key.as_ref().context("Signer not initialized")?;
        let signer = PrivateKeySigner::from_bytes(key.into())?;

        println!("Signer address: {}", signer.address());

        let domain_id = namehash(domain_name); 
        let records_hash = keccak256(message.as_bytes());


        let domain_value = DynSolValue::Tuple(vec![
            DynSolValue::String("DNS Manager".to_string()),
            DynSolValue::String("1".to_string()),
            DynSolValue::Uint(U256::from(10), 256),
            DynSolValue::Address(Address::from({
                let bytes: [u8; 20] = hex::decode("B5e7d42440738df2270749E336329fA1A360C313").unwrap().try_into().unwrap();
                bytes
            })),
        ]);

        let message_value = DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(domain_id.into(), 32),
            DynSolValue::FixedBytes(records_hash.into(), 32),
        ]);

        // Encode the domain and message
        let encoded_domain = domain_value.abi_encode();
        let encoded_message = message_value.abi_encode();

        // Calculate EIP-712 hash
        let domain_separator = keccak256(&encoded_domain);
        let message_hash = keccak256(&encoded_message);
        let eip712_hash = keccak256([&[0x19, 0x01], &domain_separator[..], &message_hash[..]].concat());

        // Sign the hash
        let signature = signer.sign_hash_sync(&eip712_hash)?;

        Ok(hex::encode(signature.as_bytes()))
    }
}
