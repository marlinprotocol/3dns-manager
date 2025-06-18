use alloy::{
    dyn_abi::DynSolValue,
    primitives::{keccak256, Address, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    hex,
};
use anyhow::{Context, Result};
use std::{env, str::FromStr};

use crate::namehash;

#[derive(Debug)]
pub struct MessageSigner {
    key: Option<[u8; 32]>,
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

        println!("Message");
        println!("Message: {}", message);
        let msg = hex::decode(message)?;

        let signer_address = signer.address();
        println!("Signer address: {}", signer_address);

        let domain_id = namehash(domain_name);
        let records_hash = keccak256(msg);

        println!("Domain ID: {:?}", domain_id);
        println!("Records Hash value: {:?}", records_hash);

        let domain_value = DynSolValue::Tuple(vec![
            DynSolValue::String("DomainManager".to_string()),
            DynSolValue::String("1.0.0".to_string()),
            DynSolValue::Uint(U256::from(10), 256), // chainId - adjust as needed
            DynSolValue::Address(Address::from_str("0xB5e7d42440738df2270749E336329fA1A360C313")?),    // verifyingContract - adjust as needed
        ]);

        println!("Domain Value: {:?}", domain_value);


        let message_value = DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(domain_id, 32),
            DynSolValue::FixedBytes(records_hash, 32),
        ]);

        // Encode the domain and message
        let encoded_domain = domain_value.abi_encode();
        let encoded_message = message_value.abi_encode();

        println!("Encoded domain: 0x{}", hex::encode(&encoded_domain));
        println!("Encoded message: 0x{}", hex::encode(&encoded_message));

        // Calculate type hash for setDNSRecords
        let type_string = "setDNSRecords(bytes32 domain_id, bytes32 recordsHash)";
        let type_hash = keccak256(type_string);
        println!("Type hash: 0x{}", type_hash);

        // Calculate struct hash: keccak256(abi.encode(TYPE_HASH, domain_id, recordsHash))
        let struct_hash_data = [
            &type_hash[..],
            &domain_id[..],
            &records_hash[..]
        ].concat();
        let struct_hash = keccak256(&struct_hash_data);
        println!("Struct hash: 0x{}", hex::encode(struct_hash));

        // Calculate domain separator
        let domain_separator = keccak256(&encoded_domain);
        println!("Domain separator: 0x{}", hex::encode(domain_separator));

        // Calculate EIP-712 hash: keccak256("\x19\x01" + domainSeparator + structHash)
        let eip712_hash = keccak256([&[0x19, 0x01], &domain_separator[..], &struct_hash[..]].concat());
        println!("EIP-712 hash: 0x{}", hex::encode(eip712_hash));

        // Sign the hash
        let signature = signer.sign_hash_sync(&eip712_hash)?;

        println!(
            "Recovered wallet address: {}",
            signature.recover_address_from_prehash(&eip712_hash)?
        );

        Ok(signature.to_string())
    }
}
