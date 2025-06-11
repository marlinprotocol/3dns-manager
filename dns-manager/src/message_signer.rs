use anyhow::{Context, Result};
use alloy::{
    primitives::{keccak256, B256},
    sol,
    signers::{local::PrivateKeySigner, SignerSync},
};

use alloy::sol_types::eip712_domain;

use crate::namehash;

#[derive(Debug)]
pub struct MessageSigner {
    key: Option<[u8; 32]>,
}

sol! {
    #[derive(Debug)]
    struct SetRecordsParams {
        bytes32 domain_id;
        bytes32 records_hash;
    }
}

impl MessageSigner {
    pub fn new() -> Self {
        Self { key: None }
    }

    pub async fn init(&mut self) -> Result<()> {
        // todo: update path -- generate domain id from domain name
        let key_bytes: [u8; 32] =
            ureq::get("http://127.0.0.1:1100/derive/secp256k1?path=signing-server")
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

    pub async fn sign_message(&self, message: &str, domain: &str) -> Result<String> {
        let key = self.key.as_ref().context("Signer not initialized")?;
        let signer = PrivateKeySigner::from_bytes(key.into())?;

        let domain_id = namehash(domain);
        let hashed_records = keccak256(message.as_bytes());

        let params = SetRecordsParams {
            domain_id: domain_id.into(),
            records_hash: hashed_records.into(),
        };

        // Create EIP-712 domain
        let domain = eip712_domain! {
            name: "3DNS Domain Manager",
            version: "1",
        };

        let signature = signer.sign_typed_data_sync(&params, &domain)?;

        let signer_address = signer.address();
        let signer_creds = signer.credential();
        print!("Signer address: {}\n", signer_address);
        println!("Signer credentials: {:?}", signer_creds.verifying_key());

        Ok(hex::encode(signature.as_bytes()))
    }
}
