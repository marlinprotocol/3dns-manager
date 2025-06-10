use anyhow::{Context, Result};
use alloy::{primitives::keccak256, signers::{k256::sha2::{Digest,Sha256}, local::PrivateKeySigner, SignerSync}};

use crate::namehash;

pub struct MessageSigner{
    key: Option<[u8; 32]>,
}

const set_record_typehash: &str = "setDNSRecords(bytes32 domain_id, bytes32 recordsHash)";

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

        let record_type_hash = keccak256(set_record_typehash.as_bytes());

        let hashed_records = keccak256(message.as_bytes());

        let mut hasher = Sha256::new();
        hasher.update(record_type_hash);
        hasher.update(domain_id);
        hasher.update(hashed_records);
        let digest: [u8; 32] = hasher.finalize().into();

        let signature = match signer.sign_hash_sync(&digest.into()) {
            Ok(sig) => sig,
            Err(e) => return Err(anyhow::anyhow!("Failed to sign message: {}", e)),
        };

        let signer_address = signer.address();
        let signer_creds = signer.credential();
        print!("Signer address: {}\n", signer_address);
        println!("Signer credentials: {:?}", signer_creds.verifying_key());

        let signature_hex = hex::encode(signature.as_bytes());

        Ok(signature_hex)
    }
}
