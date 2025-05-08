use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;

pub struct Signer {
    key: Option<SigningKey>,
}

impl Signer {
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

        self.key = Some(
            SigningKey::from_bytes(&key_bytes.into())
                .context("Failed to create signing key")?,
        );

        Ok(())
    }

    pub fn sign_message(&self, message: &str) -> Result<String> {
        let key = self.key.as_ref().context("Signer not initialized")?;

        let signature = key
            .sign_recoverable(message.as_bytes())
            .context("Failed to sign message")?;

        let signature_bytes =
            hex::encode(signature.0.to_bytes()) + &hex::encode(&[signature.1.to_byte() + 27]);
        
        Ok(signature_bytes)
    }
}
