use serde::Serialize;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[derive(thiserror::Error, Debug)]
pub enum SignerError {
    #[error("failed to read: {0}")]
    FileReadFailed(String),
    #[error("failed to parse")]
    ParseFailed(#[from] serde_json::Error),
    #[error("invalid ACME: {0}")]
    ACMEError(String),
    #[error("Invalid ACME data directory {0}")]
    InvalidDataDir(String),
}

#[derive(Serialize)]
pub struct BinderResponse {
    pub acme_id: String,
}
pub struct ACMEManager {
    default_acme: String,
    default_email: String,
    default_user: String,
}

impl ACMEManager {
    pub fn new(acme: String, email: String, user: String) -> Self {
        ACMEManager {
            default_acme: acme,
            default_email: email,
            default_user: user,
        }
    }

    pub fn get_ca_info_path(
        &self,
        acme: &str,
        email: &str,
        user: &str,
    ) -> Result<PathBuf, SignerError> {
        // Assuming Caddy's ACME data is mounted at /data based on docker-compose.yml
        let base_ca_path = "/data/caddy/acme";
        let ca_info_path: PathBuf = [
            base_ca_path,
            acme,
            "users",
            email,
            format!("{}.json", user).as_str(),
        ]
        .iter()
        .collect();

        // temp
        // Print the default.key file path and its contents
        let key_path = [base_ca_path, acme, "users", email, "default.key"]
            .iter()
            .collect::<PathBuf>();
        println!("Default key path: {}", key_path.display());
        match fs::read_to_string(&key_path) {
            Ok(key) => println!("Key contents: {}", key),
            Err(e) => println!("Failed to read key: {}", e),
        };
        // end temp

        if !ca_info_path.starts_with(base_ca_path) {
            return Err(SignerError::InvalidDataDir(
                ca_info_path.into_os_string().into_string().unwrap(),
            ));
        }
        Ok(ca_info_path)
    }

    pub fn get_ca_id(&self, acme: &str, email: &str, user: &str) -> Result<String, SignerError> {
        let ca_info_path = self.get_ca_info_path(acme, email, user)?;
        let ca_info = match fs::read_to_string(&ca_info_path) {
            Ok(ca_info) => ca_info,
            Err(_) => {
                return Err(SignerError::FileReadFailed(
                    ca_info_path.into_os_string().into_string().unwrap(),
                ))
            }
        };
        let ca_info: Value = match serde_json::from_str(&ca_info) {
            Ok(ca_info) => ca_info,
            Err(e) => return Err(SignerError::ParseFailed(e)),
        };

        println!("CA Info: {}", ca_info);

        let status = ca_info["status"]
            .as_str()
            .ok_or_else(|| SignerError::ACMEError("Missing status field".to_string()))?
            .to_string();

        let ca_id = ca_info["location"]
            .as_str()
            .ok_or_else(|| SignerError::ACMEError("Missing location field".to_string()))?
            .to_string();

        if status != "valid" {
            return Err(SignerError::ACMEError(ca_id));
        }

        Ok(ca_id)
    }

    pub fn get_default_caa_record(&self) -> Result<String, SignerError> {
        let acme_id =
            self.get_ca_id(&self.default_acme, &self.default_email, &self.default_user)?;

        // NOTE: Assumes letsencrypt.org is the only CA
        Ok(format!(
            "0 issue \"letsencrypt.org; accounturi={}\"",
            acme_id
        ))
    }

    pub fn get_acme_id_by_acme(&self, acme_dir: &str) -> Result<String, SignerError> {
        let acme_id = self.get_ca_id(acme_dir, &self.default_email, &self.default_user)?;

        // NOTE: Assumes letsencrypt.org is the only CA
        Ok(format!(
            "0 issue \"letsencrypt.org; accounturi={}\"",
            acme_id
        ))
    }

    pub fn get_acme_id_by_all(
        &self,
        acme_dir: &str,
        email: &str,
        user: &str,
    ) -> Result<BinderResponse, SignerError> {
        let acme_id = self.get_ca_id(acme_dir, email, user)?;

        Ok(BinderResponse { acme_id })
    }
}
