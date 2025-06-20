use alloy::primitives::{keccak256, B256};
use dotenv;
use eyre::Result;
use ip_checker::get_public_ip;
use std::sync::Arc;
use std::{env, time::Duration};
use tokio;
use warp::{self, http::Response, Filter};

mod acme_manager;
use acme_manager::ACMEManager;
mod dns_encoder;
mod ip_checker;
mod message_signer;
use message_signer::MessageSigner;

use crate::dns_encoder::{TYPE_A, TYPE_CAA};

#[derive(serde::Deserialize)]
struct TtlParam {
    ttl: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    // Get configuration from environment variables
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8004".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");
    let acme_env =
        env::var("ACME").unwrap_or_else(|_| "acme-v02.api.letsencrypt.org-directory".to_string());
    let acme_services: Vec<String> = acme_env.split(',').map(|s| s.trim().to_string()).collect();
    println!("ACME services: {:?}", acme_services);

    println!("Yo, Starting DNS Manager server on port {}...", port);

    // Initialize the signer
    let mut signer = message_signer::MessageSigner::new();
    match signer.init().await {
        Ok(_) => println!("Signer initialized successfully"),
        Err(e) => eprintln!("Failed to initialize signer: {}", e),
    }
    let signer = Arc::new(signer);

    // Share signer with routes
    let signer_filter = warp::any().map(move || signer.clone());

    let acme_services_for_dns = acme_services.clone();
    // GET /dns-records
    let dns_records_route = warp::path("dns-records")
        .and(warp::get())
        .and(warp::query::<TtlParam>())
        .and(signer_filter.clone())
        .and_then(move |ttl_param: TtlParam, signer: Arc<MessageSigner>| {
            let acme_services = acme_services_for_dns.clone();
            async move { get_encoded_dns_records(acme_services, ttl_param, signer).await }
        });

    let acme_services_for_caa = acme_services.clone();
    // GET /caa-records
    let caa_record_route = warp::path("caa-records")
        .and(warp::get())
        .and(warp::query::<TtlParam>())
        .and(signer_filter.clone())
        .and_then(move |ttl_param: TtlParam, signer: Arc<MessageSigner>| {
            let acme_services = acme_services_for_caa.clone();
            async move { get_encoded_caa_records(acme_services, ttl_param, signer).await }
        });

    // Combine routes
    let routes = dns_records_route.or(caa_record_route);

    // Start the server
    let server = warp::serve(routes).run(([0, 0, 0, 0], port));
    println!("Server started");
    // Run server
    server.await;

    Ok(())
}

/// Generate and encode DNS records
async fn get_encoded_dns_records(
    acme_services: Vec<String>,
    ttl_param: TtlParam,
    signer: Arc<MessageSigner>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ttl = ttl_param.ttl.unwrap_or(3600);
    match generate_encoded_dns_records(acme_services, ttl, signer).await {
        Ok(encoded) => Ok(Response::builder().body(encoded)),
        Err(e) => Ok(Response::builder()
            .status(500)
            .body(format!("Error: {}", e))),
    }
}

/// Generate and encode CAA records for all ACME services together
async fn get_encoded_caa_records(
    acme_services: Vec<String>,
    ttl_param: TtlParam,
    signer: Arc<MessageSigner>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ttl = ttl_param.ttl.unwrap_or(3600);
    match generate_encoded_caa_records(acme_services, ttl, signer).await {
        Ok(encoded) => Ok(Response::builder().body(encoded)),
        Err(e) => Ok(Response::builder()
            .status(500)
            .body(format!("Error: {}", e))),
    }
}

fn get_caa_record_data(acme: &str) -> Result<String> {
    let acme_manager = ACMEManager::new(
        acme.to_string(),
        "default".to_string(),
        "default".to_string(),
    );
    let max_retries = 50;
    let retry_delay = Duration::from_secs(2);
    let mut attempt = 0;
    loop {
        attempt += 1;
        match acme_manager.get_acme_id_by_acme(acme) {
            Ok(response) => return Ok(response),
            Err(err) => {
                if attempt >= max_retries {
                    return Err(eyre::eyre!(
                        "Failed to get CAA record data for {} after {} attempts: {:?}",
                        acme,
                        max_retries,
                        err
                    ));
                }
                eprintln!(
                    "Attempt {}/{}: Error fetching CAA data for {}: {:?}",
                    attempt, max_retries, acme, err
                );
                eprintln!("Retrying in {} seconds...", retry_delay.as_secs());
                std::thread::sleep(retry_delay);
            }
        }
    }
}

/// Generate all CAA records for all ACME services (returns Vec<DnsRecord>)
async fn generate_caa_records(
    acme_services: Vec<String>,
    ttl: u32,
    domain: &str,
) -> Result<Vec<dns_encoder::DnsRecord>> {
    let mut caa_records = Vec::new();
    for acme in acme_services {
        let caa_record_data = tokio::task::spawn_blocking(move || get_caa_record_data(&acme))
            .await
            .unwrap()?;
        println!("CAA record data raw :  {}", caa_record_data);
        let caa_record = dns_encoder::DnsRecord {
            domain: domain.to_string(),
            record_type: TYPE_CAA, // CAA record type
            class: 1,
            ttl: ttl,
            data: caa_record_data, // CAA record data
        };
        println!("CAA record: {:?}", caa_record);
        caa_records.push(caa_record);
    }
    Ok(caa_records)
}

/// Generate and encode all CAA records together for all ACME services
async fn generate_encoded_caa_records(
    acme_services: Vec<String>,
    ttl: u32,
    signer: Arc<MessageSigner>,
) -> Result<String> {
    let domain = env::var("DOMAIN_NAME").expect("DOMAIN_NAME must be set");
    let caa_records = generate_caa_records(acme_services, ttl, &domain).await?;

    // Encode all CAA records together
    let encoded_records = dns_encoder::DnsRecord::encode_dns_records(&caa_records)
        .map_err(|e| eyre::eyre!("Failed to encode CAA records: {}", e))?;

    // Sign the combined encoded records
    let signature = signer
        .sign_message(&encoded_records, &domain)
        .await
        .map_err(|e| eyre::eyre!("Failed to sign CAA records: {}", e))?;

    Ok(format!("{}:{}", encoded_records, signature))
}

/// Generate encoded DNS records
async fn generate_encoded_dns_records(
    acme_services: Vec<String>,
    ttl: u32,
    signer: Arc<MessageSigner>,
) -> Result<String> {
    println!("Fetching public IP...");
    let ip = get_public_ip().await;
    println!("Current Public IP: {}", ip);

    let domain = env::var("DOMAIN_NAME").expect("DOMAIN_NAME must be set");

    // Generate A record
    let a_record = dns_encoder::DnsRecord {
        domain: domain.clone(),
        record_type: TYPE_A, // A record type
        class: 1,
        ttl: ttl, // Example TTL
        data: ip, // Use the fetched public IP
    };

    // Encode the record
    let mut dns_records = vec![a_record];

    // Generate CAA records
    let caa_records = generate_caa_records(acme_services, ttl, &domain).await?;
    dns_records.extend(caa_records);

    println!("Generated DNS records: {:?}", dns_records);

    let encoded_records = dns_encoder::DnsRecord::encode_dns_records(&dns_records)
        .map_err(|e| eyre::eyre!("Failed to encode DNS record: {}", e))?;
    println!("Encoded DNS record: {}", encoded_records);

    // Sign the encoded records
    let signature = signer
        .sign_message(&encoded_records, &domain)
        .await
        .map_err(|e| eyre::eyre!("Failed to sign DNS records: {}", e))?;

    println!("Signature: {}", signature);

    // Return signed response (base encoded record + signature appended)
    Ok(format!("{}:{}", encoded_records, signature))
}

fn namehash(domain: &str) -> B256 {
    let mut node = B256::ZERO;
    if domain.is_empty() {
        return node;
    }

    let labels: Vec<&str> = domain.split('.').rev().collect();

    for label in labels {
        let label_hash = keccak256(label.as_bytes());

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(node.as_slice());
        combined[32..].copy_from_slice(label_hash.as_slice());

        node = keccak256(&combined);
    }

    node
}
