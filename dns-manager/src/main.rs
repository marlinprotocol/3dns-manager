use eyre::Result;
use ip_checker::get_public_ip;
use std::{env, time::Duration};
use tokio;
use dotenv;
use warp::{self, Filter, http::Response};
use std::sync::Arc;

mod acme_manager;
use acme_manager::ACMEManager;
mod dns_encoder;
mod ip_checker;
mod signer;
use signer::Signer;

#[derive(serde::Deserialize)]
struct TtlParam {
    ttl: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    // Get configuration from environment variables
    let port = env::var("PORT").unwrap_or_else(|_| "8004".to_string()).parse::<u16>()
        .expect("PORT must be a valid port number");
    let acme = env::var("ACME").unwrap_or_else(|_| "acme-v02.api.letsencrypt.org-directory".to_string());

    println!("Starting DNS Manager server on port {}...", port);

    // Initialize the signer
    let mut signer = Signer::new();
    match signer.init().await {
        Ok(_) => println!("Signer initialized successfully"),
        Err(e) => eprintln!("Failed to initialize signer: {}", e),
    }
    let signer = Arc::new(signer);

    // Share signer with routes
    let signer_filter = warp::any().map(move || signer.clone());

    // GET /a-record
    let a_record_route = warp::path("a-record")
        .and(warp::get())
        .and(warp::query::<TtlParam>())
        .and(signer_filter.clone())
        .and_then(get_encoded_a_record);

    // Create a filter for sharing acme
    let acme_filter = warp::any().map(move || acme.clone());

    // GET /caa-record
    let caa_record_route = warp::path("caa-record")
        .and(warp::get())
        .and(warp::query::<TtlParam>())
        .and(acme_filter)
        .and(signer_filter.clone())
        .and_then(get_encoded_ca_record);   

    // Combine routes
    let routes = a_record_route.or(caa_record_route);

    // Start the server
    let server = warp::serve(routes).run(([0, 0, 0, 0], port));
    
    // Run server
    server.await;

    Ok(())
}

/// Generate and encode A record
async fn get_encoded_a_record(ttl_param: TtlParam, signer: Arc<Signer> ) -> Result<impl warp::Reply, warp::Rejection> {
    let ttl = ttl_param.ttl.unwrap_or(3600);
    match generate_encoded_a_record(signer, ttl).await {
        Ok(encoded) => Ok(Response::builder().body(encoded)),
        Err(e) => Ok(Response::builder().status(500).body(format!("Error: {}", e))),
    }
}

/// Generate and encode CAA record
async fn get_encoded_ca_record(ttl_param: TtlParam, acme: String, signer: Arc<Signer>) -> Result<impl warp::Reply, warp::Rejection> {
    let ttl = ttl_param.ttl.unwrap_or(3600);
    match generate_encoded_caa_record(&acme, signer, ttl).await {
        Ok(encoded) => Ok(Response::builder().body(encoded)),
        Err(e) => Ok(Response::builder().status(500).body(format!("Error: {}", e))),
    }
}

/// Generate encoded A record
async fn generate_encoded_a_record(signer: Arc<Signer>, ttl: u32) -> Result<String> {
    println!("Fetching public IP...");
    let ip = get_public_ip().await;
    println!("Current Public IP: {}", ip);

    let domain = env::var("DOMAIN_NAME").expect("DOMAIN_NAME must be set");

    // Generate A record
    let a_record = dns_encoder::DnsRecord {
        domain: domain.clone(),
        record_type: 1, // A record type
        class: 1,
        ttl: ttl, // Example TTL
        data: ip, // Use the fetched public IP
    };

    // Encode the record
    let dns_records = vec![a_record];
    let encoded_records = dns_encoder::DnsRecord::encode_dns_records(&dns_records)
        .map_err(|e| eyre::eyre!("Failed to encode A record: {}", e))?;
    println!("Encoded A record: {}", encoded_records);

    // Sign the encoded records
    let signature = signer.sign_message(&encoded_records)
        .map_err(|e| eyre::eyre!("Failed to sign A record: {}", e))?;
    
    // Return signed response (base encoded record + signature appended)
    Ok(format!("{}:{}", encoded_records, signature))
}

/// Generate encoded CAA record
async fn generate_encoded_caa_record(acme: &str, signer: Arc<Signer>, ttl: u32) -> Result<String> {
    println!("Generating CAA record...");
    let domain = env::var("DOMAIN_NAME").expect("DOMAIN_NAME must be set");

    // Create a new Signer instance
    let acme_manager = ACMEManager::new(
        acme.to_string(),
        "default".to_string(),
        "default".to_string()
    );

    // Retry configuration
    let max_retries = 50;
    let retry_delay = Duration::from_secs(2);
    let mut caa_record_data = String::new();

    // Get CAA record data (fetch ACME ID/details) with retries
    println!("Fetching CAA record data...");
    let mut attempt = 0;
    loop {
        attempt += 1;
        match acme_manager.get_default_caa_record() {
            Ok(response) => {
                caa_record_data = response;
                println!("CAA Record Data: {}", caa_record_data);
                break;
            },
            Err(err) => {
                if attempt >= max_retries {
                    return Err(eyre::eyre!("Failed to get CAA record data after {} attempts: {:?}", max_retries, err));
                }
                eprintln!("Attempt {}/{}: Error fetching CAA data: {:?}",
                    attempt, max_retries, err);
                eprintln!("Retrying in {} seconds...", retry_delay.as_secs());
                tokio::time::sleep(retry_delay).await;
            }
        }
    }

    // Generate CAA record
    let caa_record = dns_encoder::DnsRecord {
        domain: domain.clone(),
        record_type: 257, // CAA record type
        class: 1,
        ttl: ttl,
        data: caa_record_data,
    };

    // Encode the record
    let dns_records = vec![caa_record];
    let encoded_records = dns_encoder::DnsRecord::encode_dns_records(&dns_records)
        .map_err(|e| eyre::eyre!("Failed to encode CAA record: {}", e))?;
    println!("Encoded CAA record: {}", encoded_records);

    // Sign the encoded records
    let signature = signer.sign_message(&encoded_records)
        .map_err(|e| eyre::eyre!("Failed to sign CAA record: {}", e))?;
    
    // Return signed response (base encoded record + signature appended)
    Ok(format!("{}:{}", encoded_records, signature))
}
