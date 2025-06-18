use reqwest::Client;
use std::time::Duration;

/// Gets the public IP address of the current machine by trying multiple services
/// Returns the IP as a String or an error message if all attempts fail
pub async fn get_public_ip() -> String {
    let client = Client::new();
    let timeout = Duration::from_secs(2);

    // Try ipify.org
    if let Ok(ip) = get_ip_from_url(&client, "https://api64.ipify.org", timeout).await {
        return ip;
    }

    // Try AWS checkip
    if let Ok(ip) = get_ip_from_url(&client, "https://checkip.amazonaws.com", timeout).await {
        return ip.trim().to_string(); // AWS adds a newline
    }

    // Try Cloudflare
    if let Ok(trace) = get_ip_from_url(&client, "https://1.1.1.1/cdn-cgi/trace", timeout).await {
        for line in trace.lines() {
            if line.starts_with("ip=") {
                return line.trim_start_matches("ip=").to_string();
            }
        }
    }

    // All attempts failed
    "?: unable to determine".to_string()
}

/// Helper function to get IP from a specified URL
async fn get_ip_from_url(
    client: &Client,
    url: &str,
    timeout: Duration,
) -> Result<String, reqwest::Error> {
    client
        .get(url)
        .timeout(timeout)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}
