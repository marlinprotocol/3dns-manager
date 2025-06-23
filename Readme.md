# Oyster Frontend Manager

This project provides tools to manage frontend deployments using Oyster CVM and DNS management capabilities.

## Prerequisites

- Rust (latest stable version)
- Docker
- Access to the Optimism network
- Wallet with sufficient funds for contract deployment
- Domain name to manage
- Oyster CVM CLI tool (v4.0.0) installed

## Project Structure

```
oyster-fe-manager/
├── dns-client/        # Rust client for DNS record management
├── dns-manager/       # Rust manager to run inside the enclave      
├── caddy.json         # Caddy server configuration
└── Readme.md          # This file
```

## Setup

1. **Clone the repository:**
    ```bash
    git clone https://github.com/marlinprotocol/3dns-manager
    cd 3dns-manager
    ```

2. **Build the DNS client:**
    ```bash
    cd dns-client
    cargo build --release
    ```

3. **Make dns-client globally available:**
    Copy the built dns-client from the release folder to `/usr/local/bin/` and give it execute permission.

    ```bash
    sudo cp target/release/dns-client /usr/local/bin/
    sudo chmod +x /usr/local/bin/dns-client
    ```

## Deploying Frontends on Oyster with Domains

1. **Buy a domain at [3dns](https://3dns.box/).**
2. **Transfer the domain to the domain manager:**
    ```bash
    dns-client transfer-domain --domain letsgoo.tech --new-owner-wallet-address <DOMAIN_MANAGER_ADDRESS> --wallet-private-key *****
    ```
3. **Set WHOIS delegate:**
    ```bash
    dns-client set-whois --domain letsgoo.tech --delegate-wallet-address <DOMAIN_MANAGER_ADDRESS> --wallet-private-key *****
    ```
4. **Deploy KMS verifier contract:**
    ```bash
    oyster-cvm kms-contract deploy --wallet-private-key ****
    ```
5. **Compute the image ID:**

    #### Debug : 
    ```bash
    oyster-cvm compute-image-id \
      --contract-address 0x166EeA146F559FC842D37C5899632eef8B7FB458 \
      --chain-id 42161 \
      --docker-compose docker-compose.yml \
      --arch amd64 \
      --preset debug
    ```
    `Note` : Running in debug mode might expose sensitive data.

    #### Production :
    ```bash
    oyster-cvm compute-image-id \
      --contract-address 0x166EeA146F559FC842D37C5899632eef8B7FB458 \
      --chain-id 42161 \
      --docker-compose docker-compose.yml \
      --arch amd64 \
    ```

6. **Approve the image ID in the contract:**
    ```bash
    oyster-cvm kms-contract approve \
      --wallet-private-key <key> \
      --image-id <image_id> \
      --contract-address <address>
    ```
7. **Compute the domain ID:**
    ```bash
    dns-client compute-domain-id --domain letsgoo.tech
    ```
8. **Get the proof signature:**
    ```bash
    curl --location 'arbone-v4.kms.box:1101/derive/secp256k1/address/ethereum?address=<address>&path=DNS-RECORD-SIGNER-<domain-id>'
    ```
    **Note:**
    - Note down the `kms-signer-address` from the response body.
    - Note down the `x-marlin-kms-signature` from the response header.
9. **Set the KMS keys:**
    ```bash
    dns-client set-kms-key \
      --domain letsgoo.tech \
      --kms-signer-address <KMS_SIGNER_ADDRESS> \
      --proof <KMS_SIGNATURE> \
      --wallet-private-key ******
    ```
10. **Build and push Docker images:**
    - Build and push your website image:
      ```bash
      docker build -t <your_dockerhub_username>/oyster-fe-kit:latest .
      docker push <your_dockerhub_username>/oyster-fe-kit:latest
      ```
    - Build and push the DNS manager image:
      ```bash
      cd dns-manager
      docker build -t <your_dockerhub_username>/dns-manager:latest .
      docker push <your_dockerhub_username>/dns-manager:latest
      ```
11. **Modify configuration files:**
    - In `caddy.json`, set:
      ```json
      "host": ["<YOUR_DOMAIN_NAME>"]
      ```
    - In `docker-compose.yml`, update:
      ```yaml
      services:
        caddy:
          image: <DOCKERHUB_USERNAME>/oyster-fe-kit:latest
          network_mode: host
          volumes:
            - caddy_data:/data
            - caddy_config:/config

        dns-manager:
          image: <DOCKERHUB_USERNAME>/dns-manager:latest
          network_mode: host
          environment:
            - DOMAIN_NAME=<DOMAIN_NAME>
            - DOMAIN_ID=<DOMAIN_ID>
          volumes:
            - caddy_data:/data

      volumes:
        caddy_data:
        caddy_config:
      ```
12. **Deploy the entire setup with Oyster CVM:**

    #### Debug:

    ```bash
    oyster-cvm deploy \
      --duration-in-minutes 180 \
      --docker-compose ./docker-compose.yml \
      --wallet-private-key *** \
      --debug \
      --arch amd64 \
      --instance-type c5n.xlarge \
      --contract-address <KMS_VERIFIER_CONTRACT> \
      --chain-id 42161 \
      --region us-west-2 \
      --preset debug \
      --image-url https://artifacts.marlin.org/oyster/eifs/base-blue_v3.0.0_linux_amd64.eif
    ```

    `Note` : Running in debug mode might expose sensitive data.

    #### Production:

    ```bash
      oyster-cvm deploy \
      --duration-in-minutes 180 \
      --docker-compose ./docker-compose.yml \
      --wallet-private-key *** \
      --arch amd64 \
      --instance-type c5n.xlarge \
      --contract-address <KMS_VERIFIER_CONTRACT> \
      --chain-id 42161 \
      --region us-west-2
    ```

    **Note:** Note down the IP address returned by the Oyster CVM CLI. You will need this in the next step.

    **Note:** Make sure the computed image ID returned by this command matches the computed image ID from Step 5.
    
13. **Set DNS records with the DNS client:**
    ```bash
    dns-client set-dns --domain letsgoo.tech --enclave-ip <ENCLAVE_IP> --wallet-private-key ****
    ```
14. **Wait for DNS propagation:**
    It may take a few minutes for DNS propagation. Once complete, your site should be available at your domain.

## Important Notes

- Ensure your wallet has admin permissions on the contract before setting DNS records.
- The enclave IP should be accessible from your machine.
- Keep your private keys secure and never share them.
- Always verify DNS propagation after making changes.

## Troubleshooting

- If you get "AccessControl" errors, ensure your wallet has admin permissions.
- If DNS records are not updating, check:
  - Contract transaction status
  - DNS propagation time (can take up to 24 hours)
  - Enclave connectivity

## Future Work

- Subdomain management
- Add mechanisms for delays between setting CAA and A records to avoid race conditions in record propagation
  - Race condition possible between propagation of CAA and A records as records are propagated individually, so not a good idea to set them together.
  - A record should only be set after setting CAA record to ensure security.
- TTL for records should be configurable
- Expand support to ACME services apart from Let's Encrypt