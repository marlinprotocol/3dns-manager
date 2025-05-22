# Oyster Frontend Manager

This project provides tools to manage frontend deployments using Oyster CVM and DNS management capabilities.

## Prerequisites

- Rust (latest stable version)
- Docker
- Access to Optimism network
- Wallet with sufficient funds for contract deployment
- Domain name you want to manage
- Oyster CVM CLI tool installed

## Project Structure

```
oyster-fe-manager/
├── dns-client/        # Rust client for DNS record management
├── dns-manager/        # Rust manager to run inside the enclave      
├── caddy.json         # Caddy server configuration
└── README.md          # This file
```

## Setup

1. Clone the repository:
```bash
git clone https://github.com/marlinprotocol/3dns-manager
cd 3dns-manager
```

2. Build the DNS client:
```bash
cd dns-client
cargo build --release
```

## Deploying DNS Manager using Oyster CVM

1. Deploy the DNS manager to AWS using Oyster CVM:
```bash
oyster-cvm deploy \
  --duration-in-minutes 20 \
  --docker-compose ./docker-compose.yml \
  --wallet-private-key <your-private-key> \
  --debug \
  --arch amd64 \
  --instance-type c5n.xlarge \
  --region us-west-2
```

Key parameters explained:
- `duration-in-minutes`: How long the instance should run
- `docker-compose.yml`: Configuration file for the services
- `arch`: CPU architecture (amd64 for most AWS instances)
- `instance-type`: AWS EC2 instance type
- `region`: AWS region for deployment

2. After deployment, note down the enclave IP address from the deployment output. You'll need this for setting DNS records.


## Managing DNS Records

The DNS client supports two main operations:
- Setting DNS records (A and CAA records)
- Setting WHOIS delegation

### Setting DNS Records

Use the following command to set DNS records:

```bash
dns-client set-dns \
  --enclave-ip <enclave-ip> \
  --wallet-private-key <your-private-key> \
  --contract-address <contract-address> \
  --domain <your-domain> \
  --a-ttl <your-desired-ttl-value-for-A-record> \
  --caa-ttl <your-desired-ttl-value-for-CAA-record> 
```
Note: a-ttl and caa-ttl are optional params. They default to 3600 seconds (1 hour) for both A record and CAA record.

### Setting WHOIS Delegation

To delegate WHOIS management to another wallet:

```bash
dns-client set-whois \
  --domain <your-domain> \
  --delegate-wallet-address <delegate-address> \
  --contract-address <contract-address> \
  --wallet-private-key <your-private-key>
```

## Important Notes

1. Make sure your wallet has admin permissions on the contract before setting DNS records
2. The enclave IP should be accessible from your machine
3. Keep your private keys secure and never share them
4. Always verify DNS propagation after making changes

## Troubleshooting

1. If you get "AccessControl" errors, ensure your wallet has admin permissions
2. If DNS records are not updating, check:
   - Contract transaction status
   - DNS propagation time (can take up to 24 hours)
   - Enclave connectivity

