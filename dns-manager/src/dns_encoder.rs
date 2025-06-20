use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    InvalidDomain(String),
    InvalidData(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsError::InvalidDomain(msg) => write!(f, "Invalid domain: {}", msg),
            DnsError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
        }
    }
}

impl Error for DnsError {}

pub const TYPE_A: u16 = 1;     // IPv4 address
pub const TYPE_NS: u16 = 2;    // Nameserver
pub const TYPE_CNAME: u16 = 5; // Canonical name
pub const TYPE_MX: u16 = 15;   // Mail exchange
pub const TYPE_TXT: u16 = 16;  // Text
pub const TYPE_AAAA: u16 = 28; // IPv6 address

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    pub domain: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: String,
}

impl DnsRecord {
    fn encode_domain(domain: &str) -> Result<Vec<u8>, DnsError> {
        let mut buffer = Vec::new();
        
        if domain.len() > 255 {
            return Err(DnsError::InvalidDomain("Domain name too long".to_string()));
        }

        for part in domain.split('.') {
            if part.is_empty() {
                return Err(DnsError::InvalidDomain("Empty label".to_string()));
            }
            if part.len() > 63 {
                return Err(DnsError::InvalidDomain("Label too long".to_string()));
            }
            buffer.push(part.len() as u8);
            buffer.extend_from_slice(part.as_bytes());
        }
        buffer.push(0); // Null terminator
        Ok(buffer)
    }

    fn encode_data(&self) -> Result<Vec<u8>, DnsError> {
        let mut data_buffer = Vec::new();

        match self.record_type {
            TYPE_A => {
                // Validate and encode IPv4 address
                let octets: Vec<&str> = self.data.split('.').collect();
                if octets.len() != 4 {
                    return Err(DnsError::InvalidData("Invalid IPv4 address".to_string()));
                }
                for octet in octets {
                    match octet.parse::<u8>() {
                        Ok(num) => data_buffer.push(num),
                        Err(_) => return Err(DnsError::InvalidData("Invalid IPv4 octet".to_string())),
                    }
                }
            },
            TYPE_AAAA => {
                // Validate and encode IPv6 address
                for segment in self.data.split(':') {
                    if segment.len() > 4 {
                        return Err(DnsError::InvalidData("Invalid IPv6 segment".to_string()));
                    }
                    match u16::from_str_radix(segment, 16) {
                        Ok(num) => data_buffer.extend_from_slice(&num.to_be_bytes()),
                        Err(_) => return Err(DnsError::InvalidData("Invalid IPv6 segment".to_string())),
                    }
                }
            },
            TYPE_NS | TYPE_CNAME => {
                // Encode domain name format
                data_buffer.extend(Self::encode_domain(&self.data)?);
            },
            TYPE_MX => {
                // Format: 2 bytes preference, then domain name
                let parts: Vec<&str> = self.data.split(' ').collect();
                if parts.len() != 2 {
                    return Err(DnsError::InvalidData("MX record must have preference and domain".to_string()));
                }
                let preference = parts[0].parse::<u16>()
                    .map_err(|_| DnsError::InvalidData("Invalid MX preference".to_string()))?;
                data_buffer.extend_from_slice(&preference.to_be_bytes());
                data_buffer.extend(Self::encode_domain(parts[1])?);
            },
            TYPE_TXT => {
                if self.data.len() > 255 {
                    return Err(DnsError::InvalidData("TXT record too long".to_string()));
                }
                data_buffer.push(self.data.len() as u8);
                data_buffer.extend_from_slice(self.data.as_bytes());
            },
            _ => {
                // For unknown types, encode data as-is
                data_buffer.extend_from_slice(self.data.as_bytes());
            }
        }

        Ok(data_buffer)
    }

    pub fn encode_dns_records(records: &[DnsRecord]) -> Result<String, Box<dyn Error>> {
        let mut buffer = Vec::new();

        for record in records {
            // Encode domain name
            buffer.extend(Self::encode_domain(&record.domain)?);

            // Encode record type (2 bytes)
            buffer.extend_from_slice(&record.record_type.to_be_bytes());

            // Encode class (2 bytes)
            buffer.extend_from_slice(&record.class.to_be_bytes());

            // Encode TTL (4 bytes)
            buffer.extend_from_slice(&record.ttl.to_be_bytes());

            // Encode record data
            let data_buffer = record.encode_data()?;
            buffer.extend_from_slice(&(data_buffer.len() as u16).to_be_bytes());
            buffer.extend_from_slice(&data_buffer);
        }

        Ok(hex::encode(buffer))
    }
}
