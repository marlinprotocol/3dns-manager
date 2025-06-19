use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    pub domain: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: String,
}

impl DnsRecord {
    pub fn decode_dns_records(hex_data: &str) -> Result<Vec<DnsRecord>, Box<dyn Error>> {
        let buffer = hex::decode(hex_data)?;
        let mut records = Vec::new();
        let mut offset = 0;

        while offset < buffer.len() {
            // Decode domain name
            let mut domain_parts = Vec::new();
            while buffer[offset] != 0 {
                let length = buffer[offset] as usize;
                offset += 1;

                let label = String::from_utf8(buffer[offset..offset + length].to_vec())?;
                domain_parts.push(label);
                offset += length;
            }
            offset += 1; // Skip null byte

            // Ensure we have enough bytes remaining
            if offset + 10 > buffer.len() {
                return Err("Incomplete DNS record data".into());
            }

            // Read record type (2 bytes)
            let record_type = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
            offset += 2;

            // Read class (2 bytes)
            let class = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
            offset += 2;

            // Read TTL (4 bytes)
            let ttl = u32::from_be_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]);
            offset += 4;

            // Read data length (2 bytes)
            let data_length = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
            offset += 2;

            // Read data
            let data = String::from_utf8(buffer[offset..offset + data_length as usize].to_vec())?;
            offset += data_length as usize;

            let record = DnsRecord {
                domain: domain_parts.join("."),
                record_type,
                class,
                ttl,
                data,
            };
            records.push(record);
        }

        Ok(records)
    }

    pub fn encode_dns_records(records: &[DnsRecord]) -> Result<String, Box<dyn Error>> {
        let mut buffer = Vec::new();

        for record in records {
            // Encode domain name
            for part in record.domain.split('.') {
                buffer.push(part.len() as u8);
                buffer.extend_from_slice(part.as_bytes());
            }
            buffer.push(0); // Null terminator

            // Encode record type (2 bytes)
            buffer.extend_from_slice(&record.record_type.to_be_bytes());

            // Encode class (2 bytes)
            buffer.extend_from_slice(&record.class.to_be_bytes());

            // Encode TTL (4 bytes)
            buffer.extend_from_slice(&record.ttl.to_be_bytes());

            // Encode data according to record type
            if record.record_type == 2 {
                // NS record
                let mut data_buffer = Vec::new();
                // Convert plain hostname (e.g. "archer.ns.cloudflare.com") to DNS format
                for part in record.data.split('.') {
                    data_buffer.push(part.len() as u8);
                    data_buffer.extend_from_slice(part.as_bytes());
                }
                data_buffer.push(0); // Null terminator

                // Write length and data
                buffer.extend_from_slice(&(data_buffer.len() as u16).to_be_bytes());
                buffer.extend_from_slice(&data_buffer);
            } else {
                // For other record types, write data as-is
                buffer.extend_from_slice(&(record.data.len() as u16).to_be_bytes());
                buffer.extend_from_slice(record.data.as_bytes());
            }
        }

        Ok(hex::encode(buffer))
    }
}
