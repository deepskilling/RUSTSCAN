/// OS Fingerprint Database
/// 
/// This module contains OS signatures and database management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use super::tcp_fingerprint::{IpIdPattern, RstBehavior, TcpOption};
use super::icmp_fingerprint::{IcmpTimestampBehavior, RateLimitPattern};

/// OS signature for matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsSignature {
    pub os_name: String,
    pub os_version: Option<String>,
    pub os_family: OsFamily,
    pub tcp_signature: Option<TcpSignature>,
    pub icmp_signature: Option<IcmpSignature>,
    pub confidence_weight: f64,
}

/// OS family classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsFamily {
    Linux,
    Windows,
    MacOS,
    BSD,
    Unix,
    Cisco,
    Embedded,
    Unknown,
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsFamily::Linux => write!(f, "Linux"),
            OsFamily::Windows => write!(f, "Windows"),
            OsFamily::MacOS => write!(f, "macOS"),
            OsFamily::BSD => write!(f, "BSD"),
            OsFamily::Unix => write!(f, "Unix"),
            OsFamily::Cisco => write!(f, "Cisco"),
            OsFamily::Embedded => write!(f, "Embedded"),
            OsFamily::Unknown => write!(f, "Unknown"),
        }
    }
}

/// TCP signature patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSignature {
    pub ttl_range: (u8, u8),
    pub window_size_range: (u16, u16),
    pub typical_mss: Option<u16>,
    pub tcp_options_pattern: Vec<TcpOption>,
    pub df_flag: bool,
    pub rst_behavior: RstBehavior,
    pub ip_id_pattern: IpIdPattern,
    pub ecn_support: bool,
}

/// ICMP signature patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpSignature {
    pub ttl_range: (u8, u8),
    pub echoes_payload: bool,
    pub timestamp_behavior: IcmpTimestampBehavior,
    pub rate_limit_pattern: RateLimitPattern,
    pub unreachable_data_length: usize,
}

/// OS fingerprint database
#[derive(Debug, Clone)]
pub struct OsFingerprintDatabase {
    signatures: HashMap<String, OsSignature>,
}

impl OsFingerprintDatabase {
    /// Create a new database with built-in signatures
    pub fn new() -> Self {
        info!("Initializing OS fingerprint database");
        
        let mut db = Self {
            signatures: HashMap::new(),
        };
        
        db.load_builtin_signatures();
        
        info!("Loaded {} OS signatures", db.signatures.len());
        db
    }

    /// Create an empty database without built-in signatures
    pub fn empty() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Load built-in OS signatures
    fn load_builtin_signatures(&mut self) {
        // Linux signatures
        self.add_signature(OsSignature {
            os_name: "Linux 2.6+".to_string(),
            os_version: Some("2.6.x - 5.x".to_string()),
            os_family: OsFamily::Linux,
            tcp_signature: Some(TcpSignature {
                ttl_range: (64, 64),
                window_size_range: (29200, 29200),
                typical_mss: Some(1460),
                tcp_options_pattern: vec![
                    TcpOption::Mss,
                    TcpOption::SackPermitted,
                    TcpOption::Timestamp,
                    TcpOption::Nop,
                    TcpOption::WindowScale,
                ],
                df_flag: true,
                rst_behavior: RstBehavior::Immediate,
                ip_id_pattern: IpIdPattern::Incremental,
                ecn_support: false,
            }),
            icmp_signature: Some(IcmpSignature {
                ttl_range: (64, 64),
                echoes_payload: true,
                timestamp_behavior: IcmpTimestampBehavior::NoResponse,
                rate_limit_pattern: RateLimitPattern::FixedRate,
                unreachable_data_length: 8,
            }),
            confidence_weight: 1.0,
        });

        // Windows 10/11
        self.add_signature(OsSignature {
            os_name: "Windows 10/11".to_string(),
            os_version: Some("10.0+".to_string()),
            os_family: OsFamily::Windows,
            tcp_signature: Some(TcpSignature {
                ttl_range: (128, 128),
                window_size_range: (8192, 65535),
                typical_mss: Some(1460),
                tcp_options_pattern: vec![
                    TcpOption::Mss,
                    TcpOption::Nop,
                    TcpOption::WindowScale,
                    TcpOption::Nop,
                    TcpOption::Nop,
                    TcpOption::SackPermitted,
                ],
                df_flag: true,
                rst_behavior: RstBehavior::Immediate,
                ip_id_pattern: IpIdPattern::Incremental,
                ecn_support: false,
            }),
            icmp_signature: Some(IcmpSignature {
                ttl_range: (128, 128),
                echoes_payload: true,
                timestamp_behavior: IcmpTimestampBehavior::NoResponse,
                rate_limit_pattern: RateLimitPattern::BurstThrottle,
                unreachable_data_length: 8,
            }),
            confidence_weight: 1.0,
        });

        // macOS
        self.add_signature(OsSignature {
            os_name: "macOS".to_string(),
            os_version: Some("10.x - 13.x".to_string()),
            os_family: OsFamily::MacOS,
            tcp_signature: Some(TcpSignature {
                ttl_range: (64, 64),
                window_size_range: (65535, 65535),
                typical_mss: Some(1460),
                tcp_options_pattern: vec![
                    TcpOption::Mss,
                    TcpOption::Nop,
                    TcpOption::WindowScale,
                    TcpOption::Nop,
                    TcpOption::Nop,
                    TcpOption::Timestamp,
                    TcpOption::SackPermitted,
                    TcpOption::EndOfOptions,
                ],
                df_flag: true,
                rst_behavior: RstBehavior::Immediate,
                ip_id_pattern: IpIdPattern::Random,
                ecn_support: false,
            }),
            icmp_signature: Some(IcmpSignature {
                ttl_range: (64, 64),
                echoes_payload: true,
                timestamp_behavior: IcmpTimestampBehavior::NoResponse,
                rate_limit_pattern: RateLimitPattern::Adaptive,
                unreachable_data_length: 8,
            }),
            confidence_weight: 1.0,
        });

        // FreeBSD
        self.add_signature(OsSignature {
            os_name: "FreeBSD".to_string(),
            os_version: Some("11.x - 13.x".to_string()),
            os_family: OsFamily::BSD,
            tcp_signature: Some(TcpSignature {
                ttl_range: (64, 64),
                window_size_range: (65535, 65535),
                typical_mss: Some(1460),
                tcp_options_pattern: vec![
                    TcpOption::Mss,
                    TcpOption::Nop,
                    TcpOption::WindowScale,
                    TcpOption::SackPermitted,
                    TcpOption::Timestamp,
                ],
                df_flag: true,
                rst_behavior: RstBehavior::Immediate,
                ip_id_pattern: IpIdPattern::Random,
                ecn_support: false,
            }),
            icmp_signature: Some(IcmpSignature {
                ttl_range: (64, 64),
                echoes_payload: true,
                timestamp_behavior: IcmpTimestampBehavior::Responds,
                rate_limit_pattern: RateLimitPattern::None,
                unreachable_data_length: 8,
            }),
            confidence_weight: 1.0,
        });

        // Cisco IOS
        self.add_signature(OsSignature {
            os_name: "Cisco IOS".to_string(),
            os_version: None,
            os_family: OsFamily::Cisco,
            tcp_signature: Some(TcpSignature {
                ttl_range: (255, 255),
                window_size_range: (4128, 4128),
                typical_mss: Some(1460),
                tcp_options_pattern: vec![TcpOption::Mss],
                df_flag: false,
                rst_behavior: RstBehavior::None,
                ip_id_pattern: IpIdPattern::Zero,
                ecn_support: false,
            }),
            icmp_signature: Some(IcmpSignature {
                ttl_range: (255, 255),
                echoes_payload: false,
                timestamp_behavior: IcmpTimestampBehavior::NoResponse,
                rate_limit_pattern: RateLimitPattern::FixedRate,
                unreachable_data_length: 0,
            }),
            confidence_weight: 1.0,
        });

        // Embedded Linux
        self.add_signature(OsSignature {
            os_name: "Embedded Linux".to_string(),
            os_version: Some("BusyBox/OpenWrt".to_string()),
            os_family: OsFamily::Embedded,
            tcp_signature: Some(TcpSignature {
                ttl_range: (64, 64),
                window_size_range: (5840, 5840),
                typical_mss: Some(1460),
                tcp_options_pattern: vec![
                    TcpOption::Mss,
                    TcpOption::SackPermitted,
                    TcpOption::WindowScale,
                ],
                df_flag: true,
                rst_behavior: RstBehavior::Immediate,
                ip_id_pattern: IpIdPattern::Incremental,
                ecn_support: false,
            }),
            icmp_signature: Some(IcmpSignature {
                ttl_range: (64, 64),
                echoes_payload: true,
                timestamp_behavior: IcmpTimestampBehavior::NoResponse,
                rate_limit_pattern: RateLimitPattern::None,
                unreachable_data_length: 8,
            }),
            confidence_weight: 0.8,
        });
    }

    /// Add a signature to the database
    pub fn add_signature(&mut self, signature: OsSignature) {
        let key = signature.os_name.clone();
        self.signatures.insert(key, signature);
    }

    /// Get all signatures
    pub fn signatures(&self) -> &HashMap<String, OsSignature> {
        &self.signatures
    }

    /// Get signature by OS name
    pub fn get_signature(&self, os_name: &str) -> Option<&OsSignature> {
        self.signatures.get(os_name)
    }

    /// Get number of signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Get signatures by OS family
    pub fn get_signatures_by_family(&self, family: OsFamily) -> Vec<&OsSignature> {
        self.signatures
            .values()
            .filter(|sig| sig.os_family == family)
            .collect()
    }
}

impl Default for OsFingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = OsFingerprintDatabase::new();
        assert!(db.signature_count() > 0);
    }

    #[test]
    fn test_os_family_display() {
        assert_eq!(format!("{}", OsFamily::Linux), "Linux");
        assert_eq!(format!("{}", OsFamily::Windows), "Windows");
        assert_eq!(format!("{}", OsFamily::MacOS), "macOS");
    }

    #[test]
    fn test_get_signature() {
        let db = OsFingerprintDatabase::new();
        let sig = db.get_signature("Linux 2.6+");
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().os_family, OsFamily::Linux);
    }

    #[test]
    fn test_get_signatures_by_family() {
        let db = OsFingerprintDatabase::new();
        let linux_sigs = db.get_signatures_by_family(OsFamily::Linux);
        assert!(!linux_sigs.is_empty());
    }

    #[test]
    fn test_add_signature() {
        let mut db = OsFingerprintDatabase::new();
        let initial_count = db.signature_count();
        
        db.add_signature(OsSignature {
            os_name: "Test OS".to_string(),
            os_version: None,
            os_family: OsFamily::Unknown,
            tcp_signature: None,
            icmp_signature: None,
            confidence_weight: 1.0,
        });
        
        assert_eq!(db.signature_count(), initial_count + 1);
    }
}

