/// OS detection module using TCP/IP stack fingerprinting
/// 
/// This module implements OS detection by analyzing TCP/IP stack behavior,
/// TTL values, window sizes, and other network characteristics.

use crate::error::ScanResult;
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// OS fingerprint match
#[derive(Debug, Clone)]
pub struct OsMatch {
    pub os_family: String,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub confidence: f32,
    pub matched_features: Vec<String>,
}

impl std::fmt::Display for OsMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.os_family)?;
        
        if let Some(ref name) = self.os_name {
            write!(f, " - {}", name)?;
        }
        
        if let Some(ref version) = self.os_version {
            write!(f, " {}", version)?;
        }
        
        write!(f, " [{:.0}% confidence]", self.confidence * 100.0)?;
        
        Ok(())
    }
}

/// OS fingerprint data collected from probes
#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub tcp_options: Vec<TcpOption>,
    pub ip_id_sequence: Vec<u16>,
    pub initial_sequence: Option<u32>,
    pub timestamp: Option<u32>,
}

/// TCP option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Timestamp(u32, u32),
    Nop,
    EndOfOptions,
}

/// OS detector
pub struct OsDetector {
    fingerprints: Vec<OsFingerprintEntry>,
}

/// OS fingerprint database entry
#[derive(Debug, Clone)]
struct OsFingerprintEntry {
    os_family: String,
    os_name: Option<String>,
    os_version: Option<String>,
    device_type: Option<String>,
    ttl_patterns: Vec<u8>,
    window_sizes: Vec<u16>,
    tcp_option_patterns: Vec<Vec<TcpOption>>,
    confidence_multiplier: f32,
}

impl OsDetector {
    /// Create a new OS detector with built-in fingerprints
    pub fn new() -> Self {
        info!("Initializing OS detector");
        let mut detector = Self {
            fingerprints: Vec::new(),
        };
        detector.load_builtin_fingerprints();
        info!("Loaded {} OS fingerprints", detector.fingerprints.len());
        detector
    }

    /// Detect OS for a target
    /// 
    /// # Arguments
    /// * `target` - Target IP address
    /// 
    /// # Returns
    /// * `ScanResult<Vec<OsMatch>>` - Possible OS matches sorted by confidence
    pub async fn detect(&self, target: IpAddr) -> ScanResult<Vec<OsMatch>> {
        debug!("Performing OS detection for {}", target);

        // TODO: Actually probe the target and collect fingerprint data
        // For now, this is a framework implementation
        warn!("OS detection requires active probing - framework mode");

        // Placeholder: Return empty results
        // In a full implementation, we would:
        // 1. Send various TCP probes
        // 2. Analyze responses (TTL, window size, options)
        // 3. Match against fingerprint database
        
        Ok(vec![])
    }

    /// Analyze collected fingerprint data and find matches
    pub fn analyze_fingerprint(&self, fingerprint: &OsFingerprint) -> Vec<OsMatch> {
        let mut matches = Vec::new();

        for entry in &self.fingerprints {
            let mut confidence = 1.0f32;
            let mut matched_features = Vec::new();

            // Match TTL
            if let Some(ttl) = fingerprint.ttl {
                if entry.ttl_patterns.contains(&ttl) {
                    matched_features.push(format!("TTL={}", ttl));
                } else {
                    // Check for TTL within common hop ranges
                    let ttl_distance = entry.ttl_patterns
                        .iter()
                        .map(|&expected| (ttl as i16 - expected as i16).abs())
                        .min()
                        .unwrap_or(255);
                    
                    if ttl_distance > 20 {
                        confidence *= 0.3;
                    } else {
                        confidence *= 0.7;
                        matched_features.push(format!("TTL~{}", ttl));
                    }
                }
            }

            // Match window size
            if let Some(window) = fingerprint.window_size {
                if entry.window_sizes.contains(&window) {
                    matched_features.push(format!("Window={}", window));
                } else {
                    confidence *= 0.7;
                }
            }

            // Match TCP options
            if !fingerprint.tcp_options.is_empty() {
                let options_match = entry.tcp_option_patterns
                    .iter()
                    .any(|pattern| self.tcp_options_match(pattern, &fingerprint.tcp_options));
                
                if options_match {
                    matched_features.push("TCP Options".to_string());
                } else {
                    confidence *= 0.8;
                }
            }

            // Apply entry confidence multiplier
            confidence *= entry.confidence_multiplier;

            // Only include matches with reasonable confidence
            if confidence >= 0.3 {
                matches.push(OsMatch {
                    os_family: entry.os_family.clone(),
                    os_name: entry.os_name.clone(),
                    os_version: entry.os_version.clone(),
                    device_type: entry.device_type.clone(),
                    confidence,
                    matched_features,
                });
            }
        }

        // Sort by confidence (highest first)
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        matches
    }

    /// Check if TCP options match a pattern
    fn tcp_options_match(&self, pattern: &[TcpOption], options: &[TcpOption]) -> bool {
        if pattern.len() != options.len() {
            return false;
        }

        for (p, o) in pattern.iter().zip(options.iter()) {
            match (p, o) {
                (TcpOption::Mss(_), TcpOption::Mss(_)) => continue,
                (TcpOption::WindowScale(_), TcpOption::WindowScale(_)) => continue,
                (TcpOption::SackPermitted, TcpOption::SackPermitted) => continue,
                (TcpOption::Timestamp(_, _), TcpOption::Timestamp(_, _)) => continue,
                (TcpOption::Nop, TcpOption::Nop) => continue,
                (TcpOption::EndOfOptions, TcpOption::EndOfOptions) => continue,
                _ => return false,
            }
        }

        true
    }

    /// Load built-in OS fingerprints
    fn load_builtin_fingerprints(&mut self) {
        // Linux fingerprints
        self.fingerprints.push(OsFingerprintEntry {
            os_family: "Linux".to_string(),
            os_name: Some("Linux Kernel".to_string()),
            os_version: Some("2.6.x - 5.x".to_string()),
            device_type: Some("general purpose".to_string()),
            ttl_patterns: vec![64],
            window_sizes: vec![5840, 14600, 29200],
            tcp_option_patterns: vec![
                vec![TcpOption::Mss(1460), TcpOption::SackPermitted, TcpOption::Timestamp(0, 0)],
            ],
            confidence_multiplier: 0.9,
        });

        // Windows fingerprints
        self.fingerprints.push(OsFingerprintEntry {
            os_family: "Windows".to_string(),
            os_name: Some("Microsoft Windows".to_string()),
            os_version: Some("10/11".to_string()),
            device_type: Some("general purpose".to_string()),
            ttl_patterns: vec![128],
            window_sizes: vec![8192, 65535],
            tcp_option_patterns: vec![
                vec![TcpOption::Mss(1460), TcpOption::Nop, TcpOption::WindowScale(8)],
            ],
            confidence_multiplier: 0.9,
        });

        self.fingerprints.push(OsFingerprintEntry {
            os_family: "Windows".to_string(),
            os_name: Some("Windows Server".to_string()),
            os_version: Some("2016-2022".to_string()),
            device_type: Some("server".to_string()),
            ttl_patterns: vec![128],
            window_sizes: vec![8192, 65535],
            tcp_option_patterns: vec![],
            confidence_multiplier: 0.85,
        });

        // macOS fingerprints
        self.fingerprints.push(OsFingerprintEntry {
            os_family: "macOS".to_string(),
            os_name: Some("Apple macOS".to_string()),
            os_version: Some("10.x - 14.x".to_string()),
            device_type: Some("general purpose".to_string()),
            ttl_patterns: vec![64],
            window_sizes: vec![65535],
            tcp_option_patterns: vec![
                vec![TcpOption::Mss(1460), TcpOption::Nop, TcpOption::WindowScale(6), TcpOption::SackPermitted],
            ],
            confidence_multiplier: 0.9,
        });

        // FreeBSD fingerprints
        self.fingerprints.push(OsFingerprintEntry {
            os_family: "FreeBSD".to_string(),
            os_name: Some("FreeBSD".to_string()),
            os_version: Some("11.x - 13.x".to_string()),
            device_type: Some("server".to_string()),
            ttl_patterns: vec![64],
            window_sizes: vec![65535],
            tcp_option_patterns: vec![],
            confidence_multiplier: 0.85,
        });

        // Cisco IOS fingerprints
        self.fingerprints.push(OsFingerprintEntry {
            os_family: "IOS".to_string(),
            os_name: Some("Cisco IOS".to_string()),
            os_version: None,
            device_type: Some("router".to_string()),
            ttl_patterns: vec![255],
            window_sizes: vec![4128],
            tcp_option_patterns: vec![],
            confidence_multiplier: 0.8,
        });

        // Embedded Linux (IoT)
        self.fingerprints.push(OsFingerprintEntry {
            os_family: "Linux".to_string(),
            os_name: Some("Embedded Linux".to_string()),
            os_version: None,
            device_type: Some("embedded".to_string()),
            ttl_patterns: vec![64],
            window_sizes: vec![5840],
            tcp_option_patterns: vec![],
            confidence_multiplier: 0.7,
        });

        debug!("Loaded {} built-in OS fingerprints", self.fingerprints.len());
    }
}

impl Default for OsDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_detector_creation() {
        let detector = OsDetector::new();
        assert!(!detector.fingerprints.is_empty());
    }

    #[test]
    fn test_os_match_display() {
        let os_match = OsMatch {
            os_family: "Linux".to_string(),
            os_name: Some("Ubuntu".to_string()),
            os_version: Some("22.04".to_string()),
            device_type: Some("server".to_string()),
            confidence: 0.95,
            matched_features: vec!["TTL=64".to_string()],
        };

        let display = format!("{}", os_match);
        assert!(display.contains("Linux"));
        assert!(display.contains("Ubuntu"));
        assert!(display.contains("22.04"));
        assert!(display.contains("95%"));
    }

    #[test]
    fn test_analyze_linux_fingerprint() {
        let detector = OsDetector::new();
        
        let fingerprint = OsFingerprint {
            ttl: Some(64),
            window_size: Some(5840),
            tcp_options: vec![],
            ip_id_sequence: vec![],
            initial_sequence: None,
            timestamp: None,
        };

        let matches = detector.analyze_fingerprint(&fingerprint);
        assert!(!matches.is_empty());
        
        // Should match Linux
        let top_match = &matches[0];
        assert_eq!(top_match.os_family, "Linux");
    }

    #[test]
    fn test_analyze_windows_fingerprint() {
        let detector = OsDetector::new();
        
        let fingerprint = OsFingerprint {
            ttl: Some(128),
            window_size: Some(65535),
            tcp_options: vec![],
            ip_id_sequence: vec![],
            initial_sequence: None,
            timestamp: None,
        };

        let matches = detector.analyze_fingerprint(&fingerprint);
        assert!(!matches.is_empty());
        
        // Should match Windows
        let top_match = &matches[0];
        assert_eq!(top_match.os_family, "Windows");
    }

    #[test]
    fn test_tcp_options_match() {
        let detector = OsDetector::new();
        
        let pattern = vec![TcpOption::Mss(1460), TcpOption::Nop];
        let options = vec![TcpOption::Mss(1400), TcpOption::Nop];
        
        assert!(detector.tcp_options_match(&pattern, &options));
    }

    #[tokio::test]
    async fn test_detect_returns_empty_framework() {
        use std::net::Ipv4Addr;
        
        let detector = OsDetector::new();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        let result = detector.detect(target).await;
        assert!(result.is_ok());
        // Framework mode returns empty
        assert_eq!(result.unwrap().len(), 0);
    }
}

