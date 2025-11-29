/// Service fingerprint matching module
/// 
/// This module implements service detection through fingerprint matching
/// using port numbers, banners, and behavior patterns.

use crate::error::ScanResult;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Service fingerprint information
#[derive(Debug, Clone)]
pub struct ServiceFingerprint {
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub os_info: Option<String>,
    pub cpe: Option<String>,
    pub confidence: f32,
}

impl std::fmt::Display for ServiceFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.service_name)?;
        
        if let Some(ref product) = self.product {
            write!(f, " ({})", product)?;
        }
        
        if let Some(ref version) = self.version {
            write!(f, " v{}", version)?;
        }
        
        write!(f, " [{:.0}% confidence]", self.confidence * 100.0)?;
        
        Ok(())
    }
}

/// Fingerprint pattern for matching
#[derive(Debug, Clone)]
pub(crate) struct FingerprintPattern {
    service_name: String,
    product: Option<String>,
    ports: Vec<u16>,
    banner_patterns: Vec<String>,
    confidence: f32,
}

/// Fingerprint database
pub struct FingerprintDatabase {
    patterns: Vec<FingerprintPattern>,
    port_map: HashMap<u16, Vec<usize>>,
}

impl FingerprintDatabase {
    /// Create a new empty fingerprint database
    pub fn new() -> Self {
        info!("Creating new fingerprint database");
        Self {
            patterns: Vec::new(),
            port_map: HashMap::new(),
        }
    }

    /// Load built-in fingerprints
    pub fn with_builtin() -> Self {
        let mut db = Self::new();
        db.load_builtin_fingerprints();
        info!("Loaded {} fingerprints", db.patterns.len());
        db
    }

    /// Load fingerprints from a file
    pub fn load_from_file(&mut self, _path: &str) -> ScanResult<()> {
        // TODO: Implement loading from file (JSON/YAML format)
        warn!("Loading fingerprints from file not yet implemented");
        Ok(())
    }

    /// Add a fingerprint pattern to the database
    pub(crate) fn add_pattern(&mut self, pattern: FingerprintPattern) {
        let index = self.patterns.len();
        
        // Index by ports for faster lookups
        for &port in &pattern.ports {
            self.port_map
                .entry(port)
                .or_insert_with(Vec::new)
                .push(index);
        }
        
        self.patterns.push(pattern);
    }

    /// Find matching fingerprints for a port and banner
    pub fn find_matches(&self, port: u16, banner: Option<&str>) -> Vec<ServiceFingerprint> {
        let mut matches = Vec::new();

        // Get patterns for this port
        if let Some(pattern_indices) = self.port_map.get(&port) {
            for &index in pattern_indices {
                if let Some(pattern) = self.patterns.get(index) {
                    if let Some(fingerprint) = self.match_pattern(pattern, banner) {
                        matches.push(fingerprint);
                    }
                }
            }
        }

        // Sort by confidence (highest first)
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        matches
    }

    /// Check if a pattern matches the banner
    fn match_pattern(&self, pattern: &FingerprintPattern, banner: Option<&str>) -> Option<ServiceFingerprint> {
        let Some(banner_text) = banner else {
            // No banner, return low confidence match based on port only
            return Some(ServiceFingerprint {
                service_name: pattern.service_name.clone(),
                product: pattern.product.clone(),
                version: None,
                os_info: None,
                cpe: None,
                confidence: 0.3, // Low confidence without banner
            });
        };

        // Check if any banner pattern matches
        for banner_pattern in &pattern.banner_patterns {
            if banner_text.to_lowercase().contains(&banner_pattern.to_lowercase()) {
                // Try to extract version if present
                let version = self.extract_version(banner_text, banner_pattern);
                
                return Some(ServiceFingerprint {
                    service_name: pattern.service_name.clone(),
                    product: pattern.product.clone(),
                    version,
                    os_info: None,
                    cpe: None,
                    confidence: pattern.confidence,
                });
            }
        }

        None
    }

    /// Extract version from banner
    fn extract_version(&self, banner: &str, _pattern: &str) -> Option<String> {
        // Simple version extraction (can be enhanced)
        let version_patterns = [
            r"(\d+\.\d+\.\d+)",
            r"(\d+\.\d+)",
            r"v(\d+\.\d+)",
        ];

        for pattern in &version_patterns {
            if let Some(version_match) = self.simple_regex_match(banner, pattern) {
                return Some(version_match);
            }
        }

        None
    }

    /// Simple regex-like pattern matching (basic implementation)
    fn simple_regex_match(&self, text: &str, _pattern: &str) -> Option<String> {
        // Basic version detection
        for word in text.split_whitespace() {
            // Check for version-like patterns: 1.2.3 or 1.2
            if word.chars().filter(|&c| c == '.').count() >= 1 {
                let parts: Vec<&str> = word.split('.').collect();
                if parts.iter().all(|p| p.chars().all(|c| c.is_numeric() || c == '-' || c == '_')) {
                    return Some(word.to_string());
                }
            }
        }
        None
    }

    /// Load built-in service fingerprints
    fn load_builtin_fingerprints(&mut self) {
        // HTTP services
        self.add_pattern(FingerprintPattern {
            service_name: "http".to_string(),
            product: Some("nginx".to_string()),
            ports: vec![80, 443, 8080, 8443],
            banner_patterns: vec!["nginx".to_string()],
            confidence: 0.95,
        });

        self.add_pattern(FingerprintPattern {
            service_name: "http".to_string(),
            product: Some("Apache".to_string()),
            ports: vec![80, 443, 8080, 8443],
            banner_patterns: vec!["Apache".to_string()],
            confidence: 0.95,
        });

        // SSH
        self.add_pattern(FingerprintPattern {
            service_name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            ports: vec![22],
            banner_patterns: vec!["SSH-".to_string(), "OpenSSH".to_string()],
            confidence: 0.98,
        });

        // FTP
        self.add_pattern(FingerprintPattern {
            service_name: "ftp".to_string(),
            product: Some("vsftpd".to_string()),
            ports: vec![21],
            banner_patterns: vec!["vsftpd".to_string()],
            confidence: 0.95,
        });

        self.add_pattern(FingerprintPattern {
            service_name: "ftp".to_string(),
            product: Some("ProFTPD".to_string()),
            ports: vec![21],
            banner_patterns: vec!["ProFTPD".to_string()],
            confidence: 0.95,
        });

        // SMTP
        self.add_pattern(FingerprintPattern {
            service_name: "smtp".to_string(),
            product: Some("Postfix".to_string()),
            ports: vec![25, 587],
            banner_patterns: vec!["Postfix".to_string(), "ESMTP Postfix".to_string()],
            confidence: 0.95,
        });

        // MySQL
        self.add_pattern(FingerprintPattern {
            service_name: "mysql".to_string(),
            product: Some("MySQL".to_string()),
            ports: vec![3306],
            banner_patterns: vec!["mysql".to_string(), "MySQL".to_string()],
            confidence: 0.90,
        });

        // PostgreSQL
        self.add_pattern(FingerprintPattern {
            service_name: "postgresql".to_string(),
            product: Some("PostgreSQL".to_string()),
            ports: vec![5432],
            banner_patterns: vec!["PostgreSQL".to_string()],
            confidence: 0.90,
        });

        // Redis
        self.add_pattern(FingerprintPattern {
            service_name: "redis".to_string(),
            product: Some("Redis".to_string()),
            ports: vec![6379],
            banner_patterns: vec!["redis_version".to_string()],
            confidence: 0.95,
        });

        // MongoDB
        self.add_pattern(FingerprintPattern {
            service_name: "mongodb".to_string(),
            product: Some("MongoDB".to_string()),
            ports: vec![27017],
            banner_patterns: vec!["MongoDB".to_string()],
            confidence: 0.90,
        });

        // Memcached
        self.add_pattern(FingerprintPattern {
            service_name: "memcached".to_string(),
            product: Some("Memcached".to_string()),
            ports: vec![11211],
            banner_patterns: vec!["STAT".to_string(), "version".to_string()],
            confidence: 0.85,
        });

        // SMB
        self.add_pattern(FingerprintPattern {
            service_name: "microsoft-ds".to_string(),
            product: Some("Samba".to_string()),
            ports: vec![445, 139],
            banner_patterns: vec!["Samba".to_string()],
            confidence: 0.90,
        });

        // RDP
        self.add_pattern(FingerprintPattern {
            service_name: "ms-wbt-server".to_string(),
            product: Some("Microsoft Terminal Services".to_string()),
            ports: vec![3389],
            banner_patterns: vec!["RDP".to_string()],
            confidence: 0.85,
        });

        debug!("Loaded {} built-in fingerprints", self.patterns.len());
    }
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::with_builtin()
    }
}

/// Fingerprint matcher
pub struct FingerprintMatcher {
    database: FingerprintDatabase,
}

impl FingerprintMatcher {
    /// Create a new fingerprint matcher
    pub fn new(database_path: Option<String>) -> ScanResult<Self> {
        let mut database = FingerprintDatabase::with_builtin();

        if let Some(path) = database_path {
            database.load_from_file(&path)?;
        }

        Ok(Self { database })
    }

    /// Match a service based on port and banner
    /// 
    /// # Arguments
    /// * `port` - Port number
    /// * `banner` - Optional service banner
    /// 
    /// # Returns
    /// * `ScanResult<Option<ServiceFingerprint>>` - Best matching service fingerprint
    pub async fn match_service(
        &self,
        port: u16,
        banner: Option<&str>,
    ) -> ScanResult<Option<ServiceFingerprint>> {
        debug!("Matching service for port {} with banner: {:?}", port, banner);

        let matches = self.database.find_matches(port, banner);

        if matches.is_empty() {
            debug!("No service match found for port {}", port);
            return Ok(None);
        }

        // Return the best match (highest confidence)
        let best_match = matches.into_iter().next();
        
        if let Some(ref service) = best_match {
            info!("Matched service: {} on port {}", service, port);
        }

        Ok(best_match)
    }

    /// Match services for multiple ports/banners
    pub async fn match_many(
        &self,
        targets: Vec<(u16, Option<String>)>,
    ) -> ScanResult<Vec<(u16, Option<ServiceFingerprint>)>> {
        let mut results = Vec::new();

        for (port, banner) in targets {
            let banner_ref = banner.as_deref();
            let fingerprint = self.match_service(port, banner_ref).await?;
            results.push((port, fingerprint));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_database_creation() {
        let db = FingerprintDatabase::new();
        assert_eq!(db.patterns.len(), 0);

        let db_builtin = FingerprintDatabase::with_builtin();
        assert!(db_builtin.patterns.len() > 0);
    }

    #[test]
    fn test_fingerprint_display() {
        let fp = ServiceFingerprint {
            service_name: "http".to_string(),
            product: Some("nginx".to_string()),
            version: Some("1.18.0".to_string()),
            os_info: None,
            cpe: None,
            confidence: 0.95,
        };

        let display = format!("{}", fp);
        assert!(display.contains("http"));
        assert!(display.contains("nginx"));
        assert!(display.contains("1.18.0"));
        assert!(display.contains("95%"));
    }

    #[tokio::test]
    async fn test_fingerprint_matcher_creation() {
        let matcher = FingerprintMatcher::new(None);
        assert!(matcher.is_ok());
    }

    #[tokio::test]
    async fn test_match_http_service() {
        let matcher = FingerprintMatcher::new(None).unwrap();
        
        let banner = Some("nginx/1.18.0");
        let result = matcher.match_service(80, banner).await.unwrap();
        
        assert!(result.is_some());
        let service = result.unwrap();
        assert_eq!(service.service_name, "http");
    }

    #[tokio::test]
    async fn test_match_ssh_service() {
        let matcher = FingerprintMatcher::new(None).unwrap();
        
        let banner = Some("SSH-2.0-OpenSSH_8.9");
        let result = matcher.match_service(22, banner).await.unwrap();
        
        assert!(result.is_some());
        let service = result.unwrap();
        assert_eq!(service.service_name, "ssh");
    }

    #[tokio::test]
    async fn test_match_unknown_service() {
        let matcher = FingerprintMatcher::new(None).unwrap();
        
        let result = matcher.match_service(9999, None).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_add_pattern() {
        let mut db = FingerprintDatabase::new();
        
        let pattern = FingerprintPattern {
            service_name: "test".to_string(),
            product: None,
            ports: vec![8080],
            banner_patterns: vec!["test".to_string()],
            confidence: 0.8,
        };

        db.add_pattern(pattern);
        assert_eq!(db.patterns.len(), 1);
    }
}

