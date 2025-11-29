/// Detection engine module for NrMAP
/// 
/// This module provides service detection, fingerprinting, and OS identification
/// capabilities for network scanning operations.

pub mod banner;
pub mod fingerprint;
pub mod os_detection;

pub use banner::{BannerGrabber, ServiceBanner};
pub use fingerprint::{FingerprintMatcher, ServiceFingerprint, FingerprintDatabase};
pub use os_detection::{OsDetector, OsFingerprint, OsMatch};

use crate::error::ScanResult;
use std::net::IpAddr;
use tracing::info;

/// Detection engine configuration
#[derive(Debug, Clone)]
pub struct DetectionEngineConfig {
    pub enable_banner_grabbing: bool,
    pub enable_service_detection: bool,
    pub enable_os_detection: bool,
    pub banner_timeout_ms: u64,
    pub max_banner_size: usize,
    pub fingerprint_database_path: Option<String>,
}

impl Default for DetectionEngineConfig {
    fn default() -> Self {
        Self {
            enable_banner_grabbing: true,
            enable_service_detection: true,
            enable_os_detection: true,
            banner_timeout_ms: 5000,
            max_banner_size: 4096,
            fingerprint_database_path: None,
        }
    }
}

/// Detection engine facade providing high-level API
pub struct DetectionEngine {
    config: DetectionEngineConfig,
    banner_grabber: BannerGrabber,
    fingerprint_matcher: FingerprintMatcher,
    os_detector: OsDetector,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new(config: DetectionEngineConfig) -> ScanResult<Self> {
        info!("Initializing detection engine");
        
        let banner_grabber = BannerGrabber::new(
            config.banner_timeout_ms,
            config.max_banner_size,
        );
        
        let fingerprint_matcher = FingerprintMatcher::new(
            config.fingerprint_database_path.clone(),
        )?;
        
        let os_detector = OsDetector::new();
        
        Ok(Self {
            config,
            banner_grabber,
            fingerprint_matcher,
            os_detector,
        })
    }

    /// Grab service banner from a host/port
    pub async fn grab_banner(
        &self,
        target: IpAddr,
        port: u16,
    ) -> ScanResult<Option<ServiceBanner>> {
        if !self.config.enable_banner_grabbing {
            return Ok(None);
        }
        
        self.banner_grabber.grab(target, port).await
    }

    /// Detect service on a port using fingerprinting
    pub async fn detect_service(
        &self,
        _target: IpAddr,
        port: u16,
        banner: Option<&str>,
    ) -> ScanResult<Option<ServiceFingerprint>> {
        if !self.config.enable_service_detection {
            return Ok(None);
        }
        
        self.fingerprint_matcher.match_service(port, banner).await
    }

    /// Perform OS detection on a target
    pub async fn detect_os(
        &self,
        target: IpAddr,
    ) -> ScanResult<Vec<OsMatch>> {
        if !self.config.enable_os_detection {
            return Ok(vec![]);
        }
        
        self.os_detector.detect(target).await
    }

    /// Perform comprehensive detection (banner + service + OS)
    pub async fn detect_all(
        &self,
        target: IpAddr,
        port: u16,
    ) -> ScanResult<DetectionResult> {
        // Grab banner
        let banner = self.grab_banner(target, port).await?;
        
        // Detect service using banner
        let service = if let Some(ref banner) = banner {
            self.detect_service(target, port, Some(&banner.data)).await?
        } else {
            self.detect_service(target, port, None).await?
        };
        
        // Detect OS (independent of port)
        let os_matches = self.detect_os(target).await?;
        
        Ok(DetectionResult {
            target,
            port,
            banner,
            service,
            os_matches,
        })
    }
}

/// Complete detection result
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub target: IpAddr,
    pub port: u16,
    pub banner: Option<ServiceBanner>,
    pub service: Option<ServiceFingerprint>,
    pub os_matches: Vec<OsMatch>,
}

impl std::fmt::Display for DetectionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Detection Results for {}:{}", self.target, self.port)?;
        
        if let Some(ref banner) = self.banner {
            writeln!(f, "  Banner: {}", banner)?;
        }
        
        if let Some(ref service) = self.service {
            writeln!(f, "  Service: {}", service)?;
        }
        
        if !self.os_matches.is_empty() {
            writeln!(f, "  OS Matches:")?;
            for os_match in &self.os_matches {
                writeln!(f, "    {}", os_match)?;
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_engine_config_default() {
        let config = DetectionEngineConfig::default();
        assert!(config.enable_banner_grabbing);
        assert!(config.enable_service_detection);
        assert!(config.enable_os_detection);
    }

    #[tokio::test]
    async fn test_detection_engine_creation() {
        let config = DetectionEngineConfig::default();
        let result = DetectionEngine::new(config);
        assert!(result.is_ok());
    }
}

