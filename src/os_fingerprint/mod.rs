/// OS Fingerprinting Module
/// 
/// This module implements comprehensive operating system detection through
/// TCP/IP stack fingerprinting and ICMP-based analysis.

pub mod tcp_fingerprint;
pub mod icmp_fingerprint;
pub mod udp_fingerprint;
pub mod protocol_hints;
pub mod fingerprint_db;
pub mod matcher;
pub mod clock_skew;
pub mod passive;
pub mod active_probes;
pub mod database_io;
pub mod fuzzy_matcher;

pub use tcp_fingerprint::{TcpFingerprint, TcpFingerprintAnalyzer};
pub use icmp_fingerprint::{IcmpFingerprint, IcmpFingerprintAnalyzer};
pub use udp_fingerprint::{UdpFingerprint, UdpFingerprintAnalyzer};
pub use protocol_hints::{ProtocolHints, ProtocolHintsAnalyzer};
pub use fingerprint_db::{OsFingerprintDatabase, OsSignature};
pub use matcher::{OsMatcher, OsMatchResult, MatchConfidence};
pub use clock_skew::{ClockSkewAnalyzer, ClockSkewAnalysis};
pub use passive::{PassiveAnalyzer, PassiveFingerprintResult, PassiveObservation};
pub use active_probes::{ActiveProbeLibrary, ActiveProbeResults, TcpProbeType, SeqAnalysis, SeqPredictability};
pub use database_io::{DatabaseIO, FingerprintDatabaseFile};
pub use fuzzy_matcher::{FuzzyMatcher, DetailedMatchResult, FuzzyScore};

use crate::error::ScanResult;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;

/// Complete OS fingerprint combining multiple analysis techniques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub target: IpAddr,
    pub tcp_fingerprint: Option<TcpFingerprint>,
    pub icmp_fingerprint: Option<IcmpFingerprint>,
    pub udp_fingerprint: Option<UdpFingerprint>,
    pub protocol_hints: Option<ProtocolHints>,
    pub clock_skew: Option<ClockSkewAnalysis>,
    pub passive_fingerprint: Option<PassiveFingerprintResult>,
    pub active_probes: Option<ActiveProbeResults>,
    pub detection_time_ms: u64,
}

/// OS fingerprinting engine
pub struct OsFingerprintEngine {
    tcp_analyzer: TcpFingerprintAnalyzer,
    icmp_analyzer: IcmpFingerprintAnalyzer,
    udp_analyzer: UdpFingerprintAnalyzer,
    protocol_analyzer: ProtocolHintsAnalyzer,
    clock_skew_analyzer: ClockSkewAnalyzer,
    passive_analyzer: PassiveAnalyzer,
    active_probe_library: ActiveProbeLibrary,
    database: OsFingerprintDatabase,
    matcher: OsMatcher,
}

impl OsFingerprintEngine {
    /// Create a new OS fingerprinting engine
    pub fn new() -> Self {
        info!("Initializing OS fingerprinting engine with all analyzers");
        
        let database = OsFingerprintDatabase::new();
        
        Self {
            tcp_analyzer: TcpFingerprintAnalyzer::new(),
            icmp_analyzer: IcmpFingerprintAnalyzer::new(),
            udp_analyzer: UdpFingerprintAnalyzer::new(),
            protocol_analyzer: ProtocolHintsAnalyzer::new(),
            clock_skew_analyzer: ClockSkewAnalyzer::new(),
            passive_analyzer: PassiveAnalyzer::new(),
            active_probe_library: ActiveProbeLibrary::new(3000),
            database: database.clone(),
            matcher: OsMatcher::new(database),
        }
    }

    /// Perform comprehensive OS fingerprinting on a target
    /// 
    /// # Arguments
    /// * `target` - Target IP address
    /// * `open_port` - Open port to use for TCP fingerprinting
    /// * `closed_port` - Closed port for some probes
    /// * `use_active_probes` - Whether to use active probe library (more intrusive)
    pub async fn fingerprint(
        &self,
        target: IpAddr,
        open_port: u16,
        closed_port: Option<u16>,
        use_active_probes: bool,
    ) -> ScanResult<OsFingerprint> {
        info!("Starting comprehensive OS fingerprinting for {}", target);
        
        let start_time = std::time::Instant::now();
        
        // TCP-based fingerprinting
        let tcp_fingerprint = self.tcp_analyzer.analyze(target, open_port).await.ok();
        
        // ICMP-based fingerprinting
        let icmp_fingerprint = self.icmp_analyzer.analyze(target).await.ok();
        
        // UDP-based fingerprinting (probe common closed ports)
        let closed_ports = vec![33434, 33435, 33436, 40000, 50000];
        let udp_fingerprint = self.udp_analyzer.analyze(target, &closed_ports).await.ok();
        
        // Protocol-based hints (check common service ports)
        let protocol_hints = self.protocol_analyzer.analyze(
            target,
            Some(22),  // SSH
            Some(445), // SMB
            Some(80),  // HTTP
            Some(443), // HTTPS
        ).await.ok();
        
        // Clock skew analysis (if TCP port is available)
        let clock_skew = self.clock_skew_analyzer.analyze(target, open_port, 20).await.ok();
        
        // Passive fingerprinting (if observations are available)
        let passive_fingerprint = self.passive_analyzer.analyze(target).ok();
        
        // Active probe library (most comprehensive but intrusive)
        let active_probes = if use_active_probes {
            let closed = closed_port.unwrap_or(open_port + 1);
            self.active_probe_library.probe_all(target, open_port, closed).await.ok()
        } else {
            None
        };
        
        let detection_time_ms = start_time.elapsed().as_millis() as u64;
        
        Ok(OsFingerprint {
            target,
            tcp_fingerprint,
            icmp_fingerprint,
            udp_fingerprint,
            protocol_hints,
            clock_skew,
            passive_fingerprint,
            active_probes,
            detection_time_ms,
        })
    }

    /// Match a fingerprint against the database
    /// 
    /// # Arguments
    /// * `fingerprint` - The OS fingerprint to match
    pub fn match_os(&self, fingerprint: &OsFingerprint) -> ScanResult<Vec<OsMatchResult>> {
        self.matcher.match_fingerprint(fingerprint)
    }

    /// Perform fingerprinting and matching in one call
    /// 
    /// # Arguments
    /// * `target` - Target IP address
    /// * `open_port` - Open port to use for TCP fingerprinting
    /// * `closed_port` - Optional closed port
    /// * `use_active_probes` - Whether to use active probes
    pub async fn detect_os(
        &self,
        target: IpAddr,
        open_port: u16,
        closed_port: Option<u16>,
        use_active_probes: bool,
    ) -> ScanResult<Vec<OsMatchResult>> {
        let fingerprint = self.fingerprint(target, open_port, closed_port, use_active_probes).await?;
        self.match_os(&fingerprint)
    }

    /// Get the fingerprint database
    pub fn database(&self) -> &OsFingerprintDatabase {
        &self.database
    }

    /// Load custom fingerprint database
    pub fn load_database(&mut self, database: OsFingerprintDatabase) {
        info!("Loading custom fingerprint database");
        self.database = database.clone();
        self.matcher = OsMatcher::new(database);
    }

    /// Get analyzer references for custom configuration
    pub fn tcp_analyzer(&mut self) -> &mut TcpFingerprintAnalyzer {
        &mut self.tcp_analyzer
    }

    pub fn icmp_analyzer(&mut self) -> &mut IcmpFingerprintAnalyzer {
        &mut self.icmp_analyzer
    }

    pub fn udp_analyzer(&mut self) -> &mut UdpFingerprintAnalyzer {
        &mut self.udp_analyzer
    }

    pub fn protocol_analyzer(&mut self) -> &mut ProtocolHintsAnalyzer {
        &mut self.protocol_analyzer
    }

    pub fn clock_skew_analyzer(&mut self) -> &mut ClockSkewAnalyzer {
        &mut self.clock_skew_analyzer
    }

    pub fn passive_analyzer(&mut self) -> &mut PassiveAnalyzer {
        &mut self.passive_analyzer
    }

    pub fn active_probe_library(&mut self) -> &mut ActiveProbeLibrary {
        &mut self.active_probe_library
    }
}

impl Default for OsFingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// OS fingerprinting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprintConfig {
    pub enable_tcp_fingerprinting: bool,
    pub enable_icmp_fingerprinting: bool,
    pub enable_udp_fingerprinting: bool,
    pub enable_protocol_hints: bool,
    pub enable_clock_skew: bool,
    pub enable_passive: bool,
    pub enable_active_probes: bool,
    pub tcp_timeout_ms: u64,
    pub icmp_timeout_ms: u64,
    pub udp_timeout_ms: u64,
    pub protocol_timeout_ms: u64,
    pub active_probes_timeout_ms: u64,
    pub clock_skew_samples: usize,
    pub passive_min_observations: usize,
    pub seq_probes_count: usize,
    pub max_retries: u8,
    pub confidence_threshold: f64,
}

impl Default for OsFingerprintConfig {
    fn default() -> Self {
        Self {
            enable_tcp_fingerprinting: true,
            enable_icmp_fingerprinting: true,
            enable_udp_fingerprinting: true,
            enable_protocol_hints: true,
            enable_clock_skew: true,
            enable_passive: false, // Passive by default off (needs packet capture)
            enable_active_probes: false, // Active probes off by default (very intrusive)
            tcp_timeout_ms: 5000,
            icmp_timeout_ms: 3000,
            udp_timeout_ms: 3000,
            protocol_timeout_ms: 5000,
            active_probes_timeout_ms: 3000,
            clock_skew_samples: 20,
            passive_min_observations: 10,
            seq_probes_count: 6,
            max_retries: 2,
            confidence_threshold: 0.75,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = OsFingerprintEngine::new();
        assert!(engine.database().signature_count() > 0);
    }

    #[test]
    fn test_config_default() {
        let config = OsFingerprintConfig::default();
        assert!(config.enable_tcp_fingerprinting);
        assert!(config.enable_icmp_fingerprinting);
        assert_eq!(config.tcp_timeout_ms, 5000);
    }

    #[tokio::test]
    async fn test_fingerprint_structure() {
        use std::net::Ipv4Addr;
        
        let engine = OsFingerprintEngine::new();
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // This will use framework implementations
        let result = engine.fingerprint(target, 80, Some(81), false).await;
        assert!(result.is_ok());
        
        let fp = result.unwrap();
        assert!(fp.tcp_fingerprint.is_some());
        assert!(fp.icmp_fingerprint.is_some());
        assert!(fp.udp_fingerprint.is_some());
        assert!(fp.protocol_hints.is_some());
    }
}

