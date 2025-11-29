//! Passive Fingerprinting Module
//!
//! This module implements passive OS fingerprinting techniques that analyze network
//! traffic without sending active probes. This is stealthier than active fingerprinting
//! and can be used for monitoring and detection without alerting the target.

use crate::error::{ScanResult, ScanError};
use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Represents a passive observation of network traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveObservation {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Initial TTL value
    pub ttl: u8,
    /// TCP window size
    pub window_size: u16,
    /// Maximum segment size (MSS)
    pub mss: Option<u16>,
    /// TCP options
    pub tcp_options: Vec<u8>,
    /// TCP flags
    pub tcp_flags: u8,
    /// Timestamp of observation (Unix microseconds)
    pub timestamp_us: u64,
    /// Whether the DF (Don't Fragment) flag is set
    pub df_flag: bool,
}

/// Represents the results of passive fingerprinting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveFingerprintResult {
    /// The target IP address
    pub target: IpAddr,
    /// Number of packets observed
    pub packets_observed: usize,
    /// TTL + MSS observations
    pub ttl_mss_profile: Option<TtlMssProfile>,
    /// TCP handshake pattern analysis
    pub handshake_pattern: Option<HandshakePattern>,
    /// Estimated system uptime
    pub estimated_uptime: Option<Duration>,
    /// OS classification hints
    pub os_hints: Vec<String>,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
}

/// TTL and MSS profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlMssProfile {
    /// Most common initial TTL value
    pub initial_ttl: u8,
    /// Most common MSS value
    pub mss: u16,
    /// TCP window size
    pub window_size: u16,
    /// Whether DF flag is typically set
    pub df_flag_set: bool,
}

/// TCP handshake pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePattern {
    /// Average window size in SYN packets
    pub syn_window_avg: f64,
    /// Average window size in SYN-ACK packets
    pub syn_ack_window_avg: f64,
    /// Common TCP options sequence
    pub common_options: Vec<u8>,
    /// Window scaling factor
    pub window_scale: Option<u8>,
}

/// Represents a duration in a more controlled way
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duration {
    pub seconds: u64,
}

/// Passive fingerprinting analyzer
pub struct PassiveAnalyzer {
    /// Observations collected per target
    observations: HashMap<IpAddr, Vec<PassiveObservation>>,
    /// Minimum number of observations needed
    min_observations: usize,
}

impl PassiveAnalyzer {
    /// Creates a new passive analyzer
    pub fn new() -> Self {
        Self {
            observations: HashMap::new(),
            min_observations: 5,
        }
    }

    /// Adds a passive observation from captured network traffic
    ///
    /// This would typically be called from a packet capture loop
    pub fn add_observation(&mut self, observation: PassiveObservation) {
        let target = observation.src_ip;
        self.observations
            .entry(target)
            .or_insert_with(Vec::new)
            .push(observation);
        
        debug!("Added passive observation for {}", target);
    }

    /// Observes TTL and MSS from passive traffic
    ///
    /// This analyzes collected packets to determine the most common TTL and MSS values,
    /// which can help identify the operating system.
    pub fn analyze_ttl_mss(&self, target: IpAddr) -> ScanResult<TtlMssProfile> {
        let observations = self.observations.get(&target)
            .ok_or_else(|| ScanError::TargetNotFound { target })?;
        
        if observations.is_empty() {
            return Err(ScanError::InsufficientData {
                required: self.min_observations,
                available: 0,
            });
        }
        
        info!("Analyzing TTL + MSS profile for {} from {} observations", target, observations.len());
        
        // Count TTL values
        let mut ttl_counts: HashMap<u8, usize> = HashMap::new();
        let mut mss_counts: HashMap<u16, usize> = HashMap::new();
        let mut window_counts: HashMap<u16, usize> = HashMap::new();
        let mut df_count = 0;
        
        for obs in observations {
            *ttl_counts.entry(obs.ttl).or_insert(0) += 1;
            *window_counts.entry(obs.window_size).or_insert(0) += 1;
            
            if let Some(mss) = obs.mss {
                *mss_counts.entry(mss).or_insert(0) += 1;
            }
            
            if obs.df_flag {
                df_count += 1;
            }
        }
        
        // Find most common values
        let initial_ttl = *ttl_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ttl, _)| ttl)
            .unwrap_or(&64);
        
        let mss = *mss_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(mss, _)| mss)
            .unwrap_or(&1460);
        
        let window_size = *window_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(win, _)| win)
            .unwrap_or(&65535);
        
        let df_flag_set = df_count > observations.len() / 2;
        
        debug!("TTL+MSS profile: TTL={}, MSS={}, Window={}, DF={}", 
               initial_ttl, mss, window_size, df_flag_set);
        
        Ok(TtlMssProfile {
            initial_ttl,
            mss,
            window_size,
            df_flag_set,
        })
    }

    /// Analyzes TCP handshake patterns
    ///
    /// This examines the characteristics of TCP handshakes (SYN, SYN-ACK patterns)
    /// to identify OS-specific behaviors.
    pub fn analyze_handshake_pattern(&self, target: IpAddr) -> ScanResult<HandshakePattern> {
        let observations = self.observations.get(&target)
            .ok_or_else(|| ScanError::TargetNotFound { target })?;
        
        if observations.is_empty() {
            return Err(ScanError::InsufficientData {
                required: self.min_observations,
                available: 0,
            });
        }
        
        info!("Analyzing TCP handshake pattern for {}", target);
        
        // Filter for SYN packets (flag 0x02)
        let syn_packets: Vec<_> = observations.iter()
            .filter(|obs| obs.tcp_flags & 0x02 != 0 && obs.tcp_flags & 0x10 == 0)
            .collect();
        
        // Filter for SYN-ACK packets (flags 0x12)
        let syn_ack_packets: Vec<_> = observations.iter()
            .filter(|obs| obs.tcp_flags & 0x02 != 0 && obs.tcp_flags & 0x10 != 0)
            .collect();
        
        // Calculate average window sizes
        let syn_window_avg = if !syn_packets.is_empty() {
            syn_packets.iter().map(|p| p.window_size as f64).sum::<f64>() / syn_packets.len() as f64
        } else {
            0.0
        };
        
        let syn_ack_window_avg = if !syn_ack_packets.is_empty() {
            syn_ack_packets.iter().map(|p| p.window_size as f64).sum::<f64>() / syn_ack_packets.len() as f64
        } else {
            0.0
        };
        
        // Find most common TCP options sequence
        let mut option_counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for obs in observations {
            *option_counts.entry(obs.tcp_options.clone()).or_insert(0) += 1;
        }
        
        let common_options = option_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(opts, _)| opts.clone())
            .unwrap_or_default();
        
        // Extract window scale if present (option kind 3)
        let window_scale = self.extract_window_scale(&common_options);
        
        debug!("Handshake pattern: SYN window avg={:.0}, SYN-ACK window avg={:.0}", 
               syn_window_avg, syn_ack_window_avg);
        
        Ok(HandshakePattern {
            syn_window_avg,
            syn_ack_window_avg,
            common_options,
            window_scale,
        })
    }

    /// Extracts window scale option from TCP options
    fn extract_window_scale(&self, options: &[u8]) -> Option<u8> {
        let mut i = 0;
        while i < options.len() {
            match options[i] {
                0 => break, // End of options
                1 => i += 1, // NOP
                3 => { // Window Scale
                    if i + 2 < options.len() {
                        return Some(options[i + 2]);
                    }
                    break;
                }
                _kind => {
                    // Other options with length
                    if i + 1 < options.len() {
                        i += options[i + 1] as usize;
                    } else {
                        break;
                    }
                }
            }
        }
        None
    }

    /// Estimates system uptime based on TCP timestamp values
    ///
    /// This uses the TCP timestamp option to estimate how long the system has been running.
    /// The timestamp typically increments at a fixed rate (e.g., 1000 Hz on Linux).
    pub fn estimate_uptime(&self, target: IpAddr) -> ScanResult<Duration> {
        let observations = self.observations.get(&target)
            .ok_or_else(|| ScanError::TargetNotFound { target })?;
        
        if observations.is_empty() {
            return Err(ScanError::InsufficientData {
                required: self.min_observations,
                available: 0,
            });
        }
        
        info!("Estimating uptime for {}", target);
        
        // In a real implementation, this would extract TCP timestamp options
        // and calculate uptime based on the timestamp value and assumed frequency
        
        // For now, we'll use a simplified approach based on observation time
        let earliest = observations.iter()
            .map(|obs| obs.timestamp_us)
            .min()
            .unwrap_or(0);
        
        let latest = observations.iter()
            .map(|obs| obs.timestamp_us)
            .max()
            .unwrap_or(0);
        
        // Calculate observation window
        let observation_window_sec = (latest - earliest) / 1_000_000;
        
        // Estimate uptime (this is a placeholder - real implementation would be more sophisticated)
        let estimated_uptime_sec = observation_window_sec * 10; // Rough estimate
        
        debug!("Estimated uptime: {} seconds", estimated_uptime_sec);
        
        Ok(Duration {
            seconds: estimated_uptime_sec,
        })
    }

    /// Classifies OS based on passive observations
    pub fn classify_os_passive(
        &self,
        ttl_mss: &TtlMssProfile,
        handshake: &HandshakePattern,
    ) -> Vec<String> {
        let mut hints = Vec::new();
        
        // Classify based on TTL
        match ttl_mss.initial_ttl {
            64 => hints.push("Linux, macOS, or Unix-like".to_string()),
            128 => hints.push("Windows".to_string()),
            255 => hints.push("Cisco IOS or legacy Unix".to_string()),
            _ => {}
        }
        
        // Classify based on MSS
        match ttl_mss.mss {
            1460 => hints.push("Ethernet MTU 1500 (common)".to_string()),
            1380 => hints.push("VPN or tunneled connection".to_string()),
            1440 => hints.push("PPPoE connection".to_string()),
            _ => {}
        }
        
        // Classify based on window size
        if ttl_mss.window_size >= 65535 {
            hints.push("High-performance TCP stack".to_string());
        } else if ttl_mss.window_size <= 8192 {
            hints.push("Legacy or embedded system".to_string());
        }
        
        // Classify based on DF flag
        if ttl_mss.df_flag_set {
            hints.push("Modern OS with PMTU discovery".to_string());
        }
        
        // Classify based on handshake pattern
        if let Some(scale) = handshake.window_scale {
            if scale >= 7 {
                hints.push("Linux (high window scaling)".to_string());
            } else if scale >= 2 {
                hints.push("Windows or macOS".to_string());
            }
        }
        
        debug!("Passive OS classification hints: {:?}", hints);
        hints
    }

    /// Performs complete passive fingerprinting analysis
    pub fn analyze(&self, target: IpAddr) -> ScanResult<PassiveFingerprintResult> {
        info!("Starting passive fingerprinting for {}", target);
        
        let observations = self.observations.get(&target)
            .ok_or_else(|| ScanError::TargetNotFound { target })?;
        
        if observations.len() < self.min_observations {
            return Err(ScanError::InsufficientData {
                required: self.min_observations,
                available: observations.len(),
            });
        }
        
        // Analyze TTL + MSS profile
        let ttl_mss_profile = self.analyze_ttl_mss(target).ok();
        
        // Analyze handshake pattern
        let handshake_pattern = self.analyze_handshake_pattern(target).ok();
        
        // Estimate uptime
        let estimated_uptime = self.estimate_uptime(target).ok();
        
        // Generate OS hints
        let os_hints = if let (Some(ref ttl_mss), Some(ref handshake)) = 
            (&ttl_mss_profile, &handshake_pattern) {
            self.classify_os_passive(ttl_mss, handshake)
        } else {
            Vec::new()
        };
        
        // Calculate confidence based on number of observations and data quality
        let confidence = self.calculate_confidence(observations.len(), &ttl_mss_profile, &handshake_pattern);
        
        Ok(PassiveFingerprintResult {
            target,
            packets_observed: observations.len(),
            ttl_mss_profile,
            handshake_pattern,
            estimated_uptime,
            os_hints,
            confidence,
        })
    }

    /// Calculates confidence score based on observation quality
    fn calculate_confidence(
        &self,
        observation_count: usize,
        ttl_mss: &Option<TtlMssProfile>,
        handshake: &Option<HandshakePattern>,
    ) -> f64 {
        let mut confidence = 0.0;
        
        // Base confidence on observation count
        confidence += (observation_count as f64 / 50.0).min(0.4);
        
        // Bonus for having TTL+MSS profile
        if ttl_mss.is_some() {
            confidence += 0.3;
        }
        
        // Bonus for having handshake pattern
        if handshake.is_some() {
            confidence += 0.3;
        }
        
        confidence.min(1.0).max(0.0)
    }

    /// Clears observations for a target
    pub fn clear_observations(&mut self, target: IpAddr) {
        self.observations.remove(&target);
        debug!("Cleared observations for {}", target);
    }

    /// Gets the number of observations for a target
    pub fn observation_count(&self, target: IpAddr) -> usize {
        self.observations.get(&target).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for PassiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_observation(src_ip: &str, ttl: u8, mss: u16, window: u16) -> PassiveObservation {
        PassiveObservation {
            src_ip: src_ip.parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            ttl,
            window_size: window,
            mss: Some(mss),
            tcp_options: vec![2, 4, 5, 180], // MSS option
            tcp_flags: 0x02, // SYN
            timestamp_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
            df_flag: true,
        }
    }

    #[test]
    fn test_passive_observation() {
        let mut analyzer = PassiveAnalyzer::new();
        let target: IpAddr = "192.168.1.100".parse().unwrap();
        
        // Add multiple observations
        for _i in 0..10 {
            let obs = create_test_observation("192.168.1.100", 64, 1460, 65535);
            analyzer.add_observation(obs);
        }
        
        assert_eq!(analyzer.observation_count(target), 10);
    }

    #[test]
    fn test_ttl_mss_analysis() {
        let mut analyzer = PassiveAnalyzer::new();
        
        // Add observations simulating a Linux system
        for _ in 0..10 {
            analyzer.add_observation(create_test_observation("192.168.1.100", 64, 1460, 65535));
        }
        
        let target: IpAddr = "192.168.1.100".parse().unwrap();
        let result = analyzer.analyze_ttl_mss(target);
        
        assert!(result.is_ok());
        let profile = result.unwrap();
        assert_eq!(profile.initial_ttl, 64);
        assert_eq!(profile.mss, 1460);
    }

    #[test]
    fn test_os_classification() {
        let analyzer = PassiveAnalyzer::new();
        
        let ttl_mss = TtlMssProfile {
            initial_ttl: 64,
            mss: 1460,
            window_size: 65535,
            df_flag_set: true,
        };
        
        let handshake = HandshakePattern {
            syn_window_avg: 65535.0,
            syn_ack_window_avg: 65535.0,
            common_options: vec![2, 4, 5, 180],
            window_scale: Some(7),
        };
        
        let hints = analyzer.classify_os_passive(&ttl_mss, &handshake);
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.contains("Linux") || h.contains("Unix")));
    }

    #[test]
    fn test_passive_analysis() {
        let mut analyzer = PassiveAnalyzer::new();
        let target: IpAddr = "192.168.1.100".parse().unwrap();
        
        // Add sufficient observations
        for _ in 0..10 {
            analyzer.add_observation(create_test_observation("192.168.1.100", 64, 1460, 65535));
        }
        
        let result = analyzer.analyze(target);
        assert!(result.is_ok());
        
        let analysis = result.unwrap();
        assert_eq!(analysis.packets_observed, 10);
        assert!(analysis.confidence > 0.0);
    }
}

