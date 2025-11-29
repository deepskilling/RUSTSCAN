/// OS Matching Engine
/// 
/// This module matches collected fingerprints against the OS signature database

use crate::error::ScanResult;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::fingerprint_db::{OsFingerprintDatabase, OsSignature};
use super::{OsFingerprint};

/// OS match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatchResult {
    pub os_name: String,
    pub os_version: Option<String>,
    pub os_family: super::fingerprint_db::OsFamily,
    pub confidence: MatchConfidence,
    pub confidence_score: f64,
    pub matching_features: Vec<String>,
}

/// Match confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MatchConfidence {
    Low,
    Medium,
    High,
    Certain,
}

impl std::fmt::Display for MatchConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchConfidence::Low => write!(f, "Low"),
            MatchConfidence::Medium => write!(f, "Medium"),
            MatchConfidence::High => write!(f, "High"),
            MatchConfidence::Certain => write!(f, "Certain"),
        }
    }
}

impl From<f64> for MatchConfidence {
    fn from(score: f64) -> Self {
        match score {
            s if s >= 0.90 => MatchConfidence::Certain,
            s if s >= 0.75 => MatchConfidence::High,
            s if s >= 0.50 => MatchConfidence::Medium,
            _ => MatchConfidence::Low,
        }
    }
}

/// OS matcher
pub struct OsMatcher {
    database: OsFingerprintDatabase,
}

impl OsMatcher {
    /// Create a new OS matcher
    pub fn new(database: OsFingerprintDatabase) -> Self {
        Self { database }
    }

    /// Match a fingerprint against the database
    /// 
    /// # Arguments
    /// * `fingerprint` - The OS fingerprint to match
    pub fn match_fingerprint(
        &self,
        fingerprint: &OsFingerprint,
    ) -> ScanResult<Vec<OsMatchResult>> {
        info!("Matching fingerprint for {}", fingerprint.target);
        
        let mut results = Vec::new();
        
        for signature in self.database.signatures().values() {
            let score = self.calculate_match_score(fingerprint, signature);
            
            if score > 0.0 {
                let matching_features = self.get_matching_features(fingerprint, signature);
                
                results.push(OsMatchResult {
                    os_name: signature.os_name.clone(),
                    os_version: signature.os_version.clone(),
                    os_family: signature.os_family,
                    confidence: MatchConfidence::from(score),
                    confidence_score: score,
                    matching_features,
                });
            }
        }
        
        // Sort by confidence score (descending)
        results.sort_by(|a, b| {
            b.confidence_score
                .partial_cmp(&a.confidence_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Return top 5 matches
        results.truncate(5);
        
        info!("Found {} potential OS matches", results.len());
        
        Ok(results)
    }

    /// Calculate match score between fingerprint and signature
    fn calculate_match_score(
        &self,
        fingerprint: &OsFingerprint,
        signature: &OsSignature,
    ) -> f64 {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;
        
        // TCP fingerprint matching (70% weight)
        if let (Some(fp_tcp), Some(sig_tcp)) = (&fingerprint.tcp_fingerprint, &signature.tcp_signature) {
            let tcp_score = self.match_tcp_fingerprint(fp_tcp, sig_tcp);
            total_score += tcp_score * 0.7;
            total_weight += 0.7;
        }
        
        // ICMP fingerprint matching (30% weight)
        if let (Some(fp_icmp), Some(sig_icmp)) = (&fingerprint.icmp_fingerprint, &signature.icmp_signature) {
            let icmp_score = self.match_icmp_fingerprint(fp_icmp, sig_icmp);
            total_score += icmp_score * 0.3;
            total_weight += 0.3;
        }
        
        // Apply signature confidence weight
        if total_weight > 0.0 {
            (total_score / total_weight) * signature.confidence_weight
        } else {
            0.0
        }
    }

    /// Match TCP fingerprints
    fn match_tcp_fingerprint(
        &self,
        fingerprint: &super::tcp_fingerprint::TcpFingerprint,
        signature: &super::fingerprint_db::TcpSignature,
    ) -> f64 {
        let mut score = 0.0;
        
        // TTL match (15% weight)
        if fingerprint.initial_ttl >= signature.ttl_range.0
            && fingerprint.initial_ttl <= signature.ttl_range.1
        {
            score += 0.15;
        }
        
        // Window size match (15% weight)
        if fingerprint.window_size >= signature.window_size_range.0
            && fingerprint.window_size <= signature.window_size_range.1
        {
            score += 0.15;
        }
        
        // MSS match (10% weight)
        if let (Some(fp_mss), Some(sig_mss)) = (fingerprint.mss, signature.typical_mss) {
            if fp_mss == sig_mss {
                score += 0.10;
            }
        }
        
        // DF flag match (10% weight)
        if fingerprint.df_flag == signature.df_flag {
            score += 0.10;
        }
        
        // RST behavior match (15% weight)
        if fingerprint.rst_behavior == signature.rst_behavior {
            score += 0.15;
        }
        
        // IP ID pattern match (15% weight)
        if fingerprint.ip_id_pattern == signature.ip_id_pattern {
            score += 0.15;
        }
        
        // ECN support match (10% weight)
        if fingerprint.ecn_support == signature.ecn_support {
            score += 0.10;
        }
        
        // TCP options matching (10% weight)
        let options_similarity = self.match_tcp_options(
            &fingerprint.tcp_options,
            &signature.tcp_options_pattern,
        );
        score += options_similarity * 0.10;
        
        score
    }

    /// Match ICMP fingerprints
    fn match_icmp_fingerprint(
        &self,
        fingerprint: &super::icmp_fingerprint::IcmpFingerprint,
        signature: &super::fingerprint_db::IcmpSignature,
    ) -> f64 {
        let mut score = 0.0;
        
        // ICMP TTL match (25% weight)
        if let Some(echo_reply) = &fingerprint.echo_reply {
            if echo_reply.ttl >= signature.ttl_range.0 && echo_reply.ttl <= signature.ttl_range.1 {
                score += 0.25;
            }
            
            // Payload echo match (25% weight)
            if echo_reply.payload_echo == signature.echoes_payload {
                score += 0.25;
            }
        }
        
        // Timestamp behavior match (25% weight)
        if fingerprint.timestamp_behavior == signature.timestamp_behavior {
            score += 0.25;
        }
        
        // Rate limiting pattern match (25% weight)
        if fingerprint.rate_limiting.pattern == signature.rate_limit_pattern {
            score += 0.25;
        }
        
        score
    }

    /// Match TCP options ordering
    fn match_tcp_options(
        &self,
        fingerprint_options: &[super::tcp_fingerprint::TcpOption],
        signature_options: &[super::tcp_fingerprint::TcpOption],
    ) -> f64 {
        if fingerprint_options.is_empty() || signature_options.is_empty() {
            return 0.5; // Neutral score if no data
        }
        
        let mut matches = 0;
        let total = signature_options.len().max(fingerprint_options.len());
        
        for (i, sig_opt) in signature_options.iter().enumerate() {
            if i < fingerprint_options.len() && fingerprint_options[i] == *sig_opt {
                matches += 1;
            }
        }
        
        matches as f64 / total as f64
    }

    /// Get list of matching features
    fn get_matching_features(
        &self,
        fingerprint: &OsFingerprint,
        signature: &OsSignature,
    ) -> Vec<String> {
        let mut features = Vec::new();
        
        if let (Some(fp_tcp), Some(sig_tcp)) = (&fingerprint.tcp_fingerprint, &signature.tcp_signature) {
            if fp_tcp.initial_ttl >= sig_tcp.ttl_range.0 && fp_tcp.initial_ttl <= sig_tcp.ttl_range.1 {
                features.push(format!("TTL: {}", fp_tcp.initial_ttl));
            }
            
            if fp_tcp.window_size >= sig_tcp.window_size_range.0 && fp_tcp.window_size <= sig_tcp.window_size_range.1 {
                features.push(format!("Window: {}", fp_tcp.window_size));
            }
            
            if fp_tcp.df_flag == sig_tcp.df_flag {
                features.push(format!("DF Flag: {}", fp_tcp.df_flag));
            }
            
            if fp_tcp.ip_id_pattern == sig_tcp.ip_id_pattern {
                features.push(format!("IP ID: {:?}", fp_tcp.ip_id_pattern));
            }
        }
        
        if let (Some(fp_icmp), Some(sig_icmp)) = (&fingerprint.icmp_fingerprint, &signature.icmp_signature) {
            if fp_icmp.timestamp_behavior == sig_icmp.timestamp_behavior {
                features.push(format!("ICMP Timestamp: {:?}", fp_icmp.timestamp_behavior));
            }
        }
        
        features
    }
}

impl std::fmt::Display for OsMatchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "OS: {}", self.os_name)?;
        if let Some(ref version) = self.os_version {
            writeln!(f, "  Version: {}", version)?;
        }
        writeln!(f, "  Family: {}", self.os_family)?;
        writeln!(f, "  Confidence: {} ({:.1}%)", self.confidence, self.confidence_score * 100.0)?;
        if !self.matching_features.is_empty() {
            writeln!(f, "  Matching Features:")?;
            for feature in &self.matching_features {
                writeln!(f, "    - {}", feature)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_match_confidence_from_score() {
        assert_eq!(MatchConfidence::from(0.95), MatchConfidence::Certain);
        assert_eq!(MatchConfidence::from(0.80), MatchConfidence::High);
        assert_eq!(MatchConfidence::from(0.60), MatchConfidence::Medium);
        assert_eq!(MatchConfidence::from(0.30), MatchConfidence::Low);
    }

    #[test]
    fn test_match_confidence_display() {
        assert_eq!(format!("{}", MatchConfidence::Certain), "Certain");
        assert_eq!(format!("{}", MatchConfidence::High), "High");
    }

    #[test]
    fn test_matcher_creation() {
        let db = OsFingerprintDatabase::new();
        let _matcher = OsMatcher::new(db);
    }

    #[test]
    fn test_match_fingerprint() {
        let db = OsFingerprintDatabase::new();
        let matcher = OsMatcher::new(db);
        
        let fingerprint = OsFingerprint {
            target: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            tcp_fingerprint: None,
            icmp_fingerprint: None,
            udp_fingerprint: None,
            protocol_hints: None,
            clock_skew: None,
            passive_fingerprint: None,
            active_probes: None,
            detection_time_ms: 100,
        };
        
        let result = matcher.match_fingerprint(&fingerprint);
        assert!(result.is_ok());
    }
}

