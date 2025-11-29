//! Fuzzy Matching Engine for OS Fingerprints
//!
//! This module implements advanced fuzzy matching algorithms for OS fingerprint matching.
//! It provides partial matches, closest suggestions, and confidence scoring.

use crate::error::ScanResult;
use super::fingerprint_db::{OsFingerprintDatabase, OsSignature, OsFamily};
use super::OsFingerprint;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Fuzzy matcher with advanced matching algorithms
pub struct FuzzyMatcher {
    database: OsFingerprintDatabase,
    /// Minimum score threshold for reporting (0.0 - 1.0)
    min_threshold: f64,
    /// Enable partial matching
    #[allow(dead_code)]
    enable_partial_match: bool,
}

impl FuzzyMatcher {
    /// Create a new fuzzy matcher
    pub fn new(database: OsFingerprintDatabase, min_threshold: f64) -> Self {
        Self {
            database,
            min_threshold,
            enable_partial_match: true,
        }
    }

    /// Match with detailed analysis
    pub fn match_with_details(
        &self,
        fingerprint: &OsFingerprint,
    ) -> ScanResult<DetailedMatchResult> {
        info!("Performing fuzzy matching for {}", fingerprint.target);
        
        let mut all_scores = Vec::new();
        
        // Calculate scores for all signatures
        for signature in self.database.signatures().values() {
            let score = self.calculate_fuzzy_score(fingerprint, signature);
            
            if score.total_score >= self.min_threshold {
                all_scores.push(score);
            }
        }
        
        // Sort by total score (descending)
        all_scores.sort_by(|a, b| b.total_score.partial_cmp(&a.total_score).unwrap());
        
        // Create detailed result
        let confidence_distribution = self.calculate_confidence_distribution(&all_scores);
        let best_match = all_scores.first().cloned();
        let closest_matches: Vec<FuzzyScore> = all_scores.iter().take(5).cloned().collect();
        
        let result = DetailedMatchResult {
            target: fingerprint.target,
            total_signatures_checked: self.database.signature_count(),
            matches_found: all_scores.len(),
            best_match,
            closest_matches,
            match_scores: all_scores,
            confidence_distribution,
            feature_coverage: self.calculate_feature_coverage(fingerprint),
        };
        
        debug!("Fuzzy matching complete: {} matches found", result.matches_found);
        Ok(result)
    }

    /// Calculate fuzzy score with detailed breakdown
    fn calculate_fuzzy_score(
        &self,
        fingerprint: &OsFingerprint,
        signature: &OsSignature,
    ) -> FuzzyScore {
        let mut score_breakdown = ScoreBreakdown::default();
        let mut matched_features = Vec::new();
        let mut mismatched_features = Vec::new();
        let mut total_weight = 0.0;
        let mut weighted_score = 0.0;
        
        // TCP fingerprint matching
        if let (Some(ref fp_tcp), Some(ref sig_tcp)) = 
            (&fingerprint.tcp_fingerprint, &signature.tcp_signature) {
            
            let tcp_score = self.match_tcp_fuzzy(&fp_tcp, sig_tcp, &mut matched_features, &mut mismatched_features);
            score_breakdown.tcp_score = Some(tcp_score);
            weighted_score += tcp_score * 0.35;
            total_weight += 0.35;
        }
        
        // ICMP fingerprint matching
        if let (Some(ref fp_icmp), Some(ref sig_icmp)) = 
            (&fingerprint.icmp_fingerprint, &signature.icmp_signature) {
            
            let icmp_score = self.match_icmp_fuzzy(&fp_icmp, sig_icmp, &mut matched_features, &mut mismatched_features);
            score_breakdown.icmp_score = Some(icmp_score);
            weighted_score += icmp_score * 0.25;
            total_weight += 0.25;
        }
        
        // UDP fingerprint matching
        if let Some(ref fp_udp) = fingerprint.udp_fingerprint {
            let udp_score = self.match_udp_fuzzy(&fp_udp, &mut matched_features, &mut mismatched_features);
            score_breakdown.udp_score = Some(udp_score);
            weighted_score += udp_score * 0.15;
            total_weight += 0.15;
        }
        
        // Protocol hints matching
        if let Some(ref fp_proto) = fingerprint.protocol_hints {
            let proto_score = self.match_protocol_hints_fuzzy(&fp_proto, &mut matched_features);
            score_breakdown.protocol_score = Some(proto_score);
            weighted_score += proto_score * 0.15;
            total_weight += 0.15;
        }
        
        // Clock skew matching
        if let Some(ref clock) = fingerprint.clock_skew {
            if let Some(freq_hz) = clock.clock_frequency_hz {
                let clock_score = self.match_clock_skew_fuzzy(freq_hz, signature.os_family);
                score_breakdown.clock_skew_score = Some(clock_score);
                weighted_score += clock_score * 0.10;
                total_weight += 0.10;
            }
        }
        
        // Normalize score
        let total_score = if total_weight > 0.0 {
            weighted_score / total_weight
        } else {
            0.0
        };
        
        // Apply signature confidence weight
        let final_score = total_score * signature.confidence_weight;
        
        FuzzyScore {
            signature_name: signature.os_name.clone(),
            signature_version: signature.os_version.clone(),
            os_family: signature.os_family,
            total_score: final_score,
            raw_score: total_score,
            confidence_weight: signature.confidence_weight,
            score_breakdown,
            matched_features,
            mismatched_features,
        }
    }

    /// Match TCP fingerprint with fuzzy logic
    fn match_tcp_fuzzy(
        &self,
        fp: &super::tcp_fingerprint::TcpFingerprint,
        sig: &super::fingerprint_db::TcpSignature,
        matched: &mut Vec<String>,
        mismatched: &mut Vec<String>,
    ) -> f64 {
        let mut score = 0.0;
        let mut checks = 0;
        
        // TTL matching (with tolerance)
        if fp.initial_ttl >= sig.ttl_range.0 && fp.initial_ttl <= sig.ttl_range.1 {
            score += 1.0;
            matched.push(format!("TCP TTL: {}", fp.initial_ttl));
        } else {
            // Partial credit if close
            let ttl_diff = if fp.initial_ttl < sig.ttl_range.0 {
                sig.ttl_range.0 - fp.initial_ttl
            } else {
                fp.initial_ttl - sig.ttl_range.1
            };
            if ttl_diff <= 10 {
                score += 0.5;
                matched.push(format!("TCP TTL: {} (partial)", fp.initial_ttl));
            } else {
                mismatched.push(format!("TCP TTL: {} (expected {}-{})", 
                                        fp.initial_ttl, sig.ttl_range.0, sig.ttl_range.1));
            }
        }
        checks += 1;
        
        // Window size matching (with tolerance)
        if fp.window_size >= sig.window_size_range.0 && fp.window_size <= sig.window_size_range.1 {
            score += 1.0;
            matched.push(format!("Window size: {}", fp.window_size));
        } else {
            // Check if within 20% tolerance
            let mid_range = (sig.window_size_range.0 + sig.window_size_range.1) / 2;
            let tolerance = (mid_range as f64 * 0.2) as u16;
            if fp.window_size >= mid_range.saturating_sub(tolerance) && 
               fp.window_size <= mid_range.saturating_add(tolerance) {
                score += 0.6;
                matched.push(format!("Window size: {} (within tolerance)", fp.window_size));
            } else {
                mismatched.push(format!("Window size: {} (expected {}-{})", 
                                        fp.window_size, sig.window_size_range.0, sig.window_size_range.1));
            }
        }
        checks += 1;
        
        // DF flag matching
        if fp.df_flag == sig.df_flag {
            score += 1.0;
            matched.push(format!("DF flag: {}", fp.df_flag));
        } else {
            mismatched.push(format!("DF flag: {} (expected {})", fp.df_flag, sig.df_flag));
        }
        checks += 1;
        
        // MSS matching (if present)
        if let Some(fp_mss) = fp.mss {
            if let Some(sig_mss) = sig.typical_mss {
                if (fp_mss as i32 - sig_mss as i32).abs() <= 100 {
                    score += 1.0;
                    matched.push(format!("MSS: {}", fp_mss));
                } else {
                    mismatched.push(format!("MSS: {} (expected ~{})", fp_mss, sig_mss));
                }
                checks += 1;
            }
        }
        
        // Normalize score
        if checks > 0 {
            score / checks as f64
        } else {
            0.0
        }
    }

    /// Match ICMP fingerprint with fuzzy logic
    fn match_icmp_fuzzy(
        &self,
        fp: &super::icmp_fingerprint::IcmpFingerprint,
        sig: &super::fingerprint_db::IcmpSignature,
        matched: &mut Vec<String>,
        mismatched: &mut Vec<String>,
    ) -> f64 {
        let mut score = 0.0;
        let mut checks = 0;
        
        // TTL matching (from echo_reply if present)
        if let Some(ref echo) = fp.echo_reply {
            if echo.ttl >= sig.ttl_range.0 && echo.ttl <= sig.ttl_range.1 {
                score += 1.0;
                matched.push(format!("ICMP TTL: {}", echo.ttl));
            } else {
                mismatched.push(format!("ICMP TTL: {} (expected {}-{})", 
                                        echo.ttl, sig.ttl_range.0, sig.ttl_range.1));
            }
            checks += 1;
            
            // Payload echo matching
            if echo.payload_echo == sig.echoes_payload {
                score += 1.0;
                matched.push(format!("Echoes payload: {}", echo.payload_echo));
            } else {
                mismatched.push(format!("Echoes payload: {} (expected {})", 
                                        echo.payload_echo, sig.echoes_payload));
            }
            checks += 1;
        }
        
        // Normalize
        if checks > 0 {
            score / checks as f64
        } else {
            0.5 // Partial score if no echo reply data
        }
    }

    /// Match UDP fingerprint with fuzzy logic
    fn match_udp_fuzzy(
        &self,
        _fp: &super::udp_fingerprint::UdpFingerprint,
        matched: &mut Vec<String>,
        _mismatched: &mut Vec<String>,
    ) -> f64 {
        // Basic UDP matching
        matched.push("UDP probe completed".to_string());
        0.7 // Partial score for having UDP data
    }

    /// Match protocol hints
    fn match_protocol_hints_fuzzy(
        &self,
        fp: &super::protocol_hints::ProtocolHints,
        matched: &mut Vec<String>,
    ) -> f64 {
        let mut score = 0.0;
        let mut checks = 0;
        
        if let Some(ref ssh) = fp.ssh_hints {
            if !ssh.os_hints.is_empty() {
                score += 1.0;
                matched.push(format!("SSH hints: {} detected", ssh.os_hints.len()));
            }
            checks += 1;
        }
        
        if let Some(ref http) = fp.http_hints {
            if !http.os_hints.is_empty() {
                score += 1.0;
                matched.push(format!("HTTP hints: {} detected", http.os_hints.len()));
            }
            checks += 1;
        }
        
        if checks > 0 {
            score / checks as f64
        } else {
            0.5
        }
    }

    /// Match clock skew against OS family
    fn match_clock_skew_fuzzy(&self, freq_hz: f64, os_family: OsFamily) -> f64 {
        match os_family {
            OsFamily::Linux if (freq_hz - 1000.0).abs() < 50.0 => 1.0,
            OsFamily::Linux if (freq_hz - 250.0).abs() < 25.0 => 0.9,
            OsFamily::Windows if (freq_hz - 100.0).abs() < 10.0 => 0.9,
            OsFamily::MacOS if (freq_hz - 1000.0).abs() < 50.0 => 1.0,
            _ => 0.5,
        }
    }

    /// Calculate confidence distribution
    fn calculate_confidence_distribution(&self, scores: &[FuzzyScore]) -> ConfidenceDistribution {
        let mut dist = ConfidenceDistribution {
            certain: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        
        for score in scores {
            if score.total_score >= 0.90 {
                dist.certain += 1;
            } else if score.total_score >= 0.75 {
                dist.high += 1;
            } else if score.total_score >= 0.50 {
                dist.medium += 1;
            } else {
                dist.low += 1;
            }
        }
        
        dist
    }

    /// Calculate feature coverage
    fn calculate_feature_coverage(&self, fingerprint: &OsFingerprint) -> FeatureCoverage {
        FeatureCoverage {
            has_tcp: fingerprint.tcp_fingerprint.is_some(),
            has_icmp: fingerprint.icmp_fingerprint.is_some(),
            has_udp: fingerprint.udp_fingerprint.is_some(),
            has_protocol_hints: fingerprint.protocol_hints.is_some(),
            has_clock_skew: fingerprint.clock_skew.is_some(),
            has_passive: fingerprint.passive_fingerprint.is_some(),
            has_active_probes: fingerprint.active_probes.is_some(),
            total_techniques: [
                fingerprint.tcp_fingerprint.is_some(),
                fingerprint.icmp_fingerprint.is_some(),
                fingerprint.udp_fingerprint.is_some(),
                fingerprint.protocol_hints.is_some(),
                fingerprint.clock_skew.is_some(),
                fingerprint.passive_fingerprint.is_some(),
                fingerprint.active_probes.is_some(),
            ].iter().filter(|&&x| x).count(),
        }
    }
}

/// Detailed match result with all analysis data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedMatchResult {
    pub target: std::net::IpAddr,
    pub total_signatures_checked: usize,
    pub matches_found: usize,
    pub best_match: Option<FuzzyScore>,
    pub closest_matches: Vec<FuzzyScore>,
    pub match_scores: Vec<FuzzyScore>,
    pub confidence_distribution: ConfidenceDistribution,
    pub feature_coverage: FeatureCoverage,
}

/// Fuzzy score with detailed breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyScore {
    pub signature_name: String,
    pub signature_version: Option<String>,
    pub os_family: OsFamily,
    pub total_score: f64,
    pub raw_score: f64,
    pub confidence_weight: f64,
    pub score_breakdown: ScoreBreakdown,
    pub matched_features: Vec<String>,
    pub mismatched_features: Vec<String>,
}

/// Score breakdown by technique
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub tcp_score: Option<f64>,
    pub icmp_score: Option<f64>,
    pub udp_score: Option<f64>,
    pub protocol_score: Option<f64>,
    pub clock_skew_score: Option<f64>,
}

/// Confidence distribution across matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceDistribution {
    pub certain: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Feature coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureCoverage {
    pub has_tcp: bool,
    pub has_icmp: bool,
    pub has_udp: bool,
    pub has_protocol_hints: bool,
    pub has_clock_skew: bool,
    pub has_passive: bool,
    pub has_active_probes: bool,
    pub total_techniques: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzy_matcher_creation() {
        let db = OsFingerprintDatabase::new();
        let matcher = FuzzyMatcher::new(db, 0.5);
        assert!(matcher.min_threshold == 0.5);
    }
}

