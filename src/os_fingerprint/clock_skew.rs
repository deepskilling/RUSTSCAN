//! Clock Skew Analysis Module
//!
//! This module implements TCP timestamp-based clock skew analysis for OS fingerprinting.
//! Clock skew analysis examines the rate at which a remote system's TCP timestamp counter
//! increments, which can reveal information about the underlying operating system and hardware.

use crate::error::{ScanResult, ScanError};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Represents a TCP timestamp measurement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampMeasurement {
    /// The TCP timestamp value from the remote host
    pub remote_timestamp: u32,
    /// The local time when this measurement was taken (as Unix timestamp in microseconds)
    pub local_time_us: u64,
    /// The sequence number of the packet (for ordering)
    pub sequence: u32,
}

/// Represents the clock skew analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSkewAnalysis {
    /// The target IP address
    pub target: IpAddr,
    /// Collected timestamp measurements
    pub measurements: Vec<TimestampMeasurement>,
    /// Estimated clock skew in parts per million (ppm)
    pub skew_ppm: Option<f64>,
    /// Clock frequency estimate in Hz
    pub clock_frequency_hz: Option<f64>,
    /// Standard deviation of the skew estimate
    pub skew_std_dev: Option<f64>,
    /// OS classification hints based on clock behavior
    pub os_hints: Vec<String>,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
}

/// Clock skew analyzer
pub struct ClockSkewAnalyzer {
    /// Minimum number of samples needed for analysis
    min_samples: usize,
    /// Maximum time window for collecting samples (seconds)
    max_collection_time: u64,
}

impl ClockSkewAnalyzer {
    /// Creates a new clock skew analyzer
    pub fn new() -> Self {
        Self {
            min_samples: 10,
            max_collection_time: 30,
        }
    }

    /// Collects TCP timestamp deltas from a target
    ///
    /// This function sends multiple probes to the target and collects TCP timestamp
    /// values to build a dataset for skew analysis.
    pub async fn collect_timestamps(
        &self,
        target: IpAddr,
        port: u16,
        num_samples: usize,
    ) -> ScanResult<Vec<TimestampMeasurement>> {
        info!("Collecting TCP timestamps from {}:{}", target, port);
        
        let mut measurements = Vec::new();
        let start_time = SystemTime::now();
        
        for i in 0..num_samples {
            // Check if we've exceeded the maximum collection time
            if let Ok(elapsed) = start_time.elapsed() {
                if elapsed.as_secs() > self.max_collection_time {
                    warn!("Timestamp collection exceeded time limit, stopping early");
                    break;
                }
            }
            
            // In a real implementation, this would send a TCP SYN packet
            // and extract the timestamp from the SYN-ACK response
            match self.probe_and_extract_timestamp(target, port, i as u32).await {
                Ok(measurement) => {
                    debug!("Collected timestamp: {:?}", measurement);
                    measurements.push(measurement);
                }
                Err(e) => {
                    warn!("Failed to collect timestamp: {}", e);
                }
            }
            
            // Add a small delay between probes
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        if measurements.len() < self.min_samples {
            return Err(ScanError::InsufficientData {
                required: self.min_samples,
                available: measurements.len(),
            });
        }
        
        info!("Collected {} timestamp measurements", measurements.len());
        Ok(measurements)
    }

    /// Probes a target and extracts the TCP timestamp
    ///
    /// This is a placeholder implementation. In a real system, this would:
    /// 1. Send a TCP SYN packet with timestamp option
    /// 2. Receive the SYN-ACK response
    /// 3. Extract the timestamp value from the TCP options
    async fn probe_and_extract_timestamp(
        &self,
        _target: IpAddr,
        _port: u16,
        sequence: u32,
    ) -> ScanResult<TimestampMeasurement> {
        // Simulate timestamp collection (in real implementation, would use raw sockets)
        let local_time_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        
        // Simulate a remote timestamp (in real implementation, extracted from packet)
        let remote_timestamp = (local_time_us / 1000) as u32 + sequence * 100;
        
        Ok(TimestampMeasurement {
            remote_timestamp,
            local_time_us,
            sequence,
        })
    }

    /// Estimates the clock skew from collected measurements
    ///
    /// This uses a linear regression approach to estimate the clock skew.
    /// The skew is calculated as the deviation from the expected 1:1 relationship
    /// between local time and remote timestamps.
    pub fn estimate_skew(
        &self,
        measurements: &[TimestampMeasurement],
    ) -> ScanResult<(f64, f64, f64)> {
        if measurements.len() < self.min_samples {
            return Err(ScanError::InsufficientData {
                required: self.min_samples,
                available: measurements.len(),
            });
        }
        
        debug!("Estimating clock skew from {} measurements", measurements.len());
        
        // Perform linear regression: y = mx + b
        // where y = remote_timestamp, x = local_time
        let n = measurements.len() as f64;
        
        let sum_x: f64 = measurements.iter().map(|m| m.local_time_us as f64).sum();
        let sum_y: f64 = measurements.iter().map(|m| m.remote_timestamp as f64).sum();
        let sum_xy: f64 = measurements.iter()
            .map(|m| (m.local_time_us as f64) * (m.remote_timestamp as f64))
            .sum();
        let sum_xx: f64 = measurements.iter()
            .map(|m| (m.local_time_us as f64).powi(2))
            .sum();
        
        // Calculate slope (m) - this represents the clock frequency ratio
        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x.powi(2));
        
        // Calculate intercept (b)
        let intercept = (sum_y - slope * sum_x) / n;
        
        // Calculate standard deviation of residuals
        let residuals: Vec<f64> = measurements.iter()
            .map(|m| {
                let predicted = slope * (m.local_time_us as f64) + intercept;
                let actual = m.remote_timestamp as f64;
                actual - predicted
            })
            .collect();
        
        let mean_residual = residuals.iter().sum::<f64>() / n;
        let variance = residuals.iter()
            .map(|r| (r - mean_residual).powi(2))
            .sum::<f64>() / n;
        let std_dev = variance.sqrt();
        
        // Convert slope to parts per million (ppm)
        // Expected slope is 1.0 (perfect clock sync), deviation indicates skew
        let skew_ppm = (slope - 1.0) * 1_000_000.0;
        
        // Estimate clock frequency (assuming microsecond timestamps)
        let clock_frequency_hz = slope * 1_000_000.0;
        
        info!(
            "Clock skew estimate: {:.2} ppm, frequency: {:.2} Hz, std_dev: {:.2}",
            skew_ppm, clock_frequency_hz, std_dev
        );
        
        Ok((skew_ppm, clock_frequency_hz, std_dev))
    }

    /// Classifies the OS based on clock behavior characteristics
    ///
    /// Different operating systems have different clock update frequencies and behaviors:
    /// - Linux: typically 100 Hz, 250 Hz, or 1000 Hz depending on kernel config
    /// - Windows: typically 10 ms (100 Hz) or 15.6 ms (64 Hz)
    /// - BSD: typically 100 Hz or 1000 Hz
    /// - macOS: typically 1000 Hz
    pub fn classify_os_by_clock(
        &self,
        skew_ppm: f64,
        clock_frequency_hz: f64,
        std_dev: f64,
    ) -> Vec<String> {
        let mut hints = Vec::new();
        
        // Classify based on clock frequency
        if (clock_frequency_hz - 1000.0).abs() < 50.0 {
            hints.push("Linux (HZ=1000) or macOS".to_string());
        } else if (clock_frequency_hz - 250.0).abs() < 25.0 {
            hints.push("Linux (HZ=250)".to_string());
        } else if (clock_frequency_hz - 100.0).abs() < 10.0 {
            hints.push("Linux (HZ=100), Windows, or BSD".to_string());
        } else if (clock_frequency_hz - 64.0).abs() < 5.0 {
            hints.push("Windows (legacy timer)".to_string());
        }
        
        // Classify based on skew stability
        if std_dev < 100.0 {
            hints.push("Stable clock (server-grade hardware)".to_string());
        } else if std_dev > 1000.0 {
            hints.push("Unstable clock (virtualized or embedded system)".to_string());
        }
        
        // Classify based on skew magnitude
        if skew_ppm.abs() < 10.0 {
            hints.push("Well-synchronized clock (NTP enabled)".to_string());
        } else if skew_ppm.abs() > 100.0 {
            hints.push("Poorly synchronized clock".to_string());
        }
        
        debug!("OS classification hints: {:?}", hints);
        hints
    }

    /// Performs a complete clock skew analysis
    pub async fn analyze(
        &self,
        target: IpAddr,
        port: u16,
        num_samples: usize,
    ) -> ScanResult<ClockSkewAnalysis> {
        info!("Starting clock skew analysis for {}", target);
        
        // Collect timestamp measurements
        let measurements = self.collect_timestamps(target, port, num_samples).await?;
        
        // Estimate clock skew
        let (skew_ppm, clock_frequency_hz, std_dev) = self.estimate_skew(&measurements)?;
        
        // Classify OS based on clock behavior
        let os_hints = self.classify_os_by_clock(skew_ppm, clock_frequency_hz, std_dev);
        
        // Calculate confidence based on standard deviation and sample count
        let confidence = self.calculate_confidence(std_dev, measurements.len());
        
        Ok(ClockSkewAnalysis {
            target,
            measurements,
            skew_ppm: Some(skew_ppm),
            clock_frequency_hz: Some(clock_frequency_hz),
            skew_std_dev: Some(std_dev),
            os_hints,
            confidence,
        })
    }

    /// Calculates confidence score based on measurement quality
    fn calculate_confidence(&self, std_dev: f64, sample_count: usize) -> f64 {
        // Base confidence on standard deviation (lower is better)
        let std_dev_factor = 1.0 / (1.0 + (std_dev / 100.0));
        
        // Bonus for more samples
        let sample_factor = (sample_count as f64 / 30.0).min(1.0);
        
        // Combine factors
        (std_dev_factor * 0.7 + sample_factor * 0.3).min(1.0).max(0.0)
    }
}

impl Default for ClockSkewAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clock_skew_collection() {
        let analyzer = ClockSkewAnalyzer::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let result = analyzer.collect_timestamps(target, 80, 15).await;
        assert!(result.is_ok());
        
        let measurements = result.unwrap();
        assert!(measurements.len() >= 10);
    }

    #[test]
    fn test_skew_estimation() {
        let analyzer = ClockSkewAnalyzer::new();
        
        // Create synthetic measurements with known skew
        let base_time = 1000000u64;
        let measurements: Vec<TimestampMeasurement> = (0..20)
            .map(|i| {
                let local_time_us = base_time + i * 100000;
                let remote_timestamp = ((local_time_us as f64) * 1.00001) as u32; // 10 ppm skew
                TimestampMeasurement {
                    remote_timestamp,
                    local_time_us,
                    sequence: i as u32,
                }
            })
            .collect();
        
        let result = analyzer.estimate_skew(&measurements);
        assert!(result.is_ok());
        
        let (skew_ppm, _freq, _std_dev) = result.unwrap();
        // Should be close to 10 ppm (with some tolerance for numerical precision)
        assert!((skew_ppm - 10.0).abs() < 5.0);
    }

    #[test]
    fn test_os_classification() {
        let analyzer = ClockSkewAnalyzer::new();
        
        // Test Linux HZ=1000
        let hints = analyzer.classify_os_by_clock(5.0, 1000.0, 50.0);
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.contains("Linux") || h.contains("macOS")));
        
        // Test Windows
        let hints = analyzer.classify_os_by_clock(5.0, 100.0, 50.0);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_confidence_calculation() {
        let analyzer = ClockSkewAnalyzer::new();
        
        // High confidence: low std_dev, many samples
        let conf1 = analyzer.calculate_confidence(50.0, 30);
        assert!(conf1 > 0.7 && conf1 < 0.9); // Should be around 0.77
        
        // Medium confidence: medium std_dev, medium samples
        let conf2 = analyzer.calculate_confidence(200.0, 15);
        assert!(conf2 > 0.3 && conf2 < 0.5);
        
        // Low confidence: high std_dev, few samples
        let conf3 = analyzer.calculate_confidence(500.0, 10);
        assert!(conf3 < 0.4);
    }
}

