/// Adaptive throttling module for NrMAP
/// 
/// This module implements intelligent rate limiting that automatically adjusts
/// scan speed based on success/failure rates to optimize performance while
/// avoiding network congestion and rate limiting.

use crate::config::ThrottlingConfig;
use crate::error::ScanError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Result of a scan operation for throttling purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleScanResult {
    Success,
    Failure,
}

/// Adaptive throttle controller
/// 
/// Monitors scan results and dynamically adjusts the rate of operations
/// to maintain optimal performance while respecting network constraints.
pub struct AdaptiveThrottle {
    config: ThrottlingConfig,
    state: Arc<RwLock<ThrottleState>>,
}

#[derive(Debug, Clone)]
struct ThrottleState {
    current_pps: usize,
    results_window: Vec<ThrottleScanResult>,
    last_adjustment: Instant,
    total_requests: usize,
    total_successes: usize,
    total_failures: usize,
}

impl AdaptiveThrottle {
    /// Create a new adaptive throttle controller
    pub fn new(config: ThrottlingConfig, initial_pps: usize) -> Self {
        let initial_pps = initial_pps.clamp(config.window_size, usize::MAX);
        
        info!(
            "Initializing adaptive throttle: initial_pps={}, window_size={}",
            initial_pps, config.window_size
        );

        let window_size = config.window_size;
        
        Self {
            config,
            state: Arc::new(RwLock::new(ThrottleState {
                current_pps: initial_pps,
                results_window: Vec::with_capacity(window_size),
                last_adjustment: Instant::now(),
                total_requests: 0,
                total_successes: 0,
                total_failures: 0,
            })),
        }
    }

    /// Wait before sending the next packet (rate limiting)
    pub async fn wait(&self) -> crate::error::ScanResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let state = self.state.read().await;
        let pps = state.current_pps;
        drop(state);

        if pps == 0 {
            return Err(ScanError::RateLimitExceeded {
                message: "Rate has been throttled to zero".to_string(),
            });
        }

        // Calculate delay between packets
        let delay_micros = 1_000_000 / pps as u64;
        let delay = Duration::from_micros(delay_micros);

        sleep(delay).await;
        Ok(())
    }

    /// Record the result of a scan operation
    pub async fn record_result(&self, result: ThrottleScanResult) {
        if !self.config.enabled {
            return;
        }

        let mut state = self.state.write().await;

        // Update statistics
        state.total_requests += 1;
        match result {
            ThrottleScanResult::Success => state.total_successes += 1,
            ThrottleScanResult::Failure => state.total_failures += 1,
        }

        // Add to sliding window
        if state.results_window.len() >= self.config.window_size {
            state.results_window.remove(0);
        }
        state.results_window.push(result);

        // Check if it's time to adjust the rate
        let elapsed = state.last_adjustment.elapsed();
        if elapsed >= Duration::from_millis(self.config.adjustment_interval_ms) {
            self.adjust_rate(&mut state).await;
            state.last_adjustment = Instant::now();
        }
    }

    /// Adjust the rate based on recent success/failure ratio
    async fn adjust_rate(&self, state: &mut ThrottleState) {
        if state.results_window.is_empty() {
            return;
        }

        let success_count = state
            .results_window
            .iter()
            .filter(|&&r| r == ThrottleScanResult::Success)
            .count();
        
        let success_rate = success_count as f64 / state.results_window.len() as f64;
        let old_pps = state.current_pps;

        if success_rate >= self.config.success_threshold {
            // High success rate: increase speed
            let new_pps = (state.current_pps as f64 * self.config.rate_increase_factor) as usize;
            state.current_pps = new_pps.min(1_000_000); // Absolute max cap
            
            debug!(
                old_pps = old_pps,
                new_pps = state.current_pps,
                success_rate = success_rate,
                "Increasing scan rate (high success rate)"
            );
            
            crate::log_rate_limit!(state.current_pps, success_rate, "increase");
        } else if success_rate <= self.config.failure_threshold {
            // Low success rate: decrease speed
            let new_pps = (state.current_pps as f64 * self.config.rate_decrease_factor) as usize;
            state.current_pps = new_pps.max(10); // Minimum 10 pps
            
            warn!(
                old_pps = old_pps,
                new_pps = state.current_pps,
                success_rate = success_rate,
                "Decreasing scan rate (low success rate)"
            );
            
            crate::log_rate_limit!(state.current_pps, success_rate, "decrease");
        }
    }

    /// Get current packets per second rate
    pub async fn current_pps(&self) -> usize {
        self.state.read().await.current_pps
    }

    /// Get statistics about throttling performance
    pub async fn get_stats(&self) -> ThrottleStats {
        let state = self.state.read().await;
        let success_rate = if state.total_requests > 0 {
            state.total_successes as f64 / state.total_requests as f64
        } else {
            0.0
        };

        ThrottleStats {
            current_pps: state.current_pps,
            total_requests: state.total_requests,
            total_successes: state.total_successes,
            total_failures: state.total_failures,
            success_rate,
        }
    }

    /// Manually set the rate (for testing or manual control)
    pub async fn set_rate(&self, pps: usize) {
        let mut state = self.state.write().await;
        state.current_pps = pps;
        info!("Manually set rate to {} pps", pps);
    }

    /// Reset throttle statistics
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        state.results_window.clear();
        state.total_requests = 0;
        state.total_successes = 0;
        state.total_failures = 0;
        info!("Throttle statistics reset");
    }
}

/// Statistics about throttle performance
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThrottleStats {
    pub current_pps: usize,
    pub total_requests: usize,
    pub total_successes: usize,
    pub total_failures: usize,
    pub success_rate: f64,
}

impl std::fmt::Display for ThrottleStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Throttle Stats: {} pps, {}/{} requests ({:.2}% success)",
            self.current_pps,
            self.total_successes,
            self.total_requests,
            self.success_rate * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ThrottlingConfig {
        ThrottlingConfig {
            enabled: true,
            success_threshold: 0.95,
            failure_threshold: 0.80,
            rate_increase_factor: 1.5,
            rate_decrease_factor: 0.5,
            window_size: 10,
            adjustment_interval_ms: 100,
        }
    }

    #[tokio::test]
    async fn test_throttle_creation() {
        let config = create_test_config();
        let throttle = AdaptiveThrottle::new(config, 1000);
        
        let pps = throttle.current_pps().await;
        assert_eq!(pps, 1000);
    }

    #[tokio::test]
    async fn test_record_result() {
        let config = create_test_config();
        let throttle = AdaptiveThrottle::new(config, 1000);
        
        throttle.record_result(ThrottleScanResult::Success).await;
        throttle.record_result(ThrottleScanResult::Failure).await;
        
        let stats = throttle.get_stats().await;
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.total_successes, 1);
        assert_eq!(stats.total_failures, 1);
    }

    #[tokio::test]
    async fn test_rate_increase() {
        let config = create_test_config();
        let throttle = AdaptiveThrottle::new(config, 1000);
        
        // Record many successes to trigger rate increase
        for _ in 0..15 {
            throttle.record_result(ThrottleScanResult::Success).await;
        }
        
        // Wait for adjustment interval
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        throttle.record_result(ThrottleScanResult::Success).await;
        
        let stats = throttle.get_stats().await;
        // Rate should have increased
        assert!(stats.current_pps > 1000);
    }

    #[tokio::test]
    async fn test_rate_decrease() {
        let config = create_test_config();
        let throttle = AdaptiveThrottle::new(config, 1000);
        
        // Record many failures to trigger rate decrease
        for _ in 0..15 {
            throttle.record_result(ThrottleScanResult::Failure).await;
        }
        
        // Wait for adjustment interval
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        throttle.record_result(ThrottleScanResult::Failure).await;
        
        let stats = throttle.get_stats().await;
        // Rate should have decreased
        assert!(stats.current_pps < 1000);
    }

    #[tokio::test]
    async fn test_manual_rate_set() {
        let config = create_test_config();
        let throttle = AdaptiveThrottle::new(config, 1000);
        
        throttle.set_rate(5000).await;
        let pps = throttle.current_pps().await;
        assert_eq!(pps, 5000);
    }

    #[tokio::test]
    async fn test_reset() {
        let config = create_test_config();
        let throttle = AdaptiveThrottle::new(config, 1000);
        
        throttle.record_result(ThrottleScanResult::Success).await;
        throttle.record_result(ThrottleScanResult::Failure).await;
        
        throttle.reset().await;
        
        let stats = throttle.get_stats().await;
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_successes, 0);
        assert_eq!(stats.total_failures, 0);
    }
}

