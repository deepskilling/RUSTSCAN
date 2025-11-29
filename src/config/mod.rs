/// Configuration module for NrMAP
/// 
/// This module handles loading and validating the single configuration file (config.toml)
/// that controls all aspects of the scanner behavior.

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub logging: LoggingConfig,
    pub scanner: ScannerConfig,
    pub throttling: ThrottlingConfig,
    pub output: OutputConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub app_name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_logging: bool,
    pub log_dir: String,
    pub max_file_size: usize,
    pub max_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub default_timeout_ms: u64,
    pub max_concurrent_scans: usize,
    pub adaptive_throttling: bool,
    pub initial_pps: usize,
    pub max_pps: usize,
    pub min_pps: usize,
    pub host_discovery: HostDiscoveryConfig,
    pub tcp_connect: TcpConnectConfig,
    pub tcp_syn: TcpSynConfig,
    pub udp: UdpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDiscoveryConfig {
    pub enabled: bool,
    pub method: String,
    pub timeout_ms: u64,
    pub retries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnectConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub retries: usize,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSynConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub retries: usize,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub retries: usize,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottlingConfig {
    pub enabled: bool,
    pub success_threshold: f64,
    pub failure_threshold: f64,
    pub rate_increase_factor: f64,
    pub rate_decrease_factor: f64,
    pub window_size: usize,
    pub adjustment_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub output_dir: String,
    pub include_timestamps: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub require_privileges_check: bool,
    pub max_targets: usize,
    pub max_ports: usize,
}

impl AppConfig {
    /// Load configuration from a TOML file
    /// 
    /// # Arguments
    /// * `path` - Path to the configuration file
    /// 
    /// # Returns
    /// * `Result<AppConfig, ConfigError>` - Loaded configuration or error
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path_str = path.as_ref().display().to_string();
        debug!("Loading configuration from: {}", path_str);

        let config = Config::builder()
            .add_source(File::with_name(&path_str))
            .build()?;

        let app_config: AppConfig = config.try_deserialize()?;
        
        info!("Configuration loaded successfully from: {}", path_str);
        app_config.validate()?;
        
        Ok(app_config)
    }

    /// Load configuration with a default fallback
    /// 
    /// Attempts to load from the specified path, or uses default config if not found
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        match Self::from_file(&path) {
            Ok(config) => Ok(config),
            Err(e) => {
                debug!("Failed to load config from file: {}. Using defaults.", e);
                Ok(Self::default())
            }
        }
    }

    /// Validate configuration values
    /// 
    /// Ensures all configuration values are within acceptable ranges
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate logging level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            return Err(ConfigError::Message(
                format!("Invalid logging level: {}. Must be one of: {:?}", 
                    self.logging.level, valid_levels)
            ));
        }

        // Validate logging format
        let valid_formats = ["text", "json"];
        if !valid_formats.contains(&self.logging.format.as_str()) {
            return Err(ConfigError::Message(
                format!("Invalid logging format: {}. Must be one of: {:?}", 
                    self.logging.format, valid_formats)
            ));
        }

        // Validate scanner PPS rates
        if self.scanner.min_pps >= self.scanner.max_pps {
            return Err(ConfigError::Message(
                "min_pps must be less than max_pps".to_string()
            ));
        }

        if self.scanner.initial_pps < self.scanner.min_pps 
            || self.scanner.initial_pps > self.scanner.max_pps {
            return Err(ConfigError::Message(
                "initial_pps must be between min_pps and max_pps".to_string()
            ));
        }

        // Validate throttling thresholds
        if self.throttling.success_threshold <= self.throttling.failure_threshold {
            return Err(ConfigError::Message(
                "success_threshold must be greater than failure_threshold".to_string()
            ));
        }

        if self.throttling.success_threshold < 0.0 || self.throttling.success_threshold > 1.0 {
            return Err(ConfigError::Message(
                "success_threshold must be between 0.0 and 1.0".to_string()
            ));
        }

        if self.throttling.failure_threshold < 0.0 || self.throttling.failure_threshold > 1.0 {
            return Err(ConfigError::Message(
                "failure_threshold must be between 0.0 and 1.0".to_string()
            ));
        }

        // Validate output format
        let valid_output_formats = ["json", "yaml", "text"];
        if !valid_output_formats.contains(&self.output.format.as_str()) {
            return Err(ConfigError::Message(
                format!("Invalid output format: {}. Must be one of: {:?}", 
                    self.output.format, valid_output_formats)
            ));
        }

        info!("Configuration validation successful");
        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                app_name: "NrMAP".to_string(),
                version: "0.1.0".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "text".to_string(),
                file_logging: true,
                log_dir: "./logs".to_string(),
                max_file_size: 10,
                max_files: 5,
            },
            scanner: ScannerConfig {
                default_timeout_ms: 5000,
                max_concurrent_scans: 1000,
                adaptive_throttling: true,
                initial_pps: 1000,
                max_pps: 10000,
                min_pps: 100,
                host_discovery: HostDiscoveryConfig {
                    enabled: true,
                    method: "icmp".to_string(),
                    timeout_ms: 3000,
                    retries: 2,
                },
                tcp_connect: TcpConnectConfig {
                    enabled: true,
                    timeout_ms: 5000,
                    retries: 1,
                    retry_delay_ms: 100,
                },
                tcp_syn: TcpSynConfig {
                    enabled: true,
                    timeout_ms: 3000,
                    retries: 2,
                    retry_delay_ms: 50,
                },
                udp: UdpConfig {
                    enabled: true,
                    timeout_ms: 5000,
                    retries: 3,
                    retry_delay_ms: 200,
                },
            },
            throttling: ThrottlingConfig {
                enabled: true,
                success_threshold: 0.95,
                failure_threshold: 0.80,
                rate_increase_factor: 1.5,
                rate_decrease_factor: 0.5,
                window_size: 100,
                adjustment_interval_ms: 1000,
            },
            output: OutputConfig {
                format: "json".to_string(),
                output_dir: "./results".to_string(),
                include_timestamps: true,
                verbose: false,
            },
            security: SecurityConfig {
                require_privileges_check: true,
                max_targets: 65536,
                max_ports: 65535,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.general.app_name, "NrMAP");
        assert_eq!(config.scanner.max_concurrent_scans, 1000);
    }

    #[test]
    fn test_config_validation() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_pps_config() {
        let mut config = AppConfig::default();
        config.scanner.min_pps = 10000;
        config.scanner.max_pps = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");
        
        let config_content = r#"
[general]
app_name = "TestApp"
version = "1.0.0"

[logging]
level = "debug"
format = "json"
file_logging = false
log_dir = "./test_logs"
max_file_size = 5
max_files = 3

[scanner]
default_timeout_ms = 3000
max_concurrent_scans = 500
adaptive_throttling = false
initial_pps = 500
max_pps = 5000
min_pps = 50

[scanner.host_discovery]
enabled = true
method = "tcp"
timeout_ms = 2000
retries = 1

[scanner.tcp_connect]
enabled = true
timeout_ms = 3000
retries = 2
retry_delay_ms = 50

[scanner.tcp_syn]
enabled = false
timeout_ms = 2000
retries = 1
retry_delay_ms = 25

[scanner.udp]
enabled = false
timeout_ms = 4000
retries = 2
retry_delay_ms = 100

[throttling]
enabled = false
success_threshold = 0.9
failure_threshold = 0.7
rate_increase_factor = 2.0
rate_decrease_factor = 0.7
window_size = 50
adjustment_interval_ms = 500

[output]
format = "yaml"
output_dir = "./test_results"
include_timestamps = false
verbose = true

[security]
require_privileges_check = false
max_targets = 1000
max_ports = 10000
"#;
        
        fs::write(&config_path, config_content).unwrap();
        
        let config = AppConfig::from_file(&config_path).unwrap();
        assert_eq!(config.general.app_name, "TestApp");
        assert_eq!(config.scanner.max_concurrent_scans, 500);
        assert_eq!(config.logging.level, "debug");
    }
}

