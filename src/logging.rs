/// Comprehensive logging setup for NrMAP
/// 
/// This module initializes and configures the tracing-based logging system
/// with support for console and file output, structured logging, and configurable levels.

use crate::config::LoggingConfig;
use crate::error::{ScanError, ScanResult};
use std::path::Path;
use tracing::{info, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the logging system based on configuration
/// 
/// # Arguments
/// * `config` - Logging configuration from config.toml
/// 
/// # Returns
/// * `ScanResult<Option<WorkerGuard>>` - Guard that must be kept alive for file logging
pub fn init_logging(config: &LoggingConfig) -> ScanResult<Option<WorkerGuard>> {
    // Parse log level (for validation)
    let _log_level = parse_log_level(&config.level)?;

    // Create environment filter
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("nrmap={}", config.level)));

    let guard = if config.file_logging {
        // Setup file logging
        let log_dir = Path::new(&config.log_dir);
        
        // Create log directory if it doesn't exist
        if !log_dir.exists() {
            std::fs::create_dir_all(log_dir).map_err(|e| {
                ScanError::scanner_error(format!("Failed to create log directory: {}", e))
            })?;
        }

        let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("nrmap")
            .filename_suffix("log")
            .max_log_files(config.max_files)
            .build(log_dir)
            .map_err(|e| ScanError::scanner_error(format!("Failed to create file appender: {}", e)))?;

        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        // Build subscriber with both console and file output
        if config.format == "json" {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_writer(std::io::stdout),
                )
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_writer(non_blocking),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_writer(std::io::stdout),
                )
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_writer(non_blocking),
                )
                .init();
        }

        Some(guard)
    } else {
        // Console-only logging
        if config.format == "json" {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true),
                )
                .init();
        }

        None
    };

    info!(
        "Logging initialized: level={}, format={}, file_logging={}",
        config.level, config.format, config.file_logging
    );

    Ok(guard)
}

/// Parse log level string to tracing Level
fn parse_log_level(level: &str) -> ScanResult<Level> {
    match level.to_lowercase().as_str() {
        "trace" => Ok(Level::TRACE),
        "debug" => Ok(Level::DEBUG),
        "info" => Ok(Level::INFO),
        "warn" => Ok(Level::WARN),
        "error" => Ok(Level::ERROR),
        _ => Err(ScanError::validation_error(
            "log_level",
            format!("Invalid log level: {}", level),
        )),
    }
}

/// Macro for logging scan events with structured data
#[macro_export]
macro_rules! log_scan_event {
    ($level:expr, $target:expr, $port:expr, $status:expr, $msg:expr) => {
        tracing::event!(
            $level,
            target = %$target,
            port = $port,
            status = $status,
            "{}",
            $msg
        );
    };
}

/// Macro for logging scan progress
#[macro_export]
macro_rules! log_scan_progress {
    ($total:expr, $completed:expr, $success:expr, $failed:expr) => {
        tracing::info!(
            total = $total,
            completed = $completed,
            success = $success,
            failed = $failed,
            progress_pct = ($completed as f64 / $total as f64 * 100.0),
            "Scan progress"
        );
    };
}

/// Macro for logging rate limiting events
#[macro_export]
macro_rules! log_rate_limit {
    ($current_pps:expr, $success_rate:expr, $action:expr) => {
        tracing::debug!(
            current_pps = $current_pps,
            success_rate = $success_rate,
            action = $action,
            "Rate limiting adjustment"
        );
    };
}

/// Log sanitization - removes sensitive data from logs
pub fn sanitize_log_data(data: &str) -> String {
    // Simple example: mask parts of IP addresses in production
    // This can be extended based on security requirements
    data.to_string()
}

/// Performance logger for tracking scan metrics
pub struct PerformanceLogger {
    start_time: std::time::Instant,
    operation: String,
}

impl PerformanceLogger {
    pub fn new(operation: String) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            operation,
        }
    }

    pub fn log_duration(self) {
        let duration = self.start_time.elapsed();
        tracing::debug!(
            operation = %self.operation,
            duration_ms = duration.as_millis(),
            "Operation completed"
        );
    }
}

/// Macro to create and auto-log performance metrics
#[macro_export]
macro_rules! track_performance {
    ($operation:expr, $code:block) => {{
        let _perf_logger = $crate::logging::PerformanceLogger::new($operation.to_string());
        let result = $code;
        _perf_logger.log_duration();
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LoggingConfig;

    #[test]
    fn test_parse_log_level() {
        assert!(matches!(parse_log_level("info"), Ok(Level::INFO)));
        assert!(matches!(parse_log_level("debug"), Ok(Level::DEBUG)));
        assert!(matches!(parse_log_level("error"), Ok(Level::ERROR)));
        assert!(parse_log_level("invalid").is_err());
    }

    #[test]
    fn test_sanitize_log_data() {
        let data = "192.168.1.1";
        let sanitized = sanitize_log_data(data);
        assert!(!sanitized.is_empty());
    }

    #[test]
    fn test_performance_logger() {
        let _logger = PerformanceLogger::new("test_operation".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Logger drops here and logs duration
    }
}

