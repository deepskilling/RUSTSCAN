/// Comprehensive error handling for NrMAP
/// 
/// This module defines all custom error types and implements proper error handling
/// throughout the application using thiserror for ergonomic error definitions.

use std::net::IpAddr;
use thiserror::Error;
use tracing::error;

/// Main error type for the NrMAP scanner
#[derive(Error, Debug)]
pub enum ScanError {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Network errors
    #[error("Network error: {message}")]
    Network { message: String },

    /// Timeout errors
    #[error("Timeout error: operation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    /// Permission errors (for raw socket operations)
    #[error("Permission denied: {operation} requires elevated privileges")]
    PermissionDenied { operation: String },

    /// Invalid target errors
    #[error("Invalid target: {target} - {reason}")]
    InvalidTarget { target: String, reason: String },

    /// Invalid port errors
    #[error("Invalid port: {port} - {reason}")]
    InvalidPort { port: u16, reason: String },

    /// Port range errors
    #[error("Invalid port range: {start}-{end}")]
    InvalidPortRange { start: u16, end: u16 },

    /// Host discovery errors
    #[error("Host discovery failed for {target}: {reason}")]
    HostDiscoveryFailed { target: IpAddr, reason: String },

    /// TCP scan errors
    #[error("TCP scan failed on {target}:{port} - {reason}")]
    TcpScanFailed {
        target: IpAddr,
        port: u16,
        reason: String,
    },

    /// UDP scan errors
    #[error("UDP scan failed on {target}:{port} - {reason}")]
    UdpScanFailed {
        target: IpAddr,
        port: u16,
        reason: String,
    },

    /// SYN scan errors
    #[error("SYN scan failed on {target}:{port} - {reason}")]
    SynScanFailed {
        target: IpAddr,
        port: u16,
        reason: String,
    },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimitExceeded { message: String },

    /// Resource exhaustion errors
    #[error("Resource exhausted: {resource} - {details}")]
    ResourceExhausted { resource: String, details: String },

    /// Packet crafting/parsing errors
    #[error("Packet error: {message}")]
    PacketError { message: String },

    /// Threading/async errors
    #[error("Concurrency error: {message}")]
    ConcurrencyError { message: String },

    /// Output/reporting errors
    #[error("Output error: {message}")]
    OutputError { message: String },

    /// Validation errors
    #[error("Validation error: {field} - {reason}")]
    ValidationError { field: String, reason: String },

    /// Generic scanner errors
    #[error("Scanner error: {message}")]
    ScannerError { message: String },

    /// Multiple errors aggregated
    #[error("Multiple errors occurred: {count} errors")]
    Multiple { count: usize, errors: Vec<String> },

    /// Insufficient data for analysis
    #[error("Insufficient data: required {required}, available {available}")]
    InsufficientData { required: usize, available: usize },

    /// Target not found in collected data
    #[error("Target not found: {target}")]
    TargetNotFound { target: IpAddr },
}

/// Result type alias for scanner operations
pub type ScanResult<T> = Result<T, ScanError>;

impl ScanError {
    /// Create a network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        ScanError::Network {
            message: message.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(timeout_ms: u64) -> Self {
        ScanError::Timeout { timeout_ms }
    }

    /// Create a permission denied error
    pub fn permission_denied<S: Into<String>>(operation: S) -> Self {
        ScanError::PermissionDenied {
            operation: operation.into(),
        }
    }

    /// Create an invalid target error
    pub fn invalid_target<S1: Into<String>, S2: Into<String>>(target: S1, reason: S2) -> Self {
        ScanError::InvalidTarget {
            target: target.into(),
            reason: reason.into(),
        }
    }

    /// Create a host discovery failed error
    pub fn host_discovery_failed<S: Into<String>>(target: IpAddr, reason: S) -> Self {
        ScanError::HostDiscoveryFailed {
            target,
            reason: reason.into(),
        }
    }

    /// Create a TCP scan failed error
    pub fn tcp_scan_failed<S: Into<String>>(target: IpAddr, port: u16, reason: S) -> Self {
        ScanError::TcpScanFailed {
            target,
            port,
            reason: reason.into(),
        }
    }

    /// Create a UDP scan failed error
    pub fn udp_scan_failed<S: Into<String>>(target: IpAddr, port: u16, reason: S) -> Self {
        ScanError::UdpScanFailed {
            target,
            port,
            reason: reason.into(),
        }
    }

    /// Create a SYN scan failed error
    pub fn syn_scan_failed<S: Into<String>>(target: IpAddr, port: u16, reason: S) -> Self {
        ScanError::SynScanFailed {
            target,
            port,
            reason: reason.into(),
        }
    }

    /// Create a packet error
    pub fn packet_error<S: Into<String>>(message: S) -> Self {
        ScanError::PacketError {
            message: message.into(),
        }
    }

    /// Create a scanner error
    pub fn scanner_error<S: Into<String>>(message: S) -> Self {
        ScanError::ScannerError {
            message: message.into(),
        }
    }

    /// Create a validation error
    pub fn validation_error<S1: Into<String>, S2: Into<String>>(field: S1, reason: S2) -> Self {
        ScanError::ValidationError {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Log this error with appropriate level and context
    pub fn log(&self) {
        match self {
            ScanError::PermissionDenied { .. } | ScanError::Config(_) => {
                error!("Critical error: {}", self);
            }
            ScanError::Timeout { .. }
            | ScanError::TcpScanFailed { .. }
            | ScanError::UdpScanFailed { .. }
            | ScanError::SynScanFailed { .. } => {
                tracing::warn!("Scan error: {}", self);
            }
            _ => {
                error!("Error: {}", self);
            }
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScanError::Timeout { .. }
                | ScanError::Network { .. }
                | ScanError::TcpScanFailed { .. }
                | ScanError::UdpScanFailed { .. }
                | ScanError::SynScanFailed { .. }
                | ScanError::RateLimitExceeded { .. }
        )
    }

    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ScanError::Config(_) | ScanError::PermissionDenied { .. } => ErrorSeverity::Critical,
            ScanError::Io(_)
            | ScanError::ResourceExhausted { .. }
            | ScanError::Multiple { .. } => ErrorSeverity::High,
            ScanError::Network { .. }
            | ScanError::InvalidTarget { .. }
            | ScanError::InvalidPort { .. }
            | ScanError::ValidationError { .. } => ErrorSeverity::Medium,
            ScanError::Timeout { .. }
            | ScanError::TcpScanFailed { .. }
            | ScanError::UdpScanFailed { .. }
            | ScanError::SynScanFailed { .. }
            | ScanError::HostDiscoveryFailed { .. } => ErrorSeverity::Low,
            _ => ErrorSeverity::Medium,
        }
    }
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "LOW"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Error context for debugging and reporting
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub error: String,
    pub severity: ErrorSeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: usize,
    pub additional_info: Option<String>,
}

impl ErrorContext {
    pub fn new(error: &ScanError) -> Self {
        Self {
            error: error.to_string(),
            severity: error.severity(),
            timestamp: chrono::Utc::now(),
            retry_count: 0,
            additional_info: None,
        }
    }

    pub fn with_retry_count(mut self, count: usize) -> Self {
        self.retry_count = count;
        self
    }

    pub fn with_info<S: Into<String>>(mut self, info: S) -> Self {
        self.additional_info = Some(info.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_error_creation() {
        let err = ScanError::network("Connection refused");
        assert!(matches!(err, ScanError::Network { .. }));
    }

    #[test]
    fn test_error_retryable() {
        let err = ScanError::timeout(5000);
        assert!(err.is_retryable());

        let err = ScanError::permission_denied("raw socket");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_severity() {
        let err = ScanError::Config(config::ConfigError::Message("test".to_string()));
        assert_eq!(err.severity(), ErrorSeverity::Critical);

        let err = ScanError::timeout(5000);
        assert_eq!(err.severity(), ErrorSeverity::Low);
    }

    #[test]
    fn test_tcp_scan_error() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let err = ScanError::tcp_scan_failed(ip, 80, "Connection refused");
        assert!(matches!(err, ScanError::TcpScanFailed { .. }));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_context() {
        let err = ScanError::network("Test error");
        let ctx = ErrorContext::new(&err)
            .with_retry_count(3)
            .with_info("Additional context");

        assert_eq!(ctx.retry_count, 3);
        assert!(ctx.additional_info.is_some());
        assert_eq!(ctx.severity, ErrorSeverity::Medium);
    }
}

