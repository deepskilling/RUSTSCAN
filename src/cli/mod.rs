/// CLI module for NrMAP
/// 
/// This module provides command-line interface functionality including
/// profiles and output formatting.

pub mod profiles;
pub mod output;

pub use profiles::{ScanProfile, PortSpec, TimingProfile};
pub use output::{OutputFormatter, OutputFormat, FormattedOutput};

use crate::error::ScanResult;
use tracing::info;

/// CLI configuration
#[derive(Debug, Clone)]
pub struct CliConfig {
    pub default_profile: String,
    pub default_output_format: OutputFormat,
    pub color_output: bool,
    pub verbose: bool,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            default_profile: "default".to_string(),
            default_output_format: OutputFormat::Text,
            color_output: true,
            verbose: false,
        }
    }
}

/// CLI coordinator
pub struct Cli {
    config: CliConfig,
    formatter: OutputFormatter,
}

impl Cli {
    /// Create a new CLI with configuration
    pub fn new(config: CliConfig) -> Self {
        info!("Initializing CLI");
        
        let formatter = OutputFormatter::new(config.default_output_format);
        
        Self { config, formatter }
    }

    /// Get a scan profile by name
    pub fn get_profile(&self, name: &str) -> ScanResult<ScanProfile> {
        ScanProfile::by_name(name).ok_or_else(|| {
            crate::error::ScanError::validation_error(
                "profile",
                format!("Unknown profile: {}", name),
            )
        })
    }

    /// List all available profiles
    pub fn list_profiles(&self) -> Vec<String> {
        ScanProfile::list_all()
    }

    /// Format output
    pub fn format_output<T: serde::Serialize>(
        &self,
        data: &T,
        format: Option<OutputFormat>,
    ) -> ScanResult<String> {
        let format = format.unwrap_or(self.config.default_output_format);
        self.formatter.format(data, format)
    }

    /// Get CLI configuration
    pub fn config(&self) -> &CliConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_config_default() {
        let config = CliConfig::default();
        assert_eq!(config.default_profile, "default");
        assert!(matches!(config.default_output_format, OutputFormat::Text));
    }

    #[test]
    fn test_cli_creation() {
        let config = CliConfig::default();
        let _cli = Cli::new(config);
    }

    #[test]
    fn test_get_profile() {
        let config = CliConfig::default();
        let cli = Cli::new(config);
        
        let profile = cli.get_profile("quick");
        assert!(profile.is_ok());
        
        let unknown = cli.get_profile("nonexistent");
        assert!(unknown.is_err());
    }

    #[test]
    fn test_list_profiles() {
        let config = CliConfig::default();
        let cli = Cli::new(config);
        
        let profiles = cli.list_profiles();
        assert!(!profiles.is_empty());
    }
}

