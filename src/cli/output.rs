/// Output formatting for CLI
/// 
/// This module provides multiple output formats for scan results including
/// JSON, YAML, and formatted text tables.

use crate::error::{ScanError, ScanResult};
use serde::Serialize;
use tracing::debug;

/// Output format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text format
    Text,
    /// JSON format
    Json,
    /// Pretty JSON format
    JsonPretty,
    /// YAML format (requires yaml feature)
    Yaml,
    /// Table format
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = ScanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "json-pretty" | "pretty" => Ok(OutputFormat::JsonPretty),
            "yaml" | "yml" => Ok(OutputFormat::Yaml),
            "table" | "tbl" => Ok(OutputFormat::Table),
            _ => Err(ScanError::validation_error(
                "output_format",
                format!("Unknown output format: {}", s),
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::JsonPretty => write!(f, "json-pretty"),
            OutputFormat::Yaml => write!(f, "yaml"),
            OutputFormat::Table => write!(f, "table"),
        }
    }
}

/// Formatted output container
#[derive(Debug, Clone)]
pub struct FormattedOutput {
    pub format: OutputFormat,
    pub content: String,
}

/// Output formatter
pub struct OutputFormatter {
    default_format: OutputFormat,
}

impl OutputFormatter {
    /// Create a new output formatter
    pub fn new(default_format: OutputFormat) -> Self {
        debug!("Creating output formatter with format: {}", default_format);
        Self { default_format }
    }

    /// Format data to string
    /// 
    /// # Arguments
    /// * `data` - Data to format (must implement Serialize)
    /// * `format` - Output format
    pub fn format<T: Serialize>(&self, data: &T, format: OutputFormat) -> ScanResult<String> {
        match format {
            OutputFormat::Text => self.format_text(data),
            OutputFormat::Json => self.format_json(data),
            OutputFormat::JsonPretty => self.format_json_pretty(data),
            OutputFormat::Yaml => self.format_yaml(data),
            OutputFormat::Table => self.format_table(data),
        }
    }

    /// Format as plain text (uses Debug formatting)
    fn format_text<T: Serialize>(&self, data: &T) -> ScanResult<String> {
        // For text format, use JSON serialization
        // In a real implementation, you'd want custom Display implementations
        serde_json::to_string_pretty(data).map_err(|e| {
            ScanError::OutputError {
                message: format!("Failed to serialize for text: {}", e),
            }
        })
    }

    /// Format as JSON
    fn format_json<T: Serialize>(&self, data: &T) -> ScanResult<String> {
        serde_json::to_string(data).map_err(|e| ScanError::OutputError {
            message: format!("Failed to serialize to JSON: {}", e),
        })
    }

    /// Format as pretty JSON
    fn format_json_pretty<T: Serialize>(&self, data: &T) -> ScanResult<String> {
        serde_json::to_string_pretty(data).map_err(|e| ScanError::OutputError {
            message: format!("Failed to serialize to pretty JSON: {}", e),
        })
    }

    /// Format as YAML
    fn format_yaml<T: Serialize>(&self, _data: &T) -> ScanResult<String> {
        // TODO: Implement YAML formatting (requires serde_yaml dependency)
        // For now, return a note
        Ok("# YAML output not yet implemented\n# Use JSON format instead\n".to_string())
    }

    /// Format as table
    fn format_table<T: Serialize>(&self, data: &T) -> ScanResult<String> {
        // Simple table formatting - convert to JSON first
        let json_str = serde_json::to_string_pretty(data).map_err(|e| {
            ScanError::OutputError {
                message: format!("Failed to serialize for table: {}", e),
            }
        })?;

        let mut output = String::new();
        output.push_str("╔═══════════════════════════════════════════╗\n");
        output.push_str("║           Scan Results                    ║\n");
        output.push_str("╠═══════════════════════════════════════════╣\n");
        output.push_str(&format!("║ {}║\n", json_str.replace('\n', "\n║ ")));
        output.push_str("╚═══════════════════════════════════════════╝\n");
        
        Ok(output)
    }

    /// Create formatted output
    pub fn create_output<T: Serialize>(
        &self,
        data: &T,
        format: Option<OutputFormat>,
    ) -> ScanResult<FormattedOutput> {
        let format = format.unwrap_or(self.default_format);
        let content = self.format(data, format)?;
        
        Ok(FormattedOutput { format, content })
    }
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self::new(OutputFormat::Text)
    }
}

/// Helper function to create a simple table
pub fn create_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut output = String::new();
    
    // Header
    output.push_str("╔");
    for (i, _) in headers.iter().enumerate() {
        output.push_str("═══════════════════");
        if i < headers.len() - 1 {
            output.push_str("╦");
        }
    }
    output.push_str("╗\n");
    
    // Header content
    output.push_str("║");
    for (i, header) in headers.iter().enumerate() {
        output.push_str(&format!(" {:17} ", header));
        if i < headers.len() - 1 {
            output.push_str("║");
        }
    }
    output.push_str("║\n");
    
    // Separator
    output.push_str("╠");
    for (i, _) in headers.iter().enumerate() {
        output.push_str("═══════════════════");
        if i < headers.len() - 1 {
            output.push_str("╬");
        }
    }
    output.push_str("╣\n");
    
    // Rows
    for row in rows {
        output.push_str("║");
        for (i, cell) in row.iter().enumerate() {
            output.push_str(&format!(" {:17} ", cell));
            if i < row.len() - 1 {
                output.push_str("║");
            }
        }
        output.push_str("║\n");
    }
    
    // Footer
    output.push_str("╚");
    for (i, _) in headers.iter().enumerate() {
        output.push_str("═══════════════════");
        if i < headers.len() - 1 {
            output.push_str("╩");
        }
    }
    output.push_str("╝\n");
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestData {
        name: String,
        value: i32,
    }

    #[test]
    fn test_output_format_from_str() {
        assert!(matches!(
            "json".parse::<OutputFormat>().unwrap(),
            OutputFormat::Json
        ));
        assert!(matches!(
            "yaml".parse::<OutputFormat>().unwrap(),
            OutputFormat::Yaml
        ));
        assert!("unknown".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(format!("{}", OutputFormat::Json), "json");
        assert_eq!(format!("{}", OutputFormat::Yaml), "yaml");
        assert_eq!(format!("{}", OutputFormat::Table), "table");
    }

    #[test]
    fn test_formatter_creation() {
        let formatter = OutputFormatter::new(OutputFormat::Json);
        assert_eq!(formatter.default_format, OutputFormat::Json);
    }

    #[test]
    fn test_format_json() {
        let formatter = OutputFormatter::new(OutputFormat::Json);
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };
        
        let result = formatter.format(&data, OutputFormat::Json);
        assert!(result.is_ok());
        
        let json = result.unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_format_json_pretty() {
        let formatter = OutputFormatter::new(OutputFormat::Json);
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };
        
        let result = formatter.format(&data, OutputFormat::JsonPretty);
        assert!(result.is_ok());
        
        let json = result.unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("\n")); // Pretty formatting includes newlines
    }

    #[test]
    fn test_create_table() {
        let headers = vec!["Name", "Value"];
        let rows = vec![
            vec!["Test1".to_string(), "100".to_string()],
            vec!["Test2".to_string(), "200".to_string()],
        ];
        
        let table = create_table(&headers, &rows);
        assert!(table.contains("Name"));
        assert!(table.contains("Value"));
        assert!(table.contains("Test1"));
        assert!(table.contains("╔"));
        assert!(table.contains("═"));
    }
}

