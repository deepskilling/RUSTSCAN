/// CLI profiles example
/// 
/// This example demonstrates using predefined scan profiles for common use cases.

use nrmap::cli::{ScanProfile, OutputFormatter, OutputFormat};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP CLI Profiles Example\n");

    // Example 1: List all available profiles
    println!("Example 1: Available Profiles");
    println!("{}", "-".repeat(50));
    
    let profiles = ScanProfile::list_all();
    println!("Available profiles ({}):", profiles.len());
    for profile_name in &profiles {
        if let Some(profile) = ScanProfile::by_name(profile_name) {
            println!("  • {} - {}", profile.name, profile.description);
        }
    }
    println!();

    // Example 2: Quick scan profile
    println!("Example 2: Quick Scan Profile");
    println!("{}", "-".repeat(50));
    
    let quick = ScanProfile::quick();
    println!("{}", quick);
    println!();

    // Example 3: Stealth scan profile
    println!("Example 3: Stealth Scan Profile");
    println!("{}", "-".repeat(50));
    
    let stealth = ScanProfile::stealth();
    println!("{}", stealth);
    println!();

    // Example 4: Intense scan profile
    println!("Example 4: Intense Scan Profile");
    println!("{}", "-".repeat(50));
    
    let intense = ScanProfile::intense();
    println!("{}", intense);
    println!();

    // Example 5: Web services profile
    println!("Example 5: Web Services Profile");
    println!("{}", "-".repeat(50));
    
    let web = ScanProfile::web();
    println!("{}", web);
    println!();

    // Example 6: Output formatting
    println!("Example 6: Output Formatting");
    println!("{}", "-".repeat(50));
    
    #[derive(serde::Serialize)]
    struct ScanSummary {
        target: String,
        ports_scanned: u32,
        open_ports: u32,
        duration_ms: u64,
    }
    
    let summary = ScanSummary {
        target: "192.168.1.1".to_string(),
        ports_scanned: 1000,
        open_ports: 5,
        duration_ms: 12345,
    };
    
    // JSON format
    let formatter = OutputFormatter::new(OutputFormat::Json);
    let json_output = formatter.format(&summary, OutputFormat::Json)?;
    println!("JSON Output:");
    println!("{}", json_output);
    println!();
    
    // Pretty JSON format
    let pretty_json = formatter.format(&summary, OutputFormat::JsonPretty)?;
    println!("Pretty JSON Output:");
    println!("{}", pretty_json);
    println!();

    println!("Example completed!");
    println!("\nTip: Use these profiles in your scans:");
    println!("  nrmap scan --target 192.168.1.1 --profile quick");
    println!("  nrmap scan --target 192.168.1.1 --profile stealth");
    println!("  nrmap scan --target 192.168.1.1 --profile intense");

    Ok(())
}

