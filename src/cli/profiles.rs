/// CLI scanning profiles
/// 
/// Predefined scanning profiles for common use cases, similar to Nmap profiles.

use crate::scanner::ScanType;
use serde::{Deserialize, Serialize};

/// Scan profile definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,
    pub ports: PortSpec,
    pub scan_types: Vec<ScanType>,
    pub timing: TimingProfile,
    pub options: ProfileOptions,
}

/// Port specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortSpec {
    /// Specific ports
    Ports(Vec<u16>),
    /// Port range
    Range(u16, u16),
    /// Port preset name
    Preset(String),
}

/// Timing profile
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TimingProfile {
    /// Paranoid (T0): Very slow, evades IDS
    Paranoid,
    /// Sneaky (T1): Slow, evades IDS
    Sneaky,
    /// Polite (T2): Slow, doesn't overwhelm target
    Polite,
    /// Normal (T3): Default timing
    Normal,
    /// Aggressive (T4): Fast, assumes good network
    Aggressive,
    /// Insane (T5): Very fast, may overwhelm target
    Insane,
}

/// Profile options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileOptions {
    pub enable_service_detection: bool,
    pub enable_os_detection: bool,
    pub enable_banner_grabbing: bool,
    pub max_concurrent: usize,
    pub timeout_ms: u64,
}

impl ScanProfile {
    /// Get a built-in profile by name
    pub fn by_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "quick" => Some(Self::quick()),
            "fast" => Some(Self::fast()),
            "default" | "normal" => Some(Self::default_profile()),
            "thorough" | "comprehensive" => Some(Self::thorough()),
            "stealth" | "sneaky" => Some(Self::stealth()),
            "intense" => Some(Self::intense()),
            "web" => Some(Self::web()),
            "database" | "db" => Some(Self::database()),
            "all-ports" => Some(Self::all_ports()),
            _ => None,
        }
    }

    /// Quick scan - top 100 ports, TCP connect only
    pub fn quick() -> Self {
        Self {
            name: "quick".to_string(),
            description: "Quick scan of top 100 most common ports".to_string(),
            ports: PortSpec::Preset("common".to_string()),
            scan_types: vec![ScanType::TcpConnect],
            timing: TimingProfile::Aggressive,
            options: ProfileOptions {
                enable_service_detection: false,
                enable_os_detection: false,
                enable_banner_grabbing: false,
                max_concurrent: 1000,
                timeout_ms: 2000,
            },
        }
    }

    /// Fast scan - top 1000 ports
    pub fn fast() -> Self {
        Self {
            name: "fast".to_string(),
            description: "Fast scan of top 1000 ports with minimal detection".to_string(),
            ports: PortSpec::Range(1, 1000),
            scan_types: vec![ScanType::TcpConnect],
            timing: TimingProfile::Aggressive,
            options: ProfileOptions {
                enable_service_detection: true,
                enable_os_detection: false,
                enable_banner_grabbing: true,
                max_concurrent: 500,
                timeout_ms: 3000,
            },
        }
    }

    /// Default/Normal profile
    pub fn default_profile() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default balanced scan profile".to_string(),
            ports: PortSpec::Preset("common".to_string()),
            scan_types: vec![ScanType::TcpConnect],
            timing: TimingProfile::Normal,
            options: ProfileOptions {
                enable_service_detection: true,
                enable_os_detection: false,
                enable_banner_grabbing: true,
                max_concurrent: 100,
                timeout_ms: 5000,
            },
        }
    }

    /// Thorough/Comprehensive scan
    pub fn thorough() -> Self {
        Self {
            name: "thorough".to_string(),
            description: "Comprehensive scan with service and OS detection".to_string(),
            ports: PortSpec::Range(1, 10000),
            scan_types: vec![ScanType::TcpConnect, ScanType::Udp],
            timing: TimingProfile::Normal,
            options: ProfileOptions {
                enable_service_detection: true,
                enable_os_detection: true,
                enable_banner_grabbing: true,
                max_concurrent: 100,
                timeout_ms: 5000,
            },
        }
    }

    /// Stealth scan - SYN scan with slow timing
    pub fn stealth() -> Self {
        Self {
            name: "stealth".to_string(),
            description: "Stealthy scan designed to evade detection".to_string(),
            ports: PortSpec::Preset("common".to_string()),
            scan_types: vec![ScanType::TcpSyn],
            timing: TimingProfile::Sneaky,
            options: ProfileOptions {
                enable_service_detection: false,
                enable_os_detection: false,
                enable_banner_grabbing: false,
                max_concurrent: 10,
                timeout_ms: 10000,
            },
        }
    }

    /// Intense scan - all ports, all scan types
    pub fn intense() -> Self {
        Self {
            name: "intense".to_string(),
            description: "Intense scan of all ports with full detection".to_string(),
            ports: PortSpec::Range(1, 65535),
            scan_types: vec![ScanType::TcpConnect, ScanType::TcpSyn, ScanType::Udp],
            timing: TimingProfile::Aggressive,
            options: ProfileOptions {
                enable_service_detection: true,
                enable_os_detection: true,
                enable_banner_grabbing: true,
                max_concurrent: 1000,
                timeout_ms: 5000,
            },
        }
    }

    /// Web services scan
    pub fn web() -> Self {
        Self {
            name: "web".to_string(),
            description: "Scan web service ports with service detection".to_string(),
            ports: PortSpec::Preset("web".to_string()),
            scan_types: vec![ScanType::TcpConnect],
            timing: TimingProfile::Normal,
            options: ProfileOptions {
                enable_service_detection: true,
                enable_os_detection: false,
                enable_banner_grabbing: true,
                max_concurrent: 100,
                timeout_ms: 5000,
            },
        }
    }

    /// Database services scan
    pub fn database() -> Self {
        Self {
            name: "database".to_string(),
            description: "Scan database ports with service detection".to_string(),
            ports: PortSpec::Preset("database".to_string()),
            scan_types: vec![ScanType::TcpConnect],
            timing: TimingProfile::Normal,
            options: ProfileOptions {
                enable_service_detection: true,
                enable_os_detection: false,
                enable_banner_grabbing: true,
                max_concurrent: 50,
                timeout_ms: 5000,
            },
        }
    }

    /// All ports scan
    pub fn all_ports() -> Self {
        Self {
            name: "all-ports".to_string(),
            description: "Scan all 65535 ports".to_string(),
            ports: PortSpec::Range(1, 65535),
            scan_types: vec![ScanType::TcpConnect],
            timing: TimingProfile::Aggressive,
            options: ProfileOptions {
                enable_service_detection: false,
                enable_os_detection: false,
                enable_banner_grabbing: false,
                max_concurrent: 1000,
                timeout_ms: 2000,
            },
        }
    }

    /// List all available profiles
    pub fn list_all() -> Vec<String> {
        vec![
            "quick".to_string(),
            "fast".to_string(),
            "default".to_string(),
            "thorough".to_string(),
            "stealth".to_string(),
            "intense".to_string(),
            "web".to_string(),
            "database".to_string(),
            "all-ports".to_string(),
        ]
    }

    /// Get profile description
    pub fn describe(&self) -> String {
        format!("{}: {}", self.name, self.description)
    }
}

impl std::fmt::Display for ScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Profile: {}", self.name)?;
        writeln!(f, "  Description: {}", self.description)?;
        writeln!(f, "  Ports: {:?}", self.ports)?;
        writeln!(f, "  Scan Types: {:?}", self.scan_types)?;
        writeln!(f, "  Timing: {:?}", self.timing)?;
        writeln!(f, "  Service Detection: {}", self.options.enable_service_detection)?;
        writeln!(f, "  OS Detection: {}", self.options.enable_os_detection)?;
        writeln!(f, "  Banner Grabbing: {}", self.options.enable_banner_grabbing)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_profile_by_name() {
        assert!(ScanProfile::by_name("quick").is_some());
        assert!(ScanProfile::by_name("fast").is_some());
        assert!(ScanProfile::by_name("default").is_some());
        assert!(ScanProfile::by_name("unknown").is_none());
    }

    #[test]
    fn test_quick_profile() {
        let profile = ScanProfile::quick();
        assert_eq!(profile.name, "quick");
        assert!(matches!(profile.timing, TimingProfile::Aggressive));
    }

    #[test]
    fn test_stealth_profile() {
        let profile = ScanProfile::stealth();
        assert_eq!(profile.name, "stealth");
        assert!(matches!(profile.timing, TimingProfile::Sneaky));
        assert!(!profile.options.enable_service_detection);
    }

    #[test]
    fn test_list_all_profiles() {
        let profiles = ScanProfile::list_all();
        assert!(profiles.len() >= 9);
        assert!(profiles.contains(&"quick".to_string()));
        assert!(profiles.contains(&"stealth".to_string()));
    }

    #[test]
    fn test_profile_display() {
        let profile = ScanProfile::quick();
        let display = format!("{}", profile);
        assert!(display.contains("quick"));
        assert!(display.contains("Description"));
    }
}

