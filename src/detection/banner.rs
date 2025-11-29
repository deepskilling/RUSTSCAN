/// Service banner grabbing module
/// 
/// This module implements banner grabbing techniques to identify services
/// running on open ports by analyzing their initial responses.

use crate::error::{ScanError, ScanResult};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

/// Service banner information
#[derive(Debug, Clone)]
pub struct ServiceBanner {
    pub target: IpAddr,
    pub port: u16,
    pub data: String,
    pub raw_bytes: Vec<u8>,
    pub response_time_ms: u64,
}

impl std::fmt::Display for ServiceBanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} - {} ({}ms)",
            self.target,
            self.port,
            self.data.chars().take(50).collect::<String>(),
            self.response_time_ms
        )
    }
}

/// Banner grabber for service identification
pub struct BannerGrabber {
    timeout_ms: u64,
    max_banner_size: usize,
}

impl BannerGrabber {
    /// Create a new banner grabber
    /// 
    /// # Arguments
    /// * `timeout_ms` - Timeout for banner grabbing in milliseconds
    /// * `max_banner_size` - Maximum banner size to read in bytes
    pub fn new(timeout_ms: u64, max_banner_size: usize) -> Self {
        info!(
            "Initializing banner grabber: timeout={}ms, max_size={}",
            timeout_ms, max_banner_size
        );
        Self {
            timeout_ms,
            max_banner_size,
        }
    }

    /// Grab banner from a service
    /// 
    /// # Arguments
    /// * `target` - Target IP address
    /// * `port` - Target port
    /// 
    /// # Returns
    /// * `ScanResult<Option<ServiceBanner>>` - Grabbed banner or None if no banner
    pub async fn grab(&self, target: IpAddr, port: u16) -> ScanResult<Option<ServiceBanner>> {
        debug!("Grabbing banner from {}:{}", target, port);
        
        let start = std::time::Instant::now();
        let addr = SocketAddr::new(target, port);
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        // Try to connect and read banner
        match timeout(timeout_duration, self.try_grab_banner(addr)).await {
            Ok(Ok(banner_data)) => {
                let elapsed = start.elapsed();
                
                if banner_data.is_empty() {
                    debug!("No banner received from {}:{}", target, port);
                    return Ok(None);
                }

                // Convert to string, replacing invalid UTF-8
                let banner_string = String::from_utf8_lossy(&banner_data).to_string();
                
                info!(
                    "Grabbed banner from {}:{} ({} bytes, {}ms)",
                    target, port, banner_data.len(), elapsed.as_millis()
                );
                
                Ok(Some(ServiceBanner {
                    target,
                    port,
                    data: banner_string,
                    raw_bytes: banner_data,
                    response_time_ms: elapsed.as_millis() as u64,
                }))
            }
            Ok(Err(e)) => {
                debug!("Failed to grab banner from {}:{}: {}", target, port, e);
                Ok(None)
            }
            Err(_) => {
                debug!("Banner grab timeout for {}:{}", target, port);
                Ok(None)
            }
        }
    }

    /// Internal method to attempt banner grab
    async fn try_grab_banner(&self, addr: SocketAddr) -> ScanResult<Vec<u8>> {
        // Connect to the service
        let mut stream = TcpStream::connect(addr).await.map_err(|e| {
            ScanError::network(format!("Failed to connect: {}", e))
        })?;

        trace!("Connected to {}", addr);

        // Try sending a probe if needed (some services require a request)
        let probe = self.get_probe_for_port(addr.port());
        if let Some(probe_data) = probe {
            trace!("Sending probe to {}", addr);
            stream.write_all(&probe_data).await.map_err(|e| {
                ScanError::network(format!("Failed to send probe: {}", e))
            })?;
        }

        // Read the banner
        let mut buffer = vec![0u8; self.max_banner_size];
        let bytes_read = stream.read(&mut buffer).await.map_err(|e| {
            ScanError::network(format!("Failed to read banner: {}", e))
        })?;

        buffer.truncate(bytes_read);
        trace!("Read {} bytes from {}", bytes_read, addr);

        Ok(buffer)
    }

    /// Get appropriate probe for a given port
    /// 
    /// Some services require a request before sending a banner
    fn get_probe_for_port(&self, port: u16) -> Option<Vec<u8>> {
        match port {
            80 | 8080 | 8000 | 8888 => {
                // HTTP probe
                Some(b"GET / HTTP/1.0\r\n\r\n".to_vec())
            }
            443 | 8443 => {
                // HTTPS probe (just connect, TLS handshake will happen)
                None
            }
            21 => {
                // FTP doesn't need a probe, server sends banner first
                None
            }
            22 => {
                // SSH sends banner first
                None
            }
            25 | 587 => {
                // SMTP sends banner first
                None
            }
            110 | 995 => {
                // POP3 sends banner first
                None
            }
            143 | 993 => {
                // IMAP sends banner first
                None
            }
            3306 => {
                // MySQL sends banner first
                None
            }
            5432 => {
                // PostgreSQL requires handshake
                None
            }
            1433 => {
                // MSSQL requires handshake
                None
            }
            27017 => {
                // MongoDB requires handshake
                None
            }
            6379 => {
                // Redis - send INFO command
                Some(b"INFO\r\n".to_vec())
            }
            11211 => {
                // Memcached - send stats command
                Some(b"stats\r\n".to_vec())
            }
            _ => {
                // Unknown service, try to read without probe
                None
            }
        }
    }

    /// Grab banners from multiple hosts/ports concurrently
    pub async fn grab_many(
        &self,
        targets: Vec<(IpAddr, u16)>,
        max_concurrent: usize,
    ) -> ScanResult<Vec<ServiceBanner>> {
        use futures::stream::{self, StreamExt};

        info!(
            "Grabbing banners from {} targets with concurrency {}",
            targets.len(),
            max_concurrent
        );

        let results = stream::iter(targets)
            .map(|(target, port)| async move {
                match self.grab(target, port).await {
                    Ok(Some(banner)) => Some(banner),
                    Ok(None) => None,
                    Err(e) => {
                        warn!("Banner grab failed for {}:{} - {}", target, port, e);
                        None
                    }
                }
            })
            .buffer_unordered(max_concurrent)
            .collect::<Vec<_>>()
            .await;

        let banners: Vec<ServiceBanner> = results.into_iter().flatten().collect();
        
        info!("Grabbed {} banners successfully", banners.len());

        Ok(banners)
    }
}

/// Analyze banner content to extract information
pub fn analyze_banner(banner: &ServiceBanner) -> BannerAnalysis {
    let data = &banner.data;
    
    let mut analysis = BannerAnalysis {
        protocol: None,
        service_name: None,
        version: None,
        additional_info: Vec::new(),
    };

    // HTTP detection
    if data.starts_with("HTTP/") {
        analysis.protocol = Some("HTTP".to_string());
        
        // Extract server header
        for line in data.lines() {
            if line.starts_with("Server:") {
                let server = line.strip_prefix("Server:").unwrap_or("").trim();
                analysis.service_name = Some(server.to_string());
            }
        }
    }

    // SSH detection
    if data.starts_with("SSH-") {
        analysis.protocol = Some("SSH".to_string());
        
        // Parse SSH version string: SSH-2.0-OpenSSH_8.9
        if let Some(parts) = data.lines().next() {
            let parts: Vec<&str> = parts.split('-').collect();
            if parts.len() >= 3 {
                analysis.service_name = Some(parts[2].to_string());
            }
        }
    }

    // FTP detection
    if data.starts_with("220 ") {
        analysis.protocol = Some("FTP".to_string());
        if let Some(first_line) = data.lines().next() {
            analysis.service_name = Some(first_line.strip_prefix("220 ").unwrap_or("").to_string());
        }
    }

    // SMTP detection
    if data.starts_with("220 ") && data.contains("SMTP") {
        analysis.protocol = Some("SMTP".to_string());
    }

    // MySQL detection
    if banner.raw_bytes.len() > 4 && banner.raw_bytes[3] == 0x0a {
        analysis.protocol = Some("MySQL".to_string());
    }

    analysis
}

/// Banner analysis result
#[derive(Debug, Clone)]
pub struct BannerAnalysis {
    pub protocol: Option<String>,
    pub service_name: Option<String>,
    pub version: Option<String>,
    pub additional_info: Vec<String>,
}

impl std::fmt::Display for BannerAnalysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref protocol) = self.protocol {
            write!(f, "{}", protocol)?;
        }
        
        if let Some(ref service) = self.service_name {
            write!(f, " - {}", service)?;
        }
        
        if let Some(ref version) = self.version {
            write!(f, " v{}", version)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_banner_grabber_creation() {
        let grabber = BannerGrabber::new(5000, 4096);
        assert_eq!(grabber.timeout_ms, 5000);
        assert_eq!(grabber.max_banner_size, 4096);
    }

    #[test]
    fn test_get_probe_for_port() {
        let grabber = BannerGrabber::new(5000, 4096);
        
        // HTTP should have a probe
        assert!(grabber.get_probe_for_port(80).is_some());
        
        // SSH shouldn't need a probe
        assert!(grabber.get_probe_for_port(22).is_none());
        
        // FTP shouldn't need a probe
        assert!(grabber.get_probe_for_port(21).is_none());
    }

    #[test]
    fn test_analyze_http_banner() {
        let banner = ServiceBanner {
            target: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 80,
            data: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n".to_string(),
            raw_bytes: vec![],
            response_time_ms: 100,
        };

        let analysis = analyze_banner(&banner);
        assert_eq!(analysis.protocol, Some("HTTP".to_string()));
        assert!(analysis.service_name.is_some());
    }

    #[test]
    fn test_analyze_ssh_banner() {
        let banner = ServiceBanner {
            target: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 22,
            data: "SSH-2.0-OpenSSH_8.9\r\n".to_string(),
            raw_bytes: vec![],
            response_time_ms: 100,
        };

        let analysis = analyze_banner(&banner);
        assert_eq!(analysis.protocol, Some("SSH".to_string()));
        assert_eq!(analysis.service_name, Some("OpenSSH_8.9".to_string()));
    }

    #[test]
    fn test_analyze_ftp_banner() {
        let banner = ServiceBanner {
            target: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 21,
            data: "220 Welcome to FTP server\r\n".to_string(),
            raw_bytes: vec![],
            response_time_ms: 100,
        };

        let analysis = analyze_banner(&banner);
        assert_eq!(analysis.protocol, Some("FTP".to_string()));
    }

    #[test]
    fn test_banner_display() {
        let banner = ServiceBanner {
            target: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 80,
            data: "HTTP/1.1 200 OK".to_string(),
            raw_bytes: vec![],
            response_time_ms: 123,
        };

        let display = format!("{}", banner);
        assert!(display.contains("192.168.1.1:80"));
        assert!(display.contains("123ms"));
    }
}

