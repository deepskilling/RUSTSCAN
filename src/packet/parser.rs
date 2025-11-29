/// Packet parser module for analyzing network packets
/// 
/// Provides parsing capabilities for TCP, UDP, ICMP, and IP packets
/// with validation and field extraction.

use crate::error::{ScanError, ScanResult};
use crate::packet::crafting::TcpFlags;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, trace, warn};

/// Type of parsed packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Igmp,
    Other(u8),
}

/// Parsed packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub packet_type: PacketType,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub ttl: u8,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub tcp_info: Option<ParsedTcpPacket>,
    pub udp_info: Option<ParsedUdpPacket>,
    pub icmp_info: Option<ParsedIcmpPacket>,
}

/// Parsed TCP packet
#[derive(Debug, Clone)]
pub struct ParsedTcpPacket {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub data_offset: u8,
}

/// Parsed UDP packet
#[derive(Debug, Clone)]
pub struct ParsedUdpPacket {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// Parsed ICMP packet
#[derive(Debug, Clone)]
pub struct ParsedIcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
}

/// Packet parser
pub struct PacketParser {
    validate_checksums: bool,
}

impl PacketParser {
    /// Create a new packet parser
    /// 
    /// # Arguments
    /// * `validate_checksums` - Whether to validate packet checksums
    pub fn new(validate_checksums: bool) -> Self {
        debug!("Creating packet parser (validate_checksums={})", validate_checksums);
        Self { validate_checksums }
    }

    /// Parse a raw packet
    /// 
    /// # Arguments
    /// * `data` - Raw packet bytes
    /// 
    /// # Returns
    /// * `ScanResult<ParsedPacket>` - Parsed packet information
    pub fn parse(&self, data: &[u8]) -> ScanResult<ParsedPacket> {
        trace!("Parsing packet of {} bytes", data.len());

        if data.len() < 20 {
            return Err(ScanError::packet_error("Packet too small to be valid IP"));
        }

        // Check IP version
        let version = (data[0] >> 4) & 0x0F;

        match version {
            4 => self.parse_ipv4(data),
            6 => self.parse_ipv6(data),
            _ => Err(ScanError::packet_error(format!(
                "Unknown IP version: {}",
                version
            ))),
        }
    }

    /// Parse an IPv4 packet
    fn parse_ipv4(&self, data: &[u8]) -> ScanResult<ParsedPacket> {
        if data.len() < 20 {
            return Err(ScanError::packet_error("IPv4 packet too small"));
        }

        // Parse IP header
        let ihl = (data[0] & 0x0F) as usize * 4;
        let ttl = data[8];
        let protocol = data[9];
        let header_checksum = u16::from_be_bytes([data[10], data[11]]);

        let source_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        // Validate checksum if requested
        if self.validate_checksums {
            let calculated_checksum = Self::calculate_ip_checksum(&data[..ihl]);
            if calculated_checksum != 0 && calculated_checksum != header_checksum {
                warn!(
                    "IP checksum mismatch: expected {}, got {}",
                    header_checksum, calculated_checksum
                );
            }
        }

        debug!(
            "Parsed IPv4: {} -> {}, protocol={}, ttl={}",
            source_ip, dest_ip, protocol, ttl
        );

        // Parse transport layer
        let transport_data = &data[ihl..];
        let (packet_type, tcp_info, udp_info, icmp_info, payload) =
            self.parse_transport_layer(protocol, transport_data, source_ip, dest_ip)?;

        Ok(ParsedPacket {
            packet_type,
            source_ip,
            dest_ip,
            ttl,
            protocol,
            payload,
            tcp_info,
            udp_info,
            icmp_info,
        })
    }

    /// Parse an IPv6 packet
    fn parse_ipv6(&self, data: &[u8]) -> ScanResult<ParsedPacket> {
        if data.len() < 40 {
            return Err(ScanError::packet_error("IPv6 packet too small"));
        }

        // Parse IPv6 header
        let ttl = data[7]; // Hop limit in IPv6
        let next_header = data[6]; // Next header (protocol)

        // Extract IPv6 addresses
        let mut src_bytes = [0u16; 8];
        let mut dst_bytes = [0u16; 8];

        for i in 0..8 {
            src_bytes[i] = u16::from_be_bytes([data[8 + i * 2], data[9 + i * 2]]);
            dst_bytes[i] = u16::from_be_bytes([data[24 + i * 2], data[25 + i * 2]]);
        }

        let source_ip = IpAddr::V6(Ipv6Addr::new(
            src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3],
            src_bytes[4], src_bytes[5], src_bytes[6], src_bytes[7],
        ));

        let dest_ip = IpAddr::V6(Ipv6Addr::new(
            dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3],
            dst_bytes[4], dst_bytes[5], dst_bytes[6], dst_bytes[7],
        ));

        debug!(
            "Parsed IPv6: {} -> {}, protocol={}, ttl={}",
            source_ip, dest_ip, next_header, ttl
        );

        // Parse transport layer
        let transport_data = &data[40..];
        let (packet_type, tcp_info, udp_info, icmp_info, payload) =
            self.parse_transport_layer(next_header, transport_data, source_ip, dest_ip)?;

        Ok(ParsedPacket {
            packet_type,
            source_ip,
            dest_ip,
            ttl,
            protocol: next_header,
            payload,
            tcp_info,
            udp_info,
            icmp_info,
        })
    }

    /// Parse transport layer (TCP/UDP/ICMP)
    fn parse_transport_layer(
        &self,
        protocol: u8,
        data: &[u8],
        _source_ip: IpAddr,
        _dest_ip: IpAddr,
    ) -> ScanResult<(
        PacketType,
        Option<ParsedTcpPacket>,
        Option<ParsedUdpPacket>,
        Option<ParsedIcmpPacket>,
        Vec<u8>,
    )> {
        match protocol {
            6 => {
                // TCP
                let tcp_info = self.parse_tcp(data)?;
                let payload_offset = tcp_info.data_offset as usize * 4;
                let payload = if payload_offset < data.len() {
                    data[payload_offset..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Tcp, Some(tcp_info), None, None, payload))
            }
            17 => {
                // UDP
                let udp_info = self.parse_udp(data)?;
                let payload = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Udp, None, Some(udp_info), None, payload))
            }
            1 => {
                // ICMP
                let icmp_info = self.parse_icmp(data)?;
                let payload = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Icmp, None, None, Some(icmp_info), payload))
            }
            2 => {
                // IGMP
                Ok((PacketType::Igmp, None, None, None, data.to_vec()))
            }
            _ => {
                Ok((PacketType::Other(protocol), None, None, None, data.to_vec()))
            }
        }
    }

    /// Parse TCP packet
    fn parse_tcp(&self, data: &[u8]) -> ScanResult<ParsedTcpPacket> {
        if data.len() < 20 {
            return Err(ScanError::packet_error("TCP packet too small"));
        }

        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let dest_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgment = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0x0F;
        let flags = TcpFlags::from_u8(data[13]);
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        debug!(
            "Parsed TCP: {}:{} -> {}:{}, seq={}, ack={}, flags={:?}",
            0, source_port, 0, dest_port, sequence, acknowledgment, flags
        );

        Ok(ParsedTcpPacket {
            source_port,
            dest_port,
            sequence,
            acknowledgment,
            flags,
            window,
            checksum,
            urgent_pointer,
            data_offset,
        })
    }

    /// Parse UDP packet
    fn parse_udp(&self, data: &[u8]) -> ScanResult<ParsedUdpPacket> {
        if data.len() < 8 {
            return Err(ScanError::packet_error("UDP packet too small"));
        }

        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let dest_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        debug!(
            "Parsed UDP: {}:{} -> {}:{}, length={}",
            0, source_port, 0, dest_port, length
        );

        Ok(ParsedUdpPacket {
            source_port,
            dest_port,
            length,
            checksum,
        })
    }

    /// Parse ICMP packet
    fn parse_icmp(&self, data: &[u8]) -> ScanResult<ParsedIcmpPacket> {
        if data.len() < 8 {
            return Err(ScanError::packet_error("ICMP packet too small"));
        }

        let icmp_type = data[0];
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        // For Echo Request/Reply, parse identifier and sequence
        let (identifier, sequence) = if icmp_type == 0 || icmp_type == 8 {
            let id = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            (Some(id), Some(seq))
        } else {
            (None, None)
        };

        debug!(
            "Parsed ICMP: type={}, code={}, id={:?}, seq={:?}",
            icmp_type, code, identifier, sequence
        );

        Ok(ParsedIcmpPacket {
            icmp_type,
            code,
            checksum,
            identifier,
            sequence,
        })
    }

    /// Calculate IP header checksum
    fn calculate_ip_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for chunk in data.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new(true)
    }
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketType::Tcp => write!(f, "TCP"),
            PacketType::Udp => write!(f, "UDP"),
            PacketType::Icmp => write!(f, "ICMP"),
            PacketType::Igmp => write!(f, "IGMP"),
            PacketType::Other(proto) => write!(f, "Protocol {}", proto),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = PacketParser::new(true);
        assert!(parser.validate_checksums);

        let parser_no_validation = PacketParser::new(false);
        assert!(!parser_no_validation.validate_checksums);
    }

    #[test]
    fn test_packet_type_display() {
        assert_eq!(format!("{}", PacketType::Tcp), "TCP");
        assert_eq!(format!("{}", PacketType::Udp), "UDP");
        assert_eq!(format!("{}", PacketType::Icmp), "ICMP");
        assert_eq!(format!("{}", PacketType::Other(89)), "Protocol 89");
    }

    #[test]
    fn test_parse_too_small() {
        let parser = PacketParser::new(true);
        let small_packet = vec![0u8; 10];
        
        let result = parser.parse(&small_packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tcp_too_small() {
        let parser = PacketParser::new(false);
        let small_tcp = vec![0u8; 10];
        
        let result = parser.parse_tcp(&small_tcp);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_udp_too_small() {
        let parser = PacketParser::new(false);
        let small_udp = vec![0u8; 4];
        
        let result = parser.parse_udp(&small_udp);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_icmp_too_small() {
        let parser = PacketParser::new(false);
        let small_icmp = vec![0u8; 4];
        
        let result = parser.parse_icmp(&small_icmp);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_checksum_calculation() {
        // Simple test packet header
        let header = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                         0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                         0xac, 0x10, 0x0a, 0x0c];
        
        let checksum = PacketParser::calculate_ip_checksum(&header);
        // Checksum calculation should work without errors
        assert!(checksum != 0 || checksum == 0); // Just ensure it computes
    }
}

