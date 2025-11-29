/// Packet engine module for NrMAP
/// 
/// This module provides low-level packet manipulation capabilities including
/// raw socket abstraction, packet crafting, and packet parsing.

pub mod raw_socket;
pub mod crafting;
pub mod parser;

pub use raw_socket::{RawSocket, RawSocketType};
pub use crafting::{PacketBuilder, TcpPacket, UdpPacket, IcmpPacket};
pub use parser::{PacketParser, ParsedPacket, PacketType};

use crate::error::ScanResult;
use std::net::IpAddr;

/// Packet engine configuration
#[derive(Debug, Clone)]
pub struct PacketEngineConfig {
    pub enable_raw_sockets: bool,
    pub default_ttl: u8,
    pub default_buffer_size: usize,
    pub enable_checksum_validation: bool,
}

impl Default for PacketEngineConfig {
    fn default() -> Self {
        Self {
            enable_raw_sockets: true,
            default_ttl: 64,
            default_buffer_size: 65535,
            enable_checksum_validation: true,
        }
    }
}

/// Packet engine facade providing high-level API
pub struct PacketEngine {
    config: PacketEngineConfig,
}

impl PacketEngine {
    /// Create a new packet engine
    pub fn new(config: PacketEngineConfig) -> Self {
        tracing::info!("Initializing packet engine");
        Self { config }
    }

    /// Create a raw socket for the specified protocol
    pub fn create_socket(&self, socket_type: RawSocketType) -> ScanResult<RawSocket> {
        if !self.config.enable_raw_sockets {
            return Err(crate::error::ScanError::scanner_error(
                "Raw sockets are disabled in configuration"
            ));
        }
        RawSocket::new(socket_type)
    }

    /// Create a packet builder
    pub fn builder(&self) -> PacketBuilder {
        PacketBuilder::new()
            .ttl(self.config.default_ttl)
    }

    /// Create a packet parser
    pub fn parser(&self) -> PacketParser {
        PacketParser::new(self.config.enable_checksum_validation)
    }

    /// Send a raw packet
    pub async fn send_packet(
        &self,
        socket: &mut RawSocket,
        packet: &[u8],
        destination: IpAddr,
    ) -> ScanResult<usize> {
        socket.send_to(packet, destination).await
    }

    /// Receive a raw packet
    pub async fn receive_packet(
        &self,
        socket: &mut RawSocket,
        timeout_ms: u64,
    ) -> ScanResult<(Vec<u8>, IpAddr)> {
        socket.receive_from(timeout_ms).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_engine_creation() {
        let config = PacketEngineConfig::default();
        let _engine = PacketEngine::new(config);
    }

    #[test]
    fn test_builder_creation() {
        let config = PacketEngineConfig::default();
        let engine = PacketEngine::new(config);
        let _builder = engine.builder();
    }

    #[test]
    fn test_parser_creation() {
        let config = PacketEngineConfig::default();
        let engine = PacketEngine::new(config);
        let _parser = engine.parser();
    }
}

