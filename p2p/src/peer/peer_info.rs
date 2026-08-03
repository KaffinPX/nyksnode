use std::net::IpAddr;
use std::time::SystemTime;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use serde::Deserialize;
use serde::Serialize;

use super::InstanceId;
use super::PeerStanding;
use crate::peer::HandshakeData;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerConnectionInfo {
    address: Multiaddr,
    inbound: bool,
}

impl PeerConnectionInfo {
    pub fn new(address: Multiaddr, inbound: bool) -> Self {
        Self { address, inbound }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    peer_connection_info: PeerConnectionInfo,
    instance_id: InstanceId,
    pub own_timestamp_connection_established: SystemTime,
    pub peer_timestamp_connection_established: SystemTime,
    pub standing: PeerStanding,
    version: String,
    is_archival_node: bool,
}

impl PeerInfo {
    pub fn new(
        peer_connection_info: PeerConnectionInfo,
        peer_handshake: &HandshakeData,
        connection_established: SystemTime,
        peer_tolerance: u16,
    ) -> Self {
        assert!(peer_tolerance > 0, "Peer tolerance must be positive");
        let standing = PeerStanding::new(peer_tolerance);
        Self {
            peer_connection_info,
            instance_id: peer_handshake.instance_id,
            own_timestamp_connection_established: connection_established,
            peer_timestamp_connection_established: peer_handshake.timestamp,
            standing,
            version: peer_handshake.version.to_string(),
            is_archival_node: peer_handshake.is_archival_node,
        }
    }

    pub fn with_standing(mut self, standing: PeerStanding) -> Self {
        self.standing = standing;
        self
    }

    pub fn instance_id(&self) -> u128 {
        self.instance_id
    }

    pub fn standing(&self) -> PeerStanding {
        self.standing
    }

    pub fn connection_established(&self) -> SystemTime {
        self.own_timestamp_connection_established
    }

    pub fn is_archival_node(&self) -> bool {
        self.is_archival_node
    }

    pub fn address(&self) -> Multiaddr {
        self.peer_connection_info.address.clone()
    }

    pub fn connection_is_inbound(&self) -> bool {
        self.peer_connection_info.inbound
    }

    pub fn connection_is_outbound(&self) -> bool {
        !self.connection_is_inbound()
    }

    pub fn ip_is_local(address: IpAddr) -> bool {
        match address {
            IpAddr::V4(ipv4_addr) => {
                ipv4_addr.is_private() || ipv4_addr.is_loopback() || ipv4_addr.is_link_local()
            }
            IpAddr::V6(ipv6_addr) => {
                ipv6_addr.is_unique_local()
                    || ipv6_addr.is_loopback()
                    || ipv6_addr.is_unicast_link_local()
            }
        }
    }

    /// Determine if the connection was established on a local network, i.e.,
    /// if the IP used for the connection is a local IP.
    pub fn is_local_connection(&self) -> bool {
        let ip_addr = self
            .peer_connection_info
            .address
            .iter()
            .find_map(|p| match p {
                Protocol::Ip4(ip) => Some(std::net::IpAddr::V4(ip)),
                Protocol::Ip6(ip) => Some(std::net::IpAddr::V6(ip)),
                _ => None,
            });

        match ip_addr {
            Some(ip) => Self::ip_is_local(ip),
            None => false, // No IP found (e.g., it's a DNS address or relay)
        }
    }

    /// returns the neptune-core version-string reported by the peer.
    ///
    /// note: the peer might not be honest.
    pub fn version(&self) -> &str {
        &self.version
    }

    #[cfg(test)]
    pub fn set_connection_established(&mut self, new_timestamp: SystemTime) {
        self.own_timestamp_connection_established = new_timestamp;
    }
}
