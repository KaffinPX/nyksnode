use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::SystemTime;

use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::multiaddr::Protocol;
use libp2p::multihash::Multihash;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use super::InstanceId;
use super::PeerStanding;
use crate::peer::HandshakeData;

/// Derive a pseudorandom [`PeerId`] from a [`SocketAddr`].
///
/// This is a controversial feature, with accordingly complex motivation -- bear
/// with:
///
/// This map is a compatibility layer bridging two architectures. With the
/// introduction of the libp2p network stack, all peer-related dictionaries
/// were modified to use the [`PeerId`] as the key instead of the
/// [`SocketAddr`]. Here is why the [`PeerId`] is a better choice:
///  - In the libp2p stack, the [`PeerId`] is cryptographically bound to the
///    peer's public key -- and the stack will refuse to connect if it fails to
///    verify that the peer really knows the matching secret key.
///  - The same peer (identified by public key) can have multiple
///    [`SocketAddr`]s, and even other internet-route-locators. While malicious
///    attackers can generate many key pairs, the point is that honest peers
///    will reuse the same public key but will be treated as different peers if
///    their [`SocketAddr`] is used as a stand-in for their identity. The
///    [`SocketAddr`] can change under benign circumstances, for instance if the
///    peer switches from WiFi to 4G, or it their ISP switches to a different
///    IP. So for honest peers, using the [`PeerId`] as the identifier leads to
///    less redundant work and greater peer set entropy.
///  - Malicious nodes must still use a variety of [`SocketAddr`]s if the goal
///    is to populate a victim's peer set with sybils and drive out honest
///    peers.Banning still happens at the level of [`SocketAddr`]s. So this
///    transition does not degrade security.
///
/// However, since the legacy peer-to-peer stack has no concept of [`PeerId`],
/// it is difficult to access the dictionaries that now use the [`PeerId`] as
/// key, such as `peer_map` and `peer_standing`. This map deterministically
/// derives an identity ([`PeerId`]) from the peer's [`SocketAddr`]. This is a
/// controversial identification because a) there is no cryptographic
/// authentication or even tie to public keys; and b) leads to duplication of
/// work and weaker peer set entropy. Therefore, this map should only be used in
/// the context of the legacy peer-to-peer stack and, if the legacy peer-to-peer
/// stack is deprecated, this function should be deprecated along with it.
pub fn pseudorandom_peer_id(addr: &SocketAddr) -> PeerId {
    let mut hasher = Sha256::new();
    hasher.update(b"legacy-mapping");
    hasher.update(addr.to_string().as_bytes());
    let hash_result = hasher.finalize();

    // Use SHA2_256 (Code 0x12) which is the libp2p standard.
    let mhash = Multihash::wrap(0x12, &hash_result)
        .expect("SHA2-256 hash length is 32 bytes, which is valid for multihash");

    PeerId::from_multihash(mhash).expect("SHA2-256 is the standard libp2p PeerId hash algorithm")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerConnectionInfo {
    listen_port: Option<u16>,
    address: Multiaddr,
    inbound: bool,
}

impl PeerConnectionInfo {
    pub fn new(listen_port: Option<u16>, connected_address: Multiaddr, inbound: bool) -> Self {
        Self {
            listen_port,
            address: connected_address,
            inbound,
        }
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

    /// Return the [`Multiaddr`] that the peer is expected to listen on. Returns
    /// `None` if peer does not accept incoming connections.
    pub fn listen_address(&self) -> Option<Multiaddr> {
        let listen_port = self.peer_connection_info.listen_port?;
        let mut new_multiaddr = Multiaddr::empty();

        for component in &self.peer_connection_info.address {
            match component {
                // If TCP or UDP, replace the port with listen_port
                Protocol::Tcp(_) => new_multiaddr.push(Protocol::Tcp(listen_port)),
                Protocol::Udp(_) => new_multiaddr.push(Protocol::Udp(listen_port)),

                // Otherwise, keep the component as is (IP, DNS, etc.)
                other => new_multiaddr.push(other),
            }
        }
        Some(new_multiaddr)
    }

    #[cfg(test)]
    pub fn set_connection_established(&mut self, new_timestamp: SystemTime) {
        self.own_timestamp_connection_established = new_timestamp;
    }
}
