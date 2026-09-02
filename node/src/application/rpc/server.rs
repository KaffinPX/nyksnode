use std::collections::HashSet;

use tokio::sync::mpsc;
use tracing::error;
use tracing::warn;

use crate::application::loops::channel::RPCServerToMain;
use crate::state::GlobalStateLock;
use nyks_rpc_core::api::ops::Namespace;

#[derive(Clone, Debug)]
pub struct RpcServer {
    pub(crate) state: GlobalStateLock,
    pub(crate) to_main_tx: mpsc::Sender<RPCServerToMain>,

    /// Whether to allow otherwise-restricted commands.
    ///
    /// With this boolean set to true, the querier can:
    ///  - make queries that induce large workloads;
    ///  - effect changes to network topology;
    ///  - (assuming the "Personal" namespace is also enabled) observe and spend
    ///    balance.
    ///
    /// If untrusted third parties have access to the RPC server, this boolean
    /// should be set to false, because otherwise the node is exposed to
    /// malicious behavior.
    pub(crate) unrestricted: bool,
}

impl RpcServer {
    pub fn new(state: GlobalStateLock, unrestricted: Option<bool>) -> Self {
        let unrestricted = unrestricted.unwrap_or(state.cli().unsafe_rpc);
        let to_main_tx = state.rpc_server_to_main_tx();

        Self {
            state,
            to_main_tx,
            unrestricted,
        }
    }

    /// Returns the enabled set of RPC namespaces with node configuration check.
    pub async fn enabled_namespaces(&self) -> HashSet<Namespace> {
        let state = self.state.lock_guard().await;
        let mut namespaces: HashSet<Namespace> =
            self.state.cli().rpc_modules.iter().copied().collect();

        if namespaces.contains(&Namespace::Archival) {
            let is_archival = state.chain.is_archival_node();

            if !is_archival {
                namespaces.remove(&Namespace::Archival);
                error!("Node is not archival, cannot enable Archival namespace.");
            }
        }

        if !self.unrestricted && namespaces.contains(&Namespace::Network) {
            warn!("Networking module is enabled without unsafe mode - this may expose sensitive data.")
        }

        namespaces
    }
}
