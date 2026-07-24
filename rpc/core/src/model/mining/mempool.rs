use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMempoolMetadata {
    pub tip_mutator_set_hash: Digest,
}
