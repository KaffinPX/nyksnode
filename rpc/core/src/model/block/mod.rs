use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::model::block::appendix::RpcBlockAppendix;
use crate::model::block::body::RpcBlockBody;
use crate::model::block::header::RpcBlockHeader;
use crate::model::common::RpcBFieldElements;
use nyks_consensus::block::Block;
use nyks_consensus::block::BlockProof;
use nyks_consensus::block::block_appendix::BlockAppendix;
use nyks_consensus::block::block_body::BlockBody;
use nyks_consensus::block::block_header::BlockHeader;
use nyks_consensus::block::block_kernel::BlockKernel;
use nyks_consensus::proof_abstractions::mast_hash::MastHash;

pub mod appendix;
pub mod body;
pub mod header;
pub mod transaction_kernel;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockKernel {
    pub header: RpcBlockHeader,
    pub body: RpcBlockBody,
    pub appendix: RpcBlockAppendix,
}

impl RpcBlockKernel {
    /// Mast hash of the block kernel
    pub fn mast_hash(&self) -> Digest {
        let kernel: BlockKernel = self.to_owned().into();
        kernel.mast_hash()
    }
}

impl From<RpcBlockKernel> for BlockKernel {
    fn from(value: RpcBlockKernel) -> Self {
        BlockKernel {
            header: BlockHeader::from(value.header),
            body: BlockBody::from(value.body),
            appendix: BlockAppendix::from(value.appendix),
        }
    }
}

impl From<&BlockKernel> for RpcBlockKernel {
    fn from(kernel: &BlockKernel) -> Self {
        RpcBlockKernel {
            header: RpcBlockHeader::from(&kernel.header),
            body: RpcBlockBody::from(&kernel.body),
            appendix: RpcBlockAppendix::from(&kernel.appendix),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcBlockProof(pub Option<RpcBFieldElements>);

impl From<&BlockProof> for RpcBlockProof {
    fn from(proof: &BlockProof) -> Self {
        match proof {
            BlockProof::Genesis | BlockProof::Invalid => RpcBlockProof(None),
            BlockProof::SingleProof(proof) => RpcBlockProof(Some(proof.0.clone().into())),
        }
    }
}

impl From<RpcBlockProof> for BlockProof {
    fn from(proof: RpcBlockProof) -> Self {
        match proof.0 {
            None => BlockProof::Genesis,
            Some(bfes) => BlockProof::SingleProof(bfes.0.into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlock {
    pub kernel: RpcBlockKernel,
    pub proof: RpcBlockProof,
}

impl From<&Block> for RpcBlock {
    fn from(block: &Block) -> Self {
        RpcBlock {
            kernel: RpcBlockKernel::from(&block.kernel),
            proof: RpcBlockProof::from(&block.proof),
        }
    }
}

impl From<RpcBlock> for Block {
    fn from(block: RpcBlock) -> Self {
        Block::new(
            block.kernel.header.into(),
            block.kernel.body.into(),
            block.kernel.appendix.into(),
            block.proof.into(),
        )
    }
}
