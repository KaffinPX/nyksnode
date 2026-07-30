use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use nyks_consensus::block::Block;
use nyks_consensus::block::BlockProof;
use nyks_consensus::block::block_appendix::BlockAppendix;
use nyks_consensus::block::block_body::BlockBody;
use nyks_consensus::block::block_header::BlockHeader;
use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::transaction::validity::nyks_proof::NyksProof;
use serde::Deserialize;
use serde::Serialize;

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub appendix: BlockAppendix,
    pub proof: NyksProof,
}

impl TryFrom<TransferBlock> for Block {
    type Error = anyhow::Error;

    fn try_from(t_block: TransferBlock) -> std::result::Result<Self, Self::Error> {
        ensure!(
            t_block.header.height != BlockHeight::genesis(),
            "The genesis block cannot be transferred or decoded from transfer",
        );

        let block = Block::new(
            t_block.header,
            t_block.body,
            t_block.appendix,
            BlockProof::SingleProof(t_block.proof),
        );
        Ok(block)
    }
}

impl TryFrom<Block> for TransferBlock {
    type Error = anyhow::Error;

    fn try_from(value: Block) -> Result<Self> {
        (&value).try_into()
    }
}

impl TryFrom<&Block> for TransferBlock {
    type Error = anyhow::Error;

    fn try_from(block: &Block) -> Result<Self> {
        let proof = match &block.proof {
            BlockProof::SingleProof(sp) => sp.clone(),
            BlockProof::Genesis => {
                bail!("The Genesis block cannot be transferred")
            }
            BlockProof::Invalid => {
                bail!("Invalid blocks cannot be transferred");
            }
        };
        Ok(Self {
            header: block.kernel.header,
            body: block.kernel.body.clone(),
            proof,
            appendix: block.kernel.appendix.clone(),
        })
    }
}
