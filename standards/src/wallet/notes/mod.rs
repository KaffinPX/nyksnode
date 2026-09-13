use nyks_consensus::BFieldElement;
use thiserror::Error;

pub mod content;
pub mod note;

#[derive(Debug, Clone, Copy, Error)]
pub enum RawBytesError {
    #[error("byte length must be a multiple of 8, got {0}")]
    InvalidLength(usize),
}

/// 1:1, big-endian, no length prefix, no escaping.
pub(crate) fn bfes_to_bytes_raw(bfes: &[BFieldElement]) -> Vec<u8> {
    bfes.iter().flat_map(|e| e.value().to_be_bytes()).collect()
}

pub(crate) fn bytes_to_bfes_raw(bytes: &[u8]) -> Result<Vec<BFieldElement>, RawBytesError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(RawBytesError::InvalidLength(bytes.len()));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|c| BFieldElement::new(u64::from_be_bytes(c.try_into().unwrap())))
        .collect())
}
