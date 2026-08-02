use tokio_util::codec::LengthDelimitedCodec;

// Max peer message size is 500MB. Should be enough to send 250 blocks in a
// block batch-response.
pub const MAX_PEER_FRAME_LENGTH_IN_BYTES: usize = 500 * 1024 * 1024;

/// Use this function to ensure that the same rules apply for both
/// ingoing and outgoing connections. This limits the size of messages
/// peers can send.
pub(crate) fn get_codec_rules() -> LengthDelimitedCodec {
    let mut codec_rules = LengthDelimitedCodec::new();
    codec_rules.set_max_frame_length(MAX_PEER_FRAME_LENGTH_IN_BYTES);
    codec_rules
}