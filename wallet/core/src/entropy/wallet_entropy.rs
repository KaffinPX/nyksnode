use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::tasm_lib::prelude::Tip5;
use nyks_consensus::twenty_first::bfe_vec;
use nyks_consensus::twenty_first::math::b_field_element::BFieldElement;
use nyks_consensus::twenty_first::math::bfield_codec::BFieldCodec;
use nyks_consensus::twenty_first::math::x_field_element::XFieldElement;
use nyks_consensus::twenty_first::tip5::digest::Digest;
use nyks_consensus::twenty_first::xfe;
use nyks_standards::wallet::keys::key::Spender;
use nyks_standards::wallet::keys::schemes::generation::GENERATION_FLAG;
use nyks_standards::wallet::keys::schemes::generation::GenerationAddress;
use nyks_standards::wallet::keys::schemes::generation::GenerationKey;
use nyks_standards::wallet::keys::schemes::symmetric::SYMMETRIC_FLAG;
use nyks_standards::wallet::keys::schemes::symmetric::SymmetricAddress;
use nyks_standards::wallet::keys::schemes::symmetric::SymmetricKey;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::entropy::secret_key_material::FromPhraseError;
use crate::entropy::secret_key_material::SecretKeyMaterial;

/// The wallet's one source of randomness, from which all keys are derived.
///
/// This struct wraps around [`SecretKeyMaterial`], which contains the secret
/// data. The wrapper supplies arithmetic functions for use in the context of a
/// wallet for Nyks.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct WalletEntropy {
    secret_seed: SecretKeyMaterial,
}

impl WalletEntropy {
    pub fn new(secret_seed: SecretKeyMaterial) -> Self {
        Self { secret_seed }
    }

    /// Convert a secret seed phrase (list of 18 valid BIP-39 words) to a
    /// [`WalletEntropy`] object
    pub fn from_phrase(phrase: &[String]) -> Result<Self, FromPhraseError> {
        let key = SecretKeyMaterial::from_phrase(phrase)?;
        Ok(Self::new(key))
    }

    /// Create a `WalletEntropy` object with a fixed digest
    pub fn devnet_wallet() -> Self {
        let secret_seed = SecretKeyMaterial(xfe!([
            12063201067205522823_u64,
            1529663126377206632_u64,
            2090171368883726200_u64,
        ]));

        Self::new(secret_seed)
    }

    /// Returns the special-purpose key used for protocol allocations and fees.
    ///
    /// Usually used for guessing, composing and upgrading.
    pub fn special_generation_key(&self) -> GenerationKey {
        self.nth_generation_key(0u64)
    }

    /// Returns the special-purpose key used for protocol allocations and fees.
    ///
    /// Used for genesis allocations.
    pub fn special_symmetric_key(&self) -> SymmetricKey {
        self.nth_symmetric_key(0u64)
    }

    pub fn nth_generation_address(&self, index: u64) -> GenerationAddress {
        self.nth_generation_key(index).to_address()
    }

    pub fn nth_symmetric_address(&self, index: u64) -> SymmetricAddress {
        self.nth_symmetric_key(index).to_address()
    }

    /// derives a generation spending key at `index`
    //
    // note: this is a read-only method and does not modify wallet state.  When
    // requesting a new key for purposes of a new wallet receiving address,
    // callers should use [wallet_state::WalletState::next_unused_spending_key()]
    // which takes &mut self.
    pub fn nth_generation_key(&self, index: u64) -> GenerationKey {
        // We keep n between 0 and 2^16 as this makes it possible to scan all possible addresses
        // in case you don't know with what counter you made the address
        let key_seed = Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![GENERATION_FLAG, index],
            ]
            .concat(),
        );
        GenerationKey::new(key_seed)
    }

    /// derives a symmetric key at `index`
    //
    // note: this is a read-only method and does not modify wallet state.  When
    // requesting a new key for purposes of a new wallet receiving address,
    // callers should use [wallet_state::WalletState::next_unused_spending_key()]
    // which takes &mut self.
    pub fn nth_symmetric_key(&self, index: u64) -> SymmetricKey {
        let key_seed = Tip5::hash_varlen(
            &[self.secret_seed.0.encode(), bfe_vec![SYMMETRIC_FLAG, index]].concat(),
        );
        SymmetricKey::new(key_seed)
    }

    /// Return a deterministic seed that can be used to seed an RNG
    pub(crate) fn deterministic_derived_seed(&self, block_height: BlockHeight) -> Digest {
        const SEED_FLAG: u64 = 0x2315439570c4a85fu64;
        Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![SEED_FLAG, block_height],
            ]
            .concat(),
        )
    }

    /// Return pseudo-random sender randomness derived from secret seed and
    /// other parameters.
    pub fn generate_sender_randomness(
        &self,
        block_height: BlockHeight,
        receiver_digest: Digest,
    ) -> Digest {
        const SENDER_RANDOMNESS_FLAG: u64 = 0x5e116e1270u64;
        Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![SENDER_RANDOMNESS_FLAG, block_height],
                receiver_digest.encode(),
            ]
            .concat(),
        )
    }

    /// Return a seed used to randomize shuffling.
    pub fn shuffle_seed(&self, block_height: BlockHeight) -> [u8; 32] {
        let secure_seed_from_wallet = self.deterministic_derived_seed(block_height);
        let seed: [u8; Digest::BYTES] = secure_seed_from_wallet.into();

        seed[0..32].try_into().unwrap()
    }
}

impl From<SecretKeyMaterial> for WalletEntropy {
    fn from(value: SecretKeyMaterial) -> Self {
        Self { secret_seed: value }
    }
}

impl From<WalletEntropy> for SecretKeyMaterial {
    fn from(value: WalletEntropy) -> Self {
        value.secret_seed.clone()
    }
}
