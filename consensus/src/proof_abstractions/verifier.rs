use tasm_lib::triton_vm;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tokio::task;

use crate::network::Network;
use crate::transaction::validity::neptune_proof::Proof;

/// This claims-cache contains claims that are simply defined to be true.
///
/// If the claim is in the cache, then the Triton VM verifier is by-passed
/// without reading the proof.
///
/// Besides tests, it is used for *checkpoints*, where we define historical
/// blocks to be valid.
//
// The cache enables mock proofs to be generated and validated immediately
// which enables mock blocks and transactions.
//
// important:  for regtest mode to work properly, peers must be able to
// verify eachother's proofs. There is presently no mechanism to sync
// the cache between peers, though that could be a possibility.
//
// HOWEVER: given that this is a process-wide cache, it is actually shared
// between in-process peers such as when executing integration tests.
//
// In other words, distributed proving works for integration tests, but not
// yet in a "real" regtest multi-node network.
//
// RAM Usage:
//
// Presently claims are never expired. So there is a very real chance of
// blowing up RAM.  Maybe not so problematic since regtest is generally started
// from genesis block anyway.
//
// see: https://github.com/Neptune-Crypto/neptune-core/issues/539
static CLAIMS_CACHE: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashSet<Claim>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

static CLAIMS_CACHE_ENABLED: std::sync::LazyLock<tokio::sync::Mutex<bool>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(true));

/// Verify a Triton VM (claim, proof) pair for default STARK parameters.
///
/// When the test flag is set, this function checks whether the claim is present
/// in the `CLAIMS_CACHE` and if so returns true early (*i.e.*, without running
/// the verifier). When the test flag is set and the cache does not contain the
/// claim and verification succeeds, the claim is added to the cache. The only
/// other way to populate the cache is through method `cache_true_claim`.
pub async fn verify(claim: Claim, proof: Proof, network: Network) -> bool {
    // security: we do not accept mock proofs unless we ourselves
    // are running a network that accepts mock-proofs, eg regtest.
    if network.use_mock_proof() {
        return proof.is_valid_mock();
    }

    {
        let is_enabled = *CLAIMS_CACHE_ENABLED.lock().await;
        if is_enabled && CLAIMS_CACHE.lock().await.contains(&claim) {
            return true;
        }
    }

    #[cfg(test)]
    let claim_clone = claim.clone();

    let verdict =
        task::spawn_blocking(move || triton_vm::verify(Stark::default(), &claim, &proof.into()))
            .await
            .expect("should be able to verify proof in new tokio task");

    // tbd: we might want to enable a cache for mainnet usage.
    // but we should probably use a cache that has a configurable max
    // size, so we don't blow up RAM.
    #[cfg(test)]
    if verdict {
        cache_true_claims([claim_clone]).await;
    }

    verdict
}

/// Add claims to the [`CLAIMS_CACHE`].
pub async fn cache_true_claims<IterClaims: IntoIterator<Item = Claim>>(claims: IterClaims) {
    let mut cache = CLAIMS_CACHE.lock().await;
    for claim in claims {
        cache.insert(claim);
    }
}

/// Disable the true [`CLAIMS_CACHE`].
#[cfg(test)]
pub async fn disable_true_claims_cache() {
    *CLAIMS_CACHE_ENABLED.lock().await = false;
}

/// Enable the true [`CLAIMS_CACHE`].
#[cfg(test)]
pub async fn enable_true_claims_cache() {
    *CLAIMS_CACHE_ENABLED.lock().await = true;
}
