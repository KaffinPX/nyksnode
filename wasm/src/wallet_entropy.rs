use nyks_consensus::network::Network;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy as Inner;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WalletEntropy {
    inner: Inner,
}

#[wasm_bindgen]
impl WalletEntropy {
    #[wasm_bindgen(constructor)]
    pub fn new(phrase: String) -> Result<WalletEntropy, JsValue> {
        let phrase: Vec<String> = phrase.split_whitespace().map(|s| s.to_string()).collect();

        Inner::from_phrase(&phrase)
            .map(|e| WalletEntropy { inner: e })
            .map_err(|e| JsValue::from_str(&format!("Error creating wallet entropy: {}", e)))
    }

    #[wasm_bindgen(js_name = "nthGenerationAddress")]
    pub fn nth_generation_address(&self, index: u64) -> String {
        let address = self.inner.nth_generation_address(index);

        address.to_bech32m(Network::Testnet(0))
    }

    #[wasm_bindgen(js_name = "nthSymmetricAddress")]
    pub fn nth_symmetric_address(&self, index: u64) -> String {
        let address = self.inner.nth_symmetric_address(index);

        address.to_bech32m(Network::Testnet(0))
    }
}
