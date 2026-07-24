use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use nyks_rpc_core::api::client::transport::Transport;
use nyks_rpc_core::model::json::JsonError;
use nyks_rpc_core::model::json::JsonRequest;
use nyks_rpc_core::model::json::JsonResponse;
use nyks_rpc_core::model::json::JsonResult;
use reqwest::Client;

#[derive(Clone, Debug)]
pub struct HttpClient {
    url: String,
    client: Client,
    last_id: Arc<AtomicU64>,
}

impl HttpClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: Client::new(),
            last_id: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl Transport for HttpClient {
    async fn call(&self, method: &str, params: serde_json::Value) -> JsonResult<serde_json::Value> {
        let request = JsonRequest {
            jsonrpc: Some("2.0".to_string()),
            method: method.to_string(),
            params,
            id: Some(self.last_id.fetch_add(1, Ordering::SeqCst).into()),
        };

        let response = self.client.post(&self.url).json(&request).send().await;
        let response = match response {
            Ok(resp) => resp,
            Err(err) => {
                return Err(JsonError::ConnectionFailed {
                    message: err.to_string(),
                });
            }
        };

        let status_code = response.status();
        if !status_code.is_success() {
            return Err(JsonError::HttpError {
                message: status_code.to_string(),
            });
        }

        let response: serde_json::Value =
            response.json().await.map_err(|_| JsonError::ParseError)?;
        let response: JsonResponse =
            serde_json::from_value(response).map_err(|_| JsonError::ParseError)?;

        match response {
            JsonResponse::Success { result, .. } => Ok(result),
            JsonResponse::Error { error, .. } => Err(error),
        }
    }
}
