use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::routing::post;
use axum::Json;
use axum::Router;
use tokio::net::TcpListener;

use crate::application::rpc::server::RpcServer;
use nyks_rpc_core::api::ops::RpcMethods;
use nyks_rpc_core::api::rpc::RpcApi;
use nyks_rpc_core::api::server::router::RpcRouter;
use nyks_rpc_core::model::json::JsonError;
use nyks_rpc_core::model::json::JsonRequest;
use nyks_rpc_core::model::json::JsonResponse;

// 20 MB, enough for most cases...
const MAX_REQUEST_SIZE_IN_BYTES: usize = 20 * 1024 * 1024;

impl RpcServer {
    /// Starts the HTTP RPC server.
    ///
    /// All RPC endpoints are accessible via `POST` requests to the root path `/`.
    /// The specific method is selected using the `method` field in the JSON request body,
    /// formatted as `namespace_method`.
    pub async fn serve_http(&self, listener: TcpListener) {
        let api: Arc<dyn RpcApi> = Arc::new(self.clone());
        let namespaces = self.enabled_namespaces().await;
        let router = RpcMethods::new_router(api, namespaces);

        let app = Router::new()
            .route("/", post(Self::rpc_handler))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_SIZE_IN_BYTES))
            .with_state(Arc::new(router));

        axum::serve(listener, app).await.unwrap();
    }

    /// Handles incoming RPC requests.
    ///
    /// # Request Body
    ///
    /// Expects a JSON-RPC 2.0 compliant body with the following fields:
    /// - `jsonrpc`: `"2.0"`
    /// - `method`: The RPC method to call, formatted as `namespace_method`
    /// - `params`: An array of parameters to pass to the method
    /// - `id` (optional): Request identifier for matching responses
    ///
    /// # Response
    ///
    /// Returns a JSON-RPC 2.0 response:
    /// - On success:
    ///   `{
    ///       "jsonrpc": "2.0",
    ///       "id": <request_id>,
    ///       "result": <method_result>
    ///   }`
    ///
    /// - On error:
    ///   `{
    ///       "jsonrpc": "2.0",
    ///       "id": <request_id>,
    ///       "error": {
    ///           "code": <error_code>,
    ///           "message": <error_message>
    ///       }
    ///   }`
    ///
    /// # Example
    ///
    /// Request:
    /// ```json
    /// POST /
    /// {
    ///     "method": "node_network",
    ///     "params": [],
    ///     "id": 1
    /// }
    /// ```
    ///
    /// Success Response:
    /// ```json
    /// {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "result": { "network": "main" }
    /// }
    /// ```
    ///
    /// Error Response:
    /// ```json
    /// {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "error": {
    ///         "code": -32601,
    ///         "message": "Method not found"
    ///     }
    /// }
    /// ```
    async fn rpc_handler(
        State(router): State<Arc<RpcRouter>>,
        body: axum::body::Bytes,
    ) -> Json<JsonResponse> {
        let request: JsonRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(_) => {
                return Json(JsonResponse::error(None, JsonError::ParseError));
            }
        };

        let res = router.dispatch(&request.method, request.params).await;
        let response = match res {
            Ok(result) => JsonResponse::success(request.id, result),
            Err(error) => JsonResponse::error(request.id, error),
        };

        Json(response)
    }
}
