use kdx_client_core::ClientHandle;
use tokio::sync::Mutex;

/// App-wide state: the one active client connection, if any.
#[derive(Default)]
pub struct AppState {
    pub client: Mutex<Option<ClientHandle>>,
}
