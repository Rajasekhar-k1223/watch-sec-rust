use tonic::transport::Channel;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use crate::config::AgentConfig;

// Include the auto-generated code from tonic
pub mod telemetry {
    tonic::include_proto!("telemetry"); // The string matches the package name in proto file
}

use telemetry::telemetry_gateway_client::TelemetryGatewayClient;
use telemetry::AgentEvent;

pub struct GrpcTelemetryClient {
    client: TelemetryGatewayClient<Channel>,
    agent_id: String,
    tenant_api_key: String,
}

impl GrpcTelemetryClient {
    pub async fn connect(config: &AgentConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Parse the hostname from backend_url and append the gRPC port 50051
        let host = config.backend_url.replace("https://", "").replace("http://", "");
        let host = host.split('/').next().unwrap_or("localhost");
        
        let url = if host.contains(':') {
            format!("http://{}", host)
        } else {
            format!("http://{}:50051", host)
        };
        
        let endpoint = Channel::from_shared(url.clone())?
            .timeout(std::time::Duration::from_secs(10));
        let client = TelemetryGatewayClient::connect(endpoint).await?;
        println!("[gRPC] Connected to Telemetry Gateway at {}", url);
        
        Ok(Self {
            client,
            agent_id: config.agent_id.clone(),
            tenant_api_key: config.tenant_api_key.clone(),
        })
    }

    pub async fn stream_events(&mut self, mut receiver: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = mpsc::channel(100);
        let rx_stream = ReceiverStream::new(rx);
        
        let agent_id = self.agent_id.clone();
        let tenant_id = self.tenant_api_key.clone(); // Passing api_key as tenant_id for now

        // Spawn a task to bridge our internal JSON events into Protobuf AgentEvents
        tokio::spawn(async move {
            while let Some(event_json) = receiver.recv().await {
                let event_type = event_json.get("EventType").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                let payload = event_json.to_string();
                
                let proto_event = AgentEvent {
                    agent_id: agent_id.clone(),
                    tenant_id: tenant_id.clone(),
                    event_type,
                    payload,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                
                if tx.send(proto_event).await.is_err() {
                    break;
                }
            }
        });

        // Send the stream to the server
        let response = self.client.stream_events(rx_stream).await?;
        println!("[gRPC] Server responded: {:?}", response.into_inner());

        Ok(())
    }
}
