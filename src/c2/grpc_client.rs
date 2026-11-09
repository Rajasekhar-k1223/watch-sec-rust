use std::fs;
use std::path::{Path, PathBuf};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use crate::config::AgentConfig;
use crate::c2::offline_queue;

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

/// Resolves the dedicated certificates directory relative to the executable
pub fn get_certs_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let certs_path = exe_dir.join("certs");
    if !certs_path.exists() {
        let _ = fs::create_dir_all(&certs_path);
    }
    certs_path
}

/// Atomically writes data to a file by writing to a temporary file then renaming
pub fn atomic_write_cert_file(target_path: &Path, content: &[u8]) -> std::io::Result<()> {
    if target_path.file_name().and_then(|n| n.to_str()) == Some("agent.key") {
        crate::c2::tpm_engine::HardwareSecurityEngine::secure_private_key_storage(target_path, content)
    } else {
        let tmp_path = target_path.with_extension("tmp");
        fs::write(&tmp_path, content)?;
        fs::rename(&tmp_path, target_path)?;
        Ok(())
    }
}

impl GrpcTelemetryClient {
    /// Establishes a hardened Mutual TLS (mTLS) connection to the Monitorix Telemetry Gateway.
    /// Strict client certificate authentication is enforced.
    pub async fn connect(config: &AgentConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let certs_dir = get_certs_dir();
        let ca_path = certs_dir.join("ca_chain.pem");
        let client_cert_path = certs_dir.join("agent.crt");
        let client_key_path = certs_dir.join("agent.key");

        // 1. Verify existence of Mutual TLS credentials
        if !ca_path.exists() || !client_cert_path.exists() || !client_key_path.exists() {
            let err_msg = format!(
                "[mTLS] Critical Security Error: Mutual TLS credentials missing in {:?}. \
                 Required: ca_chain.pem, agent.crt, agent.key. Insecure fallback is strictly forbidden.",
                certs_dir
            );
            eprintln!("{}", err_msg);
            return Err(err_msg.into());
        }

        // 2. Hardware Security Audit and strict permission enforcement on private key
        let hw_audit = crate::c2::tpm_engine::HardwareSecurityEngine::audit_hardware_status();
        println!("{}", hw_audit);
        let _ = crate::c2::tpm_engine::HardwareSecurityEngine::enforce_file_permissions(&client_key_path);

        // 3. Load cryptographic materials
        let ca_pem = fs::read(&ca_path)?;
        let client_cert_pem = fs::read(&client_cert_path)?;
        let client_key_pem = fs::read(&client_key_path)?;

        let ca_cert = Certificate::from_pem(ca_pem);
        let client_identity = Identity::from_pem(client_cert_pem, client_key_pem);

        // 3. Resolve destination URL and server domain
        let host_raw = config.backend_url.replace("https://", "").replace("http://", "");
        let host = host_raw.split('/').next().unwrap_or("localhost");
        let domain_for_sni = if host.contains(':') {
            host.split(':').next().unwrap_or("grpc-gateway")
        } else {
            host
        };

        let domain_for_sni = if domain_for_sni == "127.0.0.1" || domain_for_sni == "localhost" {
            "grpc-gateway"
        } else {
            domain_for_sni
        };

        let url = if host.contains(':') {
            format!("https://{}", host)
        } else {
            format!("https://{}:50051", host)
        };

        println!("[mTLS] Initializing secure channel to {} (SNI: {})", url, domain_for_sni);

        // 4. Configure strict ClientTlsConfig
        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .identity(client_identity)
            .domain_name(domain_for_sni);

        let endpoint = Channel::from_shared(url.clone())?
            .timeout(std::time::Duration::from_secs(15))
            .tls_config(tls_config)?;

        let client = TelemetryGatewayClient::connect(endpoint).await?;
        println!("[mTLS] Handshake successful! Connected to Telemetry Gateway at {}", url);

        Ok(Self {
            client,
            agent_id: config.agent_id.clone(),
            tenant_api_key: config.tenant_api_key.clone(),
        })
    }

    /// Streams events to the Gateway with offline buffering and recovery.
    pub async fn stream_events(&mut self, mut receiver: mpsc::Receiver<serde_json::Value>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = mpsc::channel(200);
        let rx_stream = ReceiverStream::new(rx);

        let agent_id = self.agent_id.clone();
        let tenant_id = self.tenant_api_key.clone();

        // 1. Flush previously buffered offline events first
        let buffered_events = offline_queue::flush_queue();
        if !buffered_events.is_empty() {
            println!("[mTLS Telemetry] Replaying {} buffered offline events...", buffered_events.len());
            for ev in buffered_events {
                let event_type = ev.get("EventType").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                let proto_event = AgentEvent {
                    agent_id: agent_id.clone(),
                    tenant_id: tenant_id.clone(),
                    event_type,
                    payload: ev.to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                let _ = tx.send(proto_event).await;
            }
        }

        // 2. Bridge live events
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

                if let Err(_) = tx.send(proto_event).await {
                    // Channel disconnected: buffer event to local disk queue to preserve data
                    offline_queue::enqueue_event(&event_json);
                    break;
                }
            }
        });

        // 3. Initiate client-streaming RPC
        match self.client.stream_events(rx_stream).await {
            Ok(response) => {
                println!("[mTLS Telemetry] Gateway response: {:?}", response.into_inner());
                Ok(())
            }
            Err(e) => {
                eprintln!("[mTLS Telemetry] Stream error: {}", e);
                Err(Box::new(e))
            }
        }
    }
}
