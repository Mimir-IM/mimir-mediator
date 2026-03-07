use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tokio::time::sleep;
use tracing::{error, info, warn};

use mimir_mediator::constants::*;
use mimir_mediator::tlv::*;

// ── Response frame ───────────────────────────────────────────────────────────

struct ResponseFrame {
    status: u8,
    #[allow(dead_code)]
    req_id: u16,
    payload: Vec<u8>,
}

/// Parse error message from mediator error response payload: [msg_len:2][msg_bytes]
fn parse_error_msg(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return String::new();
    }
    let msg_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + msg_len {
        return String::new();
    }
    String::from_utf8_lossy(&payload[2..2 + msg_len]).to_string()
}

// ── StressClient ─────────────────────────────────────────────────────────────

struct StressClient {
    conn: ygg_stream::AsyncConn,
    signing_key: SigningKey,
    pub_key: [u8; 32],
    next_req_id: AtomicU16,
}

impl StressClient {
    /// Read exactly `n` bytes from the connection.
    async fn read_exact(&self, buf: &mut [u8]) -> Result<(), String> {
        let mut offset = 0;
        while offset < buf.len() {
            match self.conn.read_with_timeout(&mut buf[offset..], 30_000).await {
                Ok(0) => return Err("connection closed".into()),
                Ok(n) => offset += n,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Read one response frame: [status:1][reqId:2][len:4][payload]
    async fn read_response(&self) -> Result<ResponseFrame, String> {
        let mut hdr = [0u8; 7];
        self.read_exact(&mut hdr).await?;
        let status = hdr[0];
        let req_id = u16::from_be_bytes([hdr[1], hdr[2]]);
        let len = u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.read_exact(&mut payload).await?;
        }
        Ok(ResponseFrame { status, req_id, payload })
    }

    /// Write a request frame: [cmd:1][reqId:2][len:4][payload]
    async fn write_frame(&self, cmd: u8, req_id: u16, payload: &[u8]) -> Result<(), String> {
        let mut buf = Vec::with_capacity(7 + payload.len());
        buf.push(cmd);
        buf.extend_from_slice(&req_id.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        self.conn.write(&buf).await.map(|_| ())
    }

    /// Send a request and read the response (sequential request-response).
    async fn send_request(&self, cmd: u8, payload: &[u8]) -> Result<ResponseFrame, String> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        self.write_frame(cmd, req_id, payload).await?;
        self.read_response().await
    }
}

// ── Connect and authenticate ─────────────────────────────────────────────────

async fn connect_and_auth(node: &ygg_stream::AsyncNode, mediator_pubkey: &[u8], signing_key: SigningKey) -> Result<StressClient, String> {
    let pub_key = signing_key.verifying_key().to_bytes();

    let conn = node.connect(mediator_pubkey, SERVER_PORT).await?;

    // Handshake: [VERSION][PROTO_CLIENT]
    conn.write(&[VERSION, PROTO_CLIENT]).await.map(|_| ())?;

    let client = StressClient {
        conn,
        signing_key,
        pub_key,
        next_req_id: AtomicU16::new(1),
    };

    // GET_NONCE
    let payload = build_tlv_payload(|w| tlv_encode_bytes(w, TAG_PUBKEY, &pub_key))
        .map_err(|e| e.to_string())?;
    let resp = client.send_request(CMD_GET_NONCE, &payload).await?;
    if resp.status != STATUS_OK {
        return Err(format!("GET_NONCE failed: status=0x{:02X} {}", resp.status, parse_error_msg(&resp.payload)));
    }
    let tlvs = parse_tlvs(&resp.payload).map_err(|e| e.to_string())?;
    let nonce = tlv_get_bytes(&tlvs, TAG_NONCE, 32)?.to_vec();

    // Sign the nonce
    let signature = client.signing_key.sign(&nonce);

    // AUTH
    let auth_payload = build_tlv_payload(|w| {
        tlv_encode_bytes(w, TAG_PUBKEY, &pub_key)?;
        tlv_encode_bytes(w, TAG_NONCE, &nonce)?;
        tlv_encode_bytes(w, TAG_SIGNATURE, &signature.to_bytes())
    }).map_err(|e| e.to_string())?;
    let resp = client.send_request(CMD_AUTH, &auth_payload).await?;
    if resp.status != STATUS_OK {
        return Err(format!("AUTH failed: status=0x{:02X} {}", resp.status, parse_error_msg(&resp.payload)));
    }

    Ok(client)
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,yggdrasil=warn,ironwood=warn,ygg_stream=warn")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.reqopt("a", "addr", "Mediator public key (hex, 64 chars)", "PUBKEY");
    opts.optopt("n", "clients", "Number of concurrent clients (default: 5)", "N");
    opts.optmulti("p", "peer", "Yggdrasil peer URI (repeatable)", "URI");
    opts.optflag("h", "help", "Show help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
            std::process::exit(1);
        }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        return;
    }

    let addr_hex = matches.opt_str("a").unwrap();
    let mediator_pubkey = hex::decode(&addr_hex).expect("invalid hex pubkey");
    if mediator_pubkey.len() != 32 {
        eprintln!("Error: pubkey must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }

    let num_clients: usize = matches
        .opt_str("n")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let peers = matches.opt_strs("p");
    if peers.is_empty() {
        eprintln!("Error: at least one --peer is required");
        std::process::exit(1);
    }

    info!("Starting stress test: {} clients, mediator={}", num_clients, &addr_hex[..8]);

    let total_pings = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let mut handles = Vec::with_capacity(num_clients);

    for i in 0..num_clients {
        let peers = peers.clone();
        let mediator_pubkey = mediator_pubkey.clone();
        let total_pings = total_pings.clone();
        let total_errors = total_errors.clone();

        let handle = tokio::spawn(async move {
            // Each client gets its own AsyncNode with a unique Yggdrasil identity
            let node_key = SigningKey::generate(&mut OsRng);
            let node = match ygg_stream::AsyncNode::new_with_key(node_key.to_bytes().as_slice(), peers).await {
                Ok(n) => n,
                Err(e) => {
                    error!("client {}: failed to create node: {}", i, e);
                    return;
                }
            };

            // Separate Ed25519 keypair for protocol-level authentication
            let auth_key = SigningKey::generate(&mut OsRng);
            sleep(Duration::from_secs(10 + i as u64)).await;

            info!("client {}: connecting...", i);
            let client = match connect_and_auth(&node, &mediator_pubkey, auth_key).await {
                Ok(c) => c,
                Err(e) => {
                    error!("client {}: auth failed: {}", i, e);
                    node.close().await;
                    return;
                }
            };
            info!("client {}: authenticated ({})", i, hex::encode(&client.pub_key[..4]));

            // Send pings every second for 10 seconds
            for ping_num in 0..10 {
                match client.send_request(CMD_PING, &[]).await {
                    Ok(resp) if resp.status == STATUS_OK => {
                        total_pings.fetch_add(1, Ordering::Relaxed);
                        info!("client {}: ping {}/10 OK", i, ping_num + 1);
                    }
                    Ok(resp) => {
                        total_errors.fetch_add(1, Ordering::Relaxed);
                        warn!("client {}: ping {} error status=0x{:02X}", i, ping_num + 1, resp.status);
                    }
                    Err(e) => {
                        total_errors.fetch_add(1, Ordering::Relaxed);
                        warn!("client {}: ping {} failed: {}", i, ping_num + 1, e);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            client.conn.close().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), node.close()).await;
            info!("client {}: done", i);
        });

        handles.push(handle);
    }

    // Wait for all clients to finish
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let pings = total_pings.load(Ordering::Relaxed);
    let errors = total_errors.load(Ordering::Relaxed);

    println!();
    println!("=== Stress Test Results ===");
    println!("Duration:    {:.1}s", elapsed.as_secs_f64());
    println!("Clients:     {}", num_clients);
    println!("Pings OK:    {}", pings);
    println!("Errors:      {}", errors);
    println!("Expected:    {}", num_clients * 10);
    if pings + errors > 0 {
        println!("Success:     {:.1}%", pings as f64 / (pings + errors) as f64 * 100.0);
    }
}
