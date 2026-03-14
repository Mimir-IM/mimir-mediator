use crate::constants::*;
use crate::server::{ClientId, ServerState};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug};

/// Per-connection state.
pub struct ClientConn {
    pub id: ClientId,
    pub conn: ygg_stream::AsyncConn,
    pub db_conn: turso::Connection,
    pub authed: RwLock<bool>,
    pub pub_key: RwLock<[u8; 32]>,
    pub chats: RwLock<HashSet<i64>>,
    pub addr: String,
    write_mu: Mutex<()>,
}

impl ClientConn {
    pub fn new(id: ClientId, conn: ygg_stream::AsyncConn, db_conn: turso::Connection) -> Arc<Self> {
        let addr = hex::encode(conn.public_key());
        Arc::new(Self {
            id,
            conn,
            db_conn,
            authed: RwLock::new(false),
            pub_key: RwLock::new([0u8; 32]),
            chats: RwLock::new(HashSet::new()),
            addr,
            write_mu: Mutex::new(()),
        })
    }

    pub async fn is_authed(&self) -> bool {
        *self.authed.read().await
    }

    /// Write an OK response (task-safe).
    pub async fn write_ok(&self, req_id: u16, payload: &[u8]) -> Result<(), String> {
        let _guard = self.write_mu.lock().await;

        let mut hdr = [0u8; 7];
        hdr[0] = STATUS_OK;
        hdr[1..3].copy_from_slice(&req_id.to_be_bytes());
        hdr[3..7].copy_from_slice(&(payload.len() as u32).to_be_bytes());

        let mut buf = Vec::with_capacity(7 + payload.len());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(payload);

        self.conn.write(&buf).await.map(|_| ())
    }

    /// Write a server-initiated push (task-safe).
    pub async fn write_push(&self, cmd: u16, payload: &[u8]) -> Result<(), String> {
        let _guard = self.write_mu.lock().await;

        let mut hdr = [0u8; 7];
        hdr[0] = STATUS_PUSH;
        hdr[1..3].copy_from_slice(&cmd.to_be_bytes());
        hdr[3..7].copy_from_slice(&(payload.len() as u32).to_be_bytes());

        let mut buf = Vec::with_capacity(7 + payload.len());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(payload);

        self.conn.write(&buf).await.map(|_| ())
    }

    /// Write an error response (task-safe).
    pub async fn write_err(&self, req_id: u16, msg: &str) -> Result<(), String> {
        debug!("sending error for reqId={}: {}", req_id, msg);
        let _guard = self.write_mu.lock().await;

        let msg_bytes = msg.as_bytes();
        let inner_len = 2 + msg_bytes.len();

        let mut hdr = [0u8; 7];
        hdr[0] = STATUS_ERR;
        hdr[1..3].copy_from_slice(&req_id.to_be_bytes());
        hdr[3..7].copy_from_slice(&(inner_len as u32).to_be_bytes());

        let mut buf = Vec::with_capacity(7 + inner_len);
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(msg_bytes);

        self.conn.write(&buf).await.map(|_| ())
    }

    /// Async read of exactly `n` bytes. Returns Err on short read or error.
    async fn read_exact(&self, buf: &mut [u8]) -> Result<(), String> {
        let mut offset = 0;
        while offset < buf.len() {
            match self.conn.read_with_timeout(&mut buf[offset..], 300_000).await {
                Ok(0) => return Err("connection closed".to_string()),
                Ok(n) => offset += n,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Serve a single client connection.
pub async fn serve_client(state: Arc<ServerState>, conn: ygg_stream::AsyncConn, client_id: ClientId) {
    let db_conn = match state.db.connect() {
        Ok(c) => c,
        Err(e) => {
            debug!("client {}: failed to create db connection: {}", client_id, e);
            return;
        }
    };
    let client = ClientConn::new(client_id, conn, db_conn);

    // Read init bytes: [version:1][protoType:1]
    {
        debug!("Reading version and proto");
        let mut init_buf = [0u8; 2];
        match client.read_exact(&mut init_buf).await {
            Ok(()) => {
                if init_buf[0] != VERSION {
                    debug!("client {}: invalid version 0x{:02X}", client_id, init_buf[0]);
                    return;
                }
                if init_buf[1] != PROTO_CLIENT {
                    debug!("client {}: invalid proto type 0x{:02X}", client_id, init_buf[1]);
                    return;
                }
            }
            Err(e) => {
                debug!("client {}: failed to read init bytes: {}", client_id, e);
                return;
            }
        }
    }

    // Register client
    {
        let mut clients = state.clients.write().await;
        clients.insert(client_id, client.clone());
    }

    debug!("client {}: initialized, entering command loop", client_id);

    // Command loop
    loop {
        // Read frame: [cmd:1][reqId:2][len:4][payload]
        let mut hdr = [0u8; 7];
        if let Err(e) = client.read_exact(&mut hdr).await {
            debug!("client {}: read error: {}", client_id, e);
            break;
        }

        let cmd = hdr[0];
        let req_id = u16::from_be_bytes([hdr[1], hdr[2]]);
        let plen = u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]);

        if plen > MAX_PAYLOAD {
            debug!("client {}: payload too large", client_id);
            break;
        }

        let payload = if plen > 0 {
            let mut buf = vec![0u8; plen as usize];
            if let Err(e) = client.read_exact(&mut buf).await {
                debug!("client {}: read error: {}", client_id, e);
                break;
            }
            buf
        } else {
            Vec::new()
        };

        debug!("client {}: cmd=0x{:02X} reqId={} payloadLen={}", client_id, cmd, req_id, payload.len());
        crate::handlers::dispatch(&state, &client, cmd, req_id, &payload).await;
    }

    // Cleanup
    state.unsubscribe_all(client_id, &client).await;
    {
        let mut clients = state.clients.write().await;
        clients.remove(&client_id);
    }
    client.conn.close().await;
    debug!("client {}: disconnected", client_id);
}
