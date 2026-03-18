use crate::client::ClientConn;
use crate::db::Db;
use crate::constants::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Unique ID for each client connection (pointer-based in Go, we use a counter).
pub type ClientId = u64;

pub struct ServerState {
    pub db: Arc<Db>,
    pub mediator_pub: [u8; 32],
    #[allow(dead_code)]
    pub mediator_priv: ed25519_dalek::SigningKey,

    // Chat subscriptions: chatID -> set of client IDs
    pub chat_subs: RwLock<HashMap<i64, HashSet<ClientId>>>,

    // Active client connections: client_id -> weak sender handle
    pub clients: RwLock<HashMap<ClientId, Arc<ClientConn>>>,

    // Authenticated clients: pubkey -> set of client IDs (multi-device)
    pub auth_clients: RwLock<HashMap<[u8; 32], HashSet<ClientId>>>,

    // Address-based dedup: "pubkey_hex:addr" -> client_id
    pub addr_conn_map: RwLock<HashMap<String, ClientId>>,

    // Counter for assigning client IDs
    next_client_id: std::sync::atomic::AtomicU64,
}

impl ServerState {
    pub fn new(
        db: Arc<Db>,
        mediator_pub: [u8; 32],
        mediator_priv: ed25519_dalek::SigningKey,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            mediator_pub,
            mediator_priv,
            chat_subs: RwLock::new(HashMap::new()),
            clients: RwLock::new(HashMap::new()),
            auth_clients: RwLock::new(HashMap::new()),
            addr_conn_map: RwLock::new(HashMap::new()),
            next_client_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    pub fn next_id(&self) -> ClientId {
        self.next_client_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Subscribe a client to a chat.
    pub async fn subscribe(&self, chat_id: i64, client_id: ClientId, client: &Arc<ClientConn>) {
        {
            let mut subs = self.chat_subs.write().await;
            subs.entry(chat_id).or_default().insert(client_id);
        }
        {
            let mut chats = client.chats.write().await;
            chats.insert(chat_id);
        }

        // Broadcast online status
        let pub_key = {
            let guard = client.pub_key.read().await;
            *guard
        };
        if client.is_authed().await {
            let ts = now_unix();
            let state = self.clone_arc();
            tokio::spawn(async move {
                crate::handlers::broadcast_member_online_status(&state, chat_id, pub_key, true, ts).await;
            });
        }
    }

    /// Unsubscribe a client from all chats (called on disconnect).
    pub async fn unsubscribe_all(&self, client_id: ClientId, client: &Arc<ClientConn>) {
        let timestamp = now_unix();
        let chats_to_notify: Vec<i64>;

        {
            let mut client_chats = client.chats.write().await;
            chats_to_notify = client_chats.drain().collect();
        }

        {
            let mut subs = self.chat_subs.write().await;
            for &chat_id in &chats_to_notify {
                if let Some(set) = subs.get_mut(&chat_id) {
                    set.remove(&client_id);
                    if set.is_empty() {
                        subs.remove(&chat_id);
                    }
                }
            }
        }

        if client.is_authed().await {
            let pub_key = *client.pub_key.read().await;
            let addr = client.addr.clone();
            let addr_key = get_addr_key(&pub_key, &addr);

            {
                let mut auth = self.auth_clients.write().await;
                let mut addr_map = self.addr_conn_map.write().await;

                // Remove from addr map only if it's still this connection
                if let Some(&stored_id) = addr_map.get(&addr_key) {
                    if stored_id == client_id {
                        addr_map.remove(&addr_key);
                    }
                }

                if let Some(conns) = auth.get_mut(&pub_key) {
                    conns.remove(&client_id);
                    if conns.is_empty() {
                        auth.remove(&pub_key);
                    }
                }
            }

            // Update last_seen and broadcast offline
            for &chat_id in &chats_to_notify {
                let users_tbl = format!("users_{}", chat_id);
                {
                    let _guard = self.db.write_mu.lock().await;
                    let q = format!("UPDATE \"{}\" SET last_seen=?1 WHERE pubkey=?2", users_tbl);
                    let _ = client.db_conn.execute(&q, turso::params![timestamp, pub_key.as_slice()]).await;
                }

                let state = self.clone_arc();
                let pk = pub_key;
                tokio::spawn(async move {
                    crate::handlers::broadcast_member_online_status(&state, chat_id, pk, false, timestamp).await;
                });
            }
        }
    }

    /// Broadcast a message payload to all subscribers of a chat except sender.
    pub async fn broadcast_message(&self, chat_id: i64, sender_id: Option<ClientId>, payload: Vec<u8>) {
        let subscriber_ids: Vec<ClientId> = {
            let subs = self.chat_subs.read().await;
            match subs.get(&chat_id) {
                Some(set) => set.iter().copied().collect(),
                None => return,
            }
        };

        let clients = self.clients.read().await;
        for cid in subscriber_ids {
            if Some(cid) == sender_id {
                continue;
            }
            if let Some(client) = clients.get(&cid) {
                let c = client.clone();
                let p = payload.clone();
                tokio::spawn(async move {
                    let _ = c.write_push(CMD_GOT_MESSAGE as u16, &p).await;
                });
            }
        }
    }

    /// Broadcast with a custom command to all chat subscribers except sender.
    pub async fn broadcast_to_chat(&self, chat_id: i64, sender_id: Option<ClientId>, cmd: u16, payload: Vec<u8>) {
        let subscriber_ids: Vec<ClientId> = {
            let subs = self.chat_subs.read().await;
            match subs.get(&chat_id) {
                Some(set) => set.iter().copied().collect(),
                None => return,
            }
        };

        let clients = self.clients.read().await;
        for cid in subscriber_ids {
            if Some(cid) == sender_id {
                continue;
            }
            if let Some(client) = clients.get(&cid) {
                let c = client.clone();
                let p = payload.clone();
                tokio::spawn(async move {
                    let _ = c.write_push(cmd, &p).await;
                });
            }
        }
    }

    fn clone_arc(&self) -> Arc<Self> {
        // This is called on &self which is behind Arc, we need to get the Arc.
        // We'll pass Arc<ServerState> through the call chain instead.
        // For now, this is a workaround - callers should pass Arc directly.
        unsafe {
            let ptr = self as *const Self;
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }
}

pub fn get_addr_key(pubkey: &[u8; 32], addr: &str) -> String {
    format!("{}:{}", hex::encode(pubkey), addr)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Run the accept loop using ygg_stream AsyncNode.
pub async fn run_accept_loop(state: Arc<ServerState>, node: Arc<ygg_stream::AsyncNode>, port: u16) {
    info!("Listening for client connections on port {}", port);

    loop {
        let conn = match node.accept(port).await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Accept error: {}", e);
                continue;
            }
        };

        let client_id = state.next_id();
        let num_clients = state.clients.read().await.len() + 1;
        let remote_pub = conn.public_key();
        info!("Client {}: connected from {}, total {}", client_id, hex::encode(&remote_pub), num_clients);

        let state2 = state.clone();
        tokio::spawn(async move {
            crate::client::serve_client(state2, conn, client_id).await;
        });
    }
}
