mod client;
mod constants;
mod db;
mod handlers;
mod permissions;
mod server;
mod tlv;

use std::fs;
use std::sync::Arc;
use std::time::Duration;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tracing::{error, info};
use crate::constants::SERVER_PORT;

#[tokio::main]
async fn main() {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,turso_core=info,yggdrasil=info,ironwood=info,ygg_stream=info")),
        )
        .init();

    // Parse CLI args
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
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

    let peers = matches.opt_strs("p");
    if peers.is_empty() {
        eprintln!("Error: at least one --peer is required");
        eprintln!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        std::process::exit(1);
    }

    // Load or generate Ed25519 keypair
    let signing_key = load_or_gen_key(constants::KEY_FILE);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes: [u8; 32] = verifying_key.to_bytes();

    info!("Mediator started; pubkey: {}", hex::encode(&pub_bytes));

    // Init ygg_stream AsyncNode
    let node = match ygg_stream::AsyncNode::new_with_key(
        signing_key.to_bytes().as_slice(),
        peers,
    ).await {
        Ok(n) => Arc::new(n),
        Err(e) => {
            error!("Failed to create ygg_stream node: {}", e);
            std::process::exit(1);
        }
    };

    info!("ygg_stream node pubkey: {}", hex::encode(node.public_key()));

    // Init database
    let db = match db::Db::open(constants::DB_FILE).await {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to open database: {}", e);
            std::process::exit(1);
        }
    };

    // Build server state
    let state = server::ServerState::new(db, pub_bytes, signing_key);

    // Start invite cleanup worker
    let state2 = state.clone();
    tokio::spawn(async move {
        handlers::invite_cleanup_worker(state2).await;
    });

    info!("Listening for client requests…");

    // Run accept loop until Ctrl+C
    tokio::select! {
        _ = server::run_accept_loop(state, node.clone(), SERVER_PORT) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down mediator…");
        }
    }

    // Give the node a moment to clean up, then exit regardless
    let _ = tokio::time::timeout(Duration::from_secs(2), node.close()).await;
}

/// Load Ed25519 private key from file, or generate and save a new one.
pub fn load_or_gen_key(path: &str) -> SigningKey {
    if let Ok(data) = fs::read(path) {
        let seed: Option<[u8; 32]> = if data.len() == 32 {
            Some(data.try_into().unwrap())
        } else if data.len() == 64 {
            // Try to parse as hex-encoded seed
            let text = String::from_utf8_lossy(&data);
            let text = text.trim();
            hex::decode(text).ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        } else {
            // Handle hex with possible trailing newline/whitespace
            let text = String::from_utf8_lossy(&data);
            let text = text.trim();
            if text.len() == 64 {
                hex::decode(text).ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            } else {
                None
            }
        };
        if let Some(seed) = seed {
            let key = SigningKey::from_bytes(&seed);
            info!("Loaded key from {}, public: {}", path, hex::encode(key.verifying_key().as_bytes()));
            return key;
        }
    }

    let key = SigningKey::generate(&mut OsRng);
    if let Err(e) = fs::write(path, key.to_bytes()) {
        error!("Failed to save key: {}", e);
    }
    info!("Generated new key (saved to {}), public: {}", path, hex::encode(key.verifying_key().as_bytes()));
    key
}
