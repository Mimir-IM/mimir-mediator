mod cache;
mod client;
mod constants;
mod db;
mod handlers;
mod permissions;
mod server;
mod tlv;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use crate::constants::SERVER_PORT;

#[tokio::main]
async fn main() {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug,turso_core=info,yggdrasil=info,ironwood=info,ygg_stream=info")),
        )
        .init();

    // Parse CLI args
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optmulti("p", "peer", "Yggdrasil peer URI (repeatable)", "URI");
    opts.optopt("c", "cache-days", "Days to cache messages (default: 1)", "DAYS");
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

    let cache_days: u64 = matches
        .opt_str("c")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // Load or generate Ed25519 keypair
    let signing_key = load_or_gen_key(constants::KEY_FILE);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes: [u8; 32] = verifying_key.to_bytes();

    info!("mediator started; pubkey: {}", hex::encode(&pub_bytes));

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

    // Init hybrid cache
    let cache_ttl = Duration::from_secs(cache_days * 24 * 3600);
    let cache_path = PathBuf::from("mediator-cache");
    let cache = match cache::HybridCache::new(&cache_path, 512 * 1024 * 1024, cache_ttl) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to init cache: {}", e);
            std::process::exit(1);
        }
    };

    // Build server state
    let state = server::ServerState::new(db, cache.clone(), pub_bytes, signing_key);

    // Start invite cleanup worker
    let state2 = state.clone();
    tokio::spawn(async move {
        handlers::invite_cleanup_worker(state2).await;
    });

    // Start cache GC worker
    let cache2 = cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30 * 60));
        loop {
            interval.tick().await;
            cache2.gc();
        }
    });

    info!("listening for client requests…");

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
fn load_or_gen_key(path: &str) -> ed25519_dalek::SigningKey {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // Try to load existing key (64-byte format: seed || public, we only need first 32)
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 64 {
            // Go Ed25519 private key format: 32-byte seed + 32-byte public key
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            let key = SigningKey::from_bytes(&seed);
            info!(
                "Loaded mediator key from {} – public: {}",
                path,
                hex::encode(key.verifying_key().as_bytes())
            );
            return key;
        } else if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let key = SigningKey::from_bytes(&seed);
            info!(
                "Loaded mediator key from {} – public: {}",
                path,
                hex::encode(key.verifying_key().as_bytes())
            );
            return key;
        }
    }

    // Generate new key
    let key = SigningKey::generate(&mut OsRng);
    // Save in Go-compatible 64-byte format: seed + public
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(key.as_bytes());
    buf[32..].copy_from_slice(key.verifying_key().as_bytes());

    if let Err(e) = std::fs::write(path, &buf) {
        error!("Failed to save key to {}: {}", path, e);
        std::process::exit(1);
    }

    info!(
        "Generated new mediator key (saved to {}) – public: {}",
        path,
        hex::encode(key.verifying_key().as_bytes())
    );
    key
}
