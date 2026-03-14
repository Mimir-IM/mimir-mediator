use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use moka::future::Cache;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Two-tier cache: moka (RAM, 2-min TTL) + fjall (disk, configurable TTL).
pub struct HybridCache {
    mem: Cache<String, Vec<u8>>,
    #[allow(dead_code)]
    db: Database,
    blobs: Keyspace,
    disk_ttl: Duration,
}

impl HybridCache {
    pub fn new(db_path: &Path, mem_max_bytes: u64, disk_ttl: Duration) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let mem = Cache::builder()
            .max_capacity(mem_max_bytes)
            .time_to_live(Duration::from_secs(120))
            .build();

        let db = Database::builder(db_path).open()?;
        let blobs = db.keyspace("blobs", KeyspaceCreateOptions::default)?;

        Ok(Arc::new(Self { mem, db, blobs, disk_ttl }))
    }

    /// Store value in both RAM and disk tiers.
    pub async fn set(&self, key: &str, val: &[u8]) {
        self.mem.insert(key.to_string(), val.to_vec()).await;

        // Disk: store as (timestamp_u64_be || value)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut entry = Vec::with_capacity(8 + val.len());
        entry.extend_from_slice(&now.to_be_bytes());
        entry.extend_from_slice(val);

        if let Err(e) = self.disk_set(key, &entry) {
            warn!("cache disk set error: {}", e);
        }
    }

    fn disk_set(&self, key: &str, entry: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.blobs.insert(key, entry)?;
        Ok(())
    }

    /// Get value from RAM, falling back to disk.
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        // RAM first
        if let Some(val) = self.mem.get(key).await {
            return Some(val);
        }

        // Disk fallback
        match self.disk_get(key) {
            Ok(Some((ts, val))) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now.saturating_sub(ts) > self.disk_ttl.as_secs() {
                    return None; // expired
                }
                // Re-populate RAM
                self.mem.insert(key.to_string(), val.clone()).await;
                Some(val)
            }
            Ok(None) => None,
            Err(e) => {
                warn!("cache disk get error: {}", e);
                None
            }
        }
    }

    fn disk_get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
        match self.blobs.get(key)? {
            Some(slice) => {
                if slice.len() < 8 {
                    return Ok(None);
                }
                let ts = u64::from_be_bytes(slice[..8].try_into().unwrap());
                let val = slice[8..].to_vec();
                Ok(Some((ts, val)))
            }
            None => Ok(None),
        }
    }

    /// Periodic GC: delete disk entries older than TTL.
    pub fn gc(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now.saturating_sub(self.disk_ttl.as_secs());

        let mut expired: Vec<Vec<u8>> = Vec::new();
        for guard in self.blobs.iter() {
            match guard.into_inner() {
                Ok((key, val)) => {
                    if val.len() >= 8 {
                        let ts = u64::from_be_bytes(val[..8].try_into().unwrap());
                        if ts < cutoff {
                            expired.push(key.to_vec());
                        }
                    }
                }
                Err(e) => {
                    warn!("cache gc: iter error: {}", e);
                    return;
                }
            }
        }

        for key in &expired {
            if let Err(e) = self.blobs.remove(key.as_slice()) {
                warn!("cache gc: remove failed: {}", e);
            }
        }
    }
}
