use moka::future::Cache;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");

/// Two-tier cache: moka (RAM, 2-min TTL) + redb (disk, configurable TTL).
pub struct HybridCache {
    mem: Cache<String, Vec<u8>>,
    disk: Database,
    disk_ttl: Duration,
}

impl HybridCache {
    pub fn new(db_path: &Path, mem_max_bytes: u64, disk_ttl: Duration) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let mem = Cache::builder()
            .max_capacity(mem_max_bytes)
            .time_to_live(Duration::from_secs(120))
            .build();

        let disk = Database::create(db_path)?;

        // Ensure table exists
        let write_txn = disk.begin_write()?;
        {
            let _ = write_txn.open_table(TABLE)?;
        }
        write_txn.commit()?;

        Ok(Arc::new(Self { mem, disk, disk_ttl }))
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
        let write_txn = self.disk.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE)?;
            table.insert(key, entry)?;
        }
        write_txn.commit()?;
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
        let read_txn = self.disk.begin_read()?;
        let table = read_txn.open_table(TABLE)?;
        match table.get(key)? {
            Some(guard) => {
                let entry = guard.value();
                if entry.len() < 8 {
                    return Ok(None);
                }
                let ts = u64::from_be_bytes(entry[..8].try_into().unwrap());
                let val = entry[8..].to_vec();
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

        let write_txn = match self.disk.begin_write() {
            Ok(t) => t,
            Err(e) => {
                warn!("cache gc: begin_write failed: {}", e);
                return;
            }
        };
        {
            let mut table = match write_txn.open_table(TABLE) {
                Ok(t) => t,
                Err(e) => {
                    warn!("cache gc: open_table failed: {}", e);
                    return;
                }
            };

            // Collect expired keys
            let expired: Vec<String> = {
                let mut keys = Vec::new();
                let range = match table.iter() {
                    Ok(i) => i,
                    Err(_) => return,
                };
                for entry in range {
                    if let Ok(entry) = entry {
                        let val = entry.1.value();
                        if val.len() >= 8 {
                            let ts = u64::from_be_bytes(val[..8].try_into().unwrap());
                            if ts < cutoff {
                                keys.push(entry.0.value().to_string());
                            }
                        }
                    }
                }
                keys
            };

            for key in &expired {
                let _: Result<_, _> = table.remove(key.as_str());
            }
        }
        if let Err(e) = write_txn.commit() {
            warn!("cache gc: commit failed: {}", e);
        }
    }
}
