use std::sync::Arc;
use tokio::sync::Mutex;
use turso::{Builder, Connection, Database};

/// Wrapper holding the Turso database + a write mutex to serialize writes (like Go's dbWriteMu).
pub struct Db {
    pub db: Database,
    pub write_mu: Mutex<()>,
}

impl Db {
    pub async fn open(path: &str) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let db = Builder::new_local(path).build().await?;

        // Use a temporary connection for schema init
        let conn = db.connect()?;
        let _ = conn.query("PRAGMA journal_mode=WAL", ()).await?;
        conn.execute("PRAGMA foreign_keys=ON", ()).await?;
        conn.execute("PRAGMA busy_timeout=5000", ()).await?;
        conn.execute("PRAGMA synchronous=NORMAL", ()).await?;
        conn.execute("PRAGMA cache_size=-262144", ()).await?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS nonces(
                pubkey BLOB(32) PRIMARY KEY,
                nonce  BLOB(32) NOT NULL,
                ts     INTEGER NOT NULL
            )",
            (),
        ).await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS chats(
                id           INTEGER PRIMARY KEY,
                owner_pubkey BLOB(32) NOT NULL,
                created_at   INTEGER NOT NULL
            )",
            (),
        ).await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS invites(
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      INTEGER NOT NULL,
                from_pubkey    BLOB(32) NOT NULL,
                to_pubkey      BLOB(32) NOT NULL,
                chat_id        INTEGER NOT NULL,
                encrypted_data BLOB NOT NULL,
                sent           INTEGER NOT NULL DEFAULT 0,
                UNIQUE(to_pubkey, chat_id)
            )",
            (),
        ).await?;

        // Migration: rename hyphenated table names to underscored
        {
            let mut rows = conn.query("SELECT id FROM chats", ()).await?;
            let mut chat_ids = Vec::new();
            while let Ok(Some(row)) = rows.next().await {
                let id: i64 = row.get(0).unwrap_or(0);
                chat_ids.push(id);
            }
            for id in &chat_ids {
                for prefix in &["settings", "users", "messages"] {
                    let old_name = format!("{}-{}", prefix, id);
                    let new_name = format!("{}_{}", prefix, id);
                    let rename = format!("ALTER TABLE \"{}\" RENAME TO \"{}\"", old_name, new_name);
                    let _ = conn.execute(&rename, ()).await; // ignore if already renamed
                }
            }
            // Migration: add blob column to existing message tables
            for id in &chat_ids {
                let alter = format!("ALTER TABLE \"messages_{}\" ADD COLUMN blob BLOB NOT NULL DEFAULT X''", id);
                let _ = conn.execute(&alter, ()).await; // ignore "duplicate column" errors
            }
        }

        Ok(Arc::new(Self {
            db,
            write_mu: Mutex::new(()),
        }))
    }

    /// Create a new connection to the database.
    pub fn connect(&self) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.db.connect()?)
    }

    /// Create the three per-chat tables. Must be called with write_mu held.
    pub async fn create_chat_tables(&self, conn: &Connection, id: i64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let settings = format!("settings_{}", id);
        let users = format!("users_{}", id);
        let messages = format!("messages_{}", id);

        conn.execute(
            &format!(
                "CREATE TABLE \"{}\"(
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    avatar BLOB,
                    perms_flags INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    extra TEXT
                )",
                settings
            ),
            (),
        )
        .await?;

        conn.execute(
            &format!(
                "CREATE TABLE \"{}\"(
                    pubkey BLOB(32) PRIMARY KEY,
                    text_rank TEXT,
                    perms_flags INTEGER NOT NULL,
                    accepted_at INTEGER NOT NULL,
                    changed_at INTEGER NOT NULL,
                    banned INTEGER NOT NULL DEFAULT 0,
                    info BLOB,
                    last_seen INTEGER NOT NULL DEFAULT 0
                )",
                users
            ),
            (),
        )
        .await?;

        conn.execute(&format!("CREATE TABLE \"{}\"(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,\
            guid INTEGER NOT NULL UNIQUE, author BLOB(32) NOT NULL, blob BLOB NOT NULL DEFAULT X'')", messages),())
        .await?;

        Ok(())
    }
}

/// Helper to get table names for a chat.
pub fn chat_table_names(id: i64) -> (String, String, String) {
    (format!("settings_{}", id), format!("users_{}", id), format!("messages_{}", id))
}

/// Generate a message GUID matching the Kotlin contentHashCode algorithm.
pub fn generate_message_guid(ts: i64, data: &[u8]) -> i64 {
    let mut hash: i32 = 1;
    for &b in data {
        hash = hash.wrapping_mul(31).wrapping_add(b as i8 as i32);
    }
    ((hash as i64) << 32) ^ ts
}

/// Generate 32 random bytes.
pub fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Constant-time byte comparison.
pub fn equal_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut ok: u8 = 0;
    for i in 0..a.len() {
        ok |= a[i] ^ b[i];
    }
    ok == 0
}
