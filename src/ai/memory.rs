//! Per-agent vector memory stored in SQLite.
//!
//! Each (model, dimension) pair gets its own database file under `base_path`,
//! and each agent its own rows. Search is an exact scan that returns the
//! squared Euclidean (L2) distance, so existing anomaly thresholds keep their
//! meaning. Each agent keeps at most `max_rows` rows (the most recent ones),
//! which bounds both the file size and the cost of a scan.
//!
//! One connection per `VectorMemory` is opened on first use, with the schema
//! created once; WAL mode and a busy timeout let several instances share the
//! same file.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Rows kept per agent unless `with_max_rows` says otherwise.
pub const DEFAULT_MAX_ROWS_PER_AGENT: usize = 10_000;

/// Version of the on-disk schema, stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 1;

pub struct VectorMemory {
    base_path: String,
    dim: i32,
    model_id: String,
    max_rows: usize,
    conn: Arc<Mutex<Option<Connection>>>,
}

impl VectorMemory {
    pub fn new(base_path: &str, dim: i32, model_id: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
            dim,
            model_id: model_id.to_string(),
            max_rows: DEFAULT_MAX_ROWS_PER_AGENT,
            conn: Arc::new(Mutex::new(None)),
        }
    }

    /// Keep at most `max_rows` rows per agent (at least 1); older rows are
    /// deleted as new ones are stored.
    pub fn with_max_rows(mut self, max_rows: usize) -> Self {
        self.max_rows = max_rows.max(1);
        self
    }

    fn safe_model(&self) -> String {
        self.model_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }

    /// Logical name of an agent's memory: base path, model, dimension, agent.
    pub fn table_namespace(&self, agent_id: &str) -> String {
        format!(
            "{}/{}_d{}/{}",
            self.base_path,
            self.safe_model(),
            self.dim,
            agent_id
        )
    }

    fn db_path(&self) -> PathBuf {
        Path::new(&self.base_path).join(format!("{}_d{}.sqlite3", self.safe_model(), self.dim))
    }

    /// Opens the database and brings its schema to `SCHEMA_VERSION`.
    fn open(path: &Path) -> Result<Connection> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(anyhow!(
                "{} has schema version {}, this build supports up to {}",
                path.display(),
                version,
                SCHEMA_VERSION
            ));
        }
        if version < SCHEMA_VERSION {
            // Version 0 is a new file or one written before versioning; the
            // table layout is the same, so creating it if missing is enough.
            conn.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE IF NOT EXISTS memory (
                     id INTEGER PRIMARY KEY,
                     agent_id TEXT NOT NULL,
                     text TEXT NOT NULL,
                     vector BLOB NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS memory_agent ON memory(agent_id);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
        Ok(conn)
    }

    /// Runs `f` on this instance's connection, opening it on first use. With
    /// `create` false and no database file yet, returns `Ok(None)` without
    /// creating one.
    fn with_conn<T>(
        slot: &Mutex<Option<Connection>>,
        path: &Path,
        create: bool,
        f: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<Option<T>> {
        let mut guard = slot
            .lock()
            .map_err(|_| anyhow!("vector memory connection lock poisoned"))?;
        if guard.is_none() {
            if !create && !path.exists() {
                return Ok(None);
            }
            *guard = Some(Self::open(path)?);
        }
        let conn = guard.as_ref().expect("connection opened above");
        f(conn).map(Some)
    }

    fn check_vector(&self, vector: &[f32]) -> Result<()> {
        if vector.len() != self.dim as usize {
            return Err(anyhow!(
                "vector has {} dimensions, memory expects {}",
                vector.len(),
                self.dim
            ));
        }
        if !vector.iter().all(|v| v.is_finite()) {
            return Err(anyhow!("vector contains NaN or infinite values"));
        }
        Ok(())
    }

    /// Store a vector embedding for a specific agent, keeping only the agent's
    /// most recent `max_rows` rows.
    pub async fn store(&self, agent_id: &str, text: &str, vector: &[f32]) -> Result<()> {
        self.check_vector(vector)?;
        let path = self.db_path();
        let slot = Arc::clone(&self.conn);
        let max_rows = self.max_rows as i64;
        let agent = agent_id.to_string();
        let text = text.to_string();
        let blob: Vec<u8> = vector.iter().flat_map(|v| v.to_le_bytes()).collect();
        tokio::task::spawn_blocking(move || -> Result<()> {
            Self::with_conn(&slot, &path, true, |conn| {
                conn.execute(
                    "INSERT INTO memory (agent_id, text, vector) VALUES (?1, ?2, ?3)",
                    params![agent, text, blob],
                )?;
                conn.execute(
                    "DELETE FROM memory WHERE agent_id = ?1 AND id <= (
                         SELECT id FROM memory WHERE agent_id = ?1
                         ORDER BY id DESC LIMIT 1 OFFSET ?2
                     )",
                    params![agent, max_rows],
                )?;
                Ok(())
            })?;
            Ok(())
        })
        .await?
    }

    /// Nearest stored texts for an agent, closest first, as (text, squared L2 distance).
    pub async fn search(
        &self,
        agent_id: &str,
        vector: &[f32],
        limit: usize,
    ) -> Result<Vec<(String, f32)>> {
        self.check_vector(vector)?;
        if limit == 0 {
            return Ok(vec![]);
        }
        let path = self.db_path();
        let slot = Arc::clone(&self.conn);
        let agent = agent_id.to_string();
        let query = vector.to_vec();
        tokio::task::spawn_blocking(move || -> Result<Vec<(String, f32)>> {
            let found = Self::with_conn(&slot, &path, false, |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT text, vector FROM memory WHERE agent_id = ?1")?;
                let mut rows = stmt.query(params![agent])?;
                let mut best: Vec<(String, f32)> = Vec::new();
                while let Some(row) = rows.next()? {
                    let blob: Vec<u8> = row.get(1)?;
                    if blob.len() != query.len() * 4 {
                        continue;
                    }
                    let d: f32 = blob
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .zip(&query)
                        .map(|(b, q)| {
                            let v = f32::from_le_bytes(*b);
                            (v - q) * (v - q)
                        })
                        .sum();
                    // Rows written before non-finite input was rejected, or values
                    // that overflow, must not break the ordering of the top-k list.
                    if !d.is_finite() {
                        continue;
                    }
                    if best.len() < limit || d < best[best.len() - 1].1 {
                        let text: String = row.get(0)?;
                        let pos = best.partition_point(|(_, bd)| *bd <= d);
                        best.insert(pos, (text, d));
                        best.truncate(limit);
                    }
                }
                Ok(best)
            })?;
            Ok(found.unwrap_or_default())
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_includes_model_id_and_dim() {
        let a = VectorMemory::new("/tmp/v", 384, "minilm-v2");
        let b = VectorMemory::new("/tmp/v", 768, "minilm-v2");
        let c = VectorMemory::new("/tmp/v", 384, "other-model");
        assert_ne!(a.table_namespace("agent"), b.table_namespace("agent"));
        assert_ne!(a.table_namespace("agent"), c.table_namespace("agent"));
        assert!(a.table_namespace("agent").contains("minilm_v2_d384"));
        assert_ne!(a.db_path(), b.db_path());
        assert_ne!(a.db_path(), c.db_path());
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zn-mem-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[tokio::test]
    async fn search_returns_nearest_first_with_squared_l2() {
        let dir = temp_dir("nearest");
        let m = VectorMemory::new(dir.to_str().unwrap(), 3, "m");
        assert!(m.search("a", &[0.0, 0.0, 0.0], 5).await.unwrap().is_empty());
        assert!(!m.db_path().exists(), "search must not create the file");
        m.store("a", "far", &[3.0, 0.0, 0.0]).await.unwrap();
        m.store("a", "near", &[1.0, 0.0, 0.0]).await.unwrap();
        m.store("a", "mid", &[0.0, 2.0, 0.0]).await.unwrap();
        m.store("b", "other agent", &[0.0, 0.0, 0.0]).await.unwrap();
        let r = m.search("a", &[0.0, 0.0, 0.0], 2).await.unwrap();
        assert_eq!(r, vec![("near".to_string(), 1.0), ("mid".to_string(), 4.0)]);
        let r = m.search("a", &[0.0, 0.0, 0.0], 10).await.unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[2], ("far".to_string(), 9.0));
        assert!(m
            .search("nobody", &[0.0, 0.0, 0.0], 1)
            .await
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wrong_dimension_is_rejected() {
        let dir = temp_dir("dim");
        let m = VectorMemory::new(dir.to_str().unwrap(), 3, "m");
        assert!(m.store("a", "x", &[1.0, 2.0]).await.is_err());
        assert!(m.search("a", &[1.0], 1).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn non_finite_vectors_are_rejected_and_skipped() {
        let dir = temp_dir("finite");
        let m = VectorMemory::new(dir.to_str().unwrap(), 2, "m");
        assert!(m.store("a", "nan", &[f32::NAN, 0.0]).await.is_err());
        assert!(m.store("a", "inf", &[f32::INFINITY, 0.0]).await.is_err());
        assert!(m.search("a", &[0.0, f32::NAN], 1).await.is_err());

        // A row that bypassed validation must not displace valid results.
        m.store("a", "near", &[1.0, 0.0]).await.unwrap();
        let blob: Vec<u8> = [f32::NAN, 0.0f32]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        Connection::open(m.db_path())
            .unwrap()
            .execute(
                "INSERT INTO memory (agent_id, text, vector) VALUES (?1, ?2, ?3)",
                params!["a", "bad", blob],
            )
            .unwrap();
        m.store("a", "far", &[2.0, 0.0]).await.unwrap();
        let r = m.search("a", &[0.0, 0.0], 5).await.unwrap();
        assert_eq!(r, vec![("near".to_string(), 1.0), ("far".to_string(), 4.0)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn each_agent_keeps_only_its_most_recent_rows() {
        let dir = temp_dir("retention");
        let m = VectorMemory::new(dir.to_str().unwrap(), 1, "m").with_max_rows(3);
        for i in 0..6 {
            m.store("a", &format!("a{i}"), &[i as f32]).await.unwrap();
        }
        m.store("b", "b0", &[0.0]).await.unwrap();
        let mut texts: Vec<String> = m
            .search("a", &[0.0], 10)
            .await
            .unwrap()
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        texts.sort();
        assert_eq!(texts, vec!["a3", "a4", "a5"]);
        // Another agent's rows are not affected.
        assert_eq!(m.search("b", &[0.0], 10).await.unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn schema_version_is_recorded_and_newer_files_are_refused() {
        let dir = temp_dir("schema");
        let m = VectorMemory::new(dir.to_str().unwrap(), 1, "m");
        m.store("a", "x", &[1.0]).await.unwrap();
        let raw = Connection::open(m.db_path()).unwrap();
        let v: i64 = raw
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);

        raw.execute_batch("PRAGMA user_version = 99;").unwrap();
        let newer = VectorMemory::new(dir.to_str().unwrap(), 1, "m");
        assert!(newer.store("a", "y", &[1.0]).await.is_err());
        assert!(newer.search("a", &[1.0], 1).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stores_and_searches_share_the_file() {
        let dir = temp_dir("concurrent");
        let base = dir.to_str().unwrap().to_string();
        // Two instances on the same file, as the proxy and the API server use.
        let a = Arc::new(VectorMemory::new(&base, 2, "m"));
        let b = Arc::new(VectorMemory::new(&base, 2, "m"));
        let mut tasks = Vec::new();
        for i in 0..64 {
            let m = if i % 2 == 0 {
                Arc::clone(&a)
            } else {
                Arc::clone(&b)
            };
            tasks.push(tokio::spawn(async move {
                let agent = format!("agent{}", i % 4);
                m.store(&agent, &format!("t{i}"), &[i as f32, 1.0]).await?;
                m.search(&agent, &[0.0, 0.0], 3).await.map(|_| ())
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let mut total = 0;
        for agent in 0..4 {
            total += a
                .search(&format!("agent{agent}"), &[0.0, 0.0], 100)
                .await
                .unwrap()
                .len();
        }
        assert_eq!(total, 64);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
