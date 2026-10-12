//! Per-agent vector memory stored in SQLite.
//!
//! Each (model, dimension) pair gets its own database file under `base_path`,
//! and each agent its own rows. Search is an exact scan that returns the
//! squared Euclidean (L2) distance, so existing anomaly thresholds keep their
//! meaning. Agent memories are small (one row per checked input), so an exact
//! scan is fast enough and needs no index.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

pub struct VectorMemory {
    base_path: String,
    dim: i32,
    model_id: String,
}

impl VectorMemory {
    pub fn new(base_path: &str, dim: i32, model_id: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
            dim,
            model_id: model_id.to_string(),
        }
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

    fn open(path: &Path) -> Result<Connection> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS memory (
                 id INTEGER PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 text TEXT NOT NULL,
                 vector BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS memory_agent ON memory(agent_id);",
        )?;
        Ok(conn)
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

    /// Store a vector embedding for a specific agent.
    pub async fn store(&self, agent_id: &str, text: &str, vector: &[f32]) -> Result<()> {
        self.check_vector(vector)?;
        let path = self.db_path();
        let agent = agent_id.to_string();
        let text = text.to_string();
        let blob: Vec<u8> = vector.iter().flat_map(|v| v.to_le_bytes()).collect();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = Self::open(&path)?;
            conn.execute(
                "INSERT INTO memory (agent_id, text, vector) VALUES (?1, ?2, ?3)",
                params![agent, text, blob],
            )?;
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
        let path = self.db_path();
        if limit == 0 || !path.exists() {
            return Ok(vec![]);
        }
        let agent = agent_id.to_string();
        let query = vector.to_vec();
        tokio::task::spawn_blocking(move || -> Result<Vec<(String, f32)>> {
            let conn = Self::open(&path)?;
            let mut stmt = conn.prepare("SELECT text, vector FROM memory WHERE agent_id = ?1")?;
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
        VectorMemory::open(&m.db_path())
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
}
