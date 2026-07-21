//! Escáner de sistema de ficheros con índice incremental.
//!
//! El índice guarda, por ruta: `(mtime, size, hash, verdict)`. Un fichero solo
//! se vuelve a escanear si cambió su mtime/tamaño (barato de comprobar sin leer
//! el contenido). Esto reduce drásticamente el coste de escaneos completos
//! repetidos — clave para el bajo impacto en rendimiento.

use crate::decision::Verdict;
use crate::engine::{Engine, FileVerdict};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

#[derive(Clone)]
struct IndexEntry {
    mtime: u64,
    size: u64,
    verdict: String,
    threat: String,
}

#[derive(Default)]
pub struct ScanIndex {
    map: HashMap<String, IndexEntry>,
}

impl ScanIndex {
    pub fn load(path: &Path) -> Self {
        let mut idx = ScanIndex::default();
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let parts: Vec<&str> = line.splitn(5, '\t').collect();
                if parts.len() == 5 {
                    idx.map.insert(
                        parts[0].to_string(),
                        IndexEntry {
                            mtime: parts[1].parse().unwrap_or(0),
                            size: parts[2].parse().unwrap_or(0),
                            verdict: parts[3].to_string(),
                            threat: parts[4].to_string(),
                        },
                    );
                }
            }
        }
        idx
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut text = String::new();
        for (p, e) in &self.map {
            text.push_str(&format!(
                "{p}\t{}\t{}\t{}\t{}\n",
                e.mtime, e.size, e.verdict, e.threat
            ));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)
    }

    fn unchanged(&self, path: &str, mtime: u64, size: u64) -> Option<&IndexEntry> {
        self.map
            .get(path)
            .filter(|e| e.mtime == mtime && e.size == size)
    }

    fn update(&mut self, path: String, mtime: u64, size: u64, v: &FileVerdict) {
        self.map.insert(
            path,
            IndexEntry {
                mtime,
                size,
                verdict: format!("{}", v.verdict()),
                threat: v.threat_name.clone().unwrap_or_default(),
            },
        );
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub files_seen: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub errors: usize,
}

/// Escanea un árbol de directorios de forma incremental, invocando `on_hit`
/// para cada fichero sospechoso/malicioso encontrado.
pub fn scan_tree<F>(
    engine: &Engine,
    root: &Path,
    index: &mut ScanIndex,
    mut on_hit: F,
) -> io::Result<ScanStats>
where
    F: FnMut(&FileVerdict),
{
    let mut stats = ScanStats::default();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    stats.errors += 1;
                    continue;
                }
            };
            // No seguir symlinks para evitar bucles y escapes fuera del árbol.
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }

            stats.files_seen += 1;
            let key = path.to_string_lossy().to_string();
            let mtime = mtime_of(&meta);
            let size = meta.len();

            // Escaneo incremental: saltar si no cambió.
            if let Some(prev) = index.unchanged(&key, mtime, size) {
                stats.files_skipped += 1;
                if prev.verdict == "MALICIOSO" {
                    stats.malicious += 1;
                } else if prev.verdict == "SOSPECHOSO" {
                    stats.suspicious += 1;
                }
                continue;
            }

            match engine.scan_path(&path) {
                Ok(v) => {
                    stats.files_scanned += 1;
                    match v.verdict() {
                        Verdict::Malicious => {
                            stats.malicious += 1;
                            on_hit(&v);
                        }
                        Verdict::Suspicious => {
                            stats.suspicious += 1;
                            on_hit(&v);
                        }
                        Verdict::Clean => {}
                    }
                    index.update(key, mtime, size, &v);
                }
                Err(_) => stats.errors += 1,
            }
        }
    }

    Ok(stats)
}

fn mtime_of(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{to_hex, Sha256};
    use crate::signatures::SignatureDb;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ngav-scan-{}-{}",
            tag,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_and_skips_on_rescan() {
        let root = tmp("tree");
        fs::write(root.join("clean.txt"), b"harmless").unwrap();
        let bad = b"this is bad content";
        fs::write(root.join("bad.bin"), bad).unwrap();

        let mut db = SignatureDb::new();
        let mut h = Sha256::new();
        h.update(bad);
        db.add_hash(&to_hex(&h.finalize()), "Test.Bad");
        let engine = Engine::new(&db);

        let mut index = ScanIndex::default();
        let mut hits = 0;
        let stats = scan_tree(&engine, &root, &mut index, |_| hits += 1).unwrap();
        assert_eq!(stats.files_seen, 2);
        assert_eq!(stats.files_scanned, 2);
        assert_eq!(stats.malicious, 1);
        assert_eq!(hits, 1);

        // Segundo escaneo: todo debe saltarse (incremental).
        let stats2 = scan_tree(&engine, &root, &mut index, |_| {}).unwrap();
        assert_eq!(stats2.files_skipped, 2);
        assert_eq!(stats2.files_scanned, 0);
        assert_eq!(stats2.malicious, 1); // recordado del índice

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn index_persistence_roundtrip() {
        let root = tmp("persist");
        let idx_path = root.join("index.tsv");
        let mut idx = ScanIndex::default();
        idx.map.insert(
            "/x/y".to_string(),
            IndexEntry {
                mtime: 100,
                size: 200,
                verdict: "LIMPIO".to_string(),
                threat: String::new(),
            },
        );
        idx.save(&idx_path).unwrap();
        let loaded = ScanIndex::load(&idx_path);
        assert!(loaded.unchanged("/x/y", 100, 200).is_some());
        fs::remove_dir_all(&root).ok();
    }
}
