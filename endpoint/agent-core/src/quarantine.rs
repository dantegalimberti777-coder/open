//! Cuarentena: aísla ficheros maliciosos para que no puedan ejecutarse.
//!
//! El fichero se ofusca (XOR con clave por-elemento) al moverlo a cuarentena,
//! de modo que no pueda ejecutarse ni leerse trivialmente por otro proceso, y
//! se registra en un journal para poder restaurarlo o eliminarlo.
//!
//! NOTA MVP: el XOR es *ofuscación*, no cifrado fuerte. En producción se usaría
//! cifrado autenticado (AES-GCM/ChaCha20-Poly1305) con clave protegida por el
//! módulo de self-defense/KMS local. Se documenta explícitamente para no dar
//! una falsa sensación de confidencialidad.

use crate::hash::sha256_hex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const XOR_KEY: &[u8] = b"NGAV-quarantine-obfuscation-key-v1";

pub struct Quarantine {
    dir: PathBuf,
    journal: PathBuf,
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub threat: String,
    pub timestamp: u64,
}

impl Quarantine {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let journal = dir.join("journal.tsv");
        Quarantine { dir, journal }
    }

    /// Mueve un fichero a cuarentena. Devuelve el id del elemento.
    pub fn quarantine_file(&self, path: &Path, threat: &str) -> io::Result<String> {
        fs::create_dir_all(&self.dir)?;
        let data = fs::read(path)?;
        let id = sha256_hex(path.to_string_lossy().as_bytes())[..16].to_string();
        let dest = self.dir.join(format!("{id}.qbin"));

        let obfuscated = xor(&data);
        fs::write(&dest, &obfuscated)?;
        // Solo tras copiar con éxito, eliminamos el original.
        fs::remove_file(path)?;

        let ts = now();
        let line = format!(
            "{id}\t{}\t{}\t{ts}\n",
            escape(&path.to_string_lossy()),
            escape(threat)
        );
        append(&self.journal, &line)?;
        Ok(id)
    }

    /// Restaura un elemento a su ruta original.
    pub fn restore(&self, id: &str) -> io::Result<PathBuf> {
        let entry = self
            .list()?
            .into_iter()
            .find(|e| e.id == id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "id no encontrado"))?;
        let src = self.dir.join(format!("{id}.qbin"));
        let data = xor(&fs::read(&src)?); // XOR es su propia inversa
        let dest = PathBuf::from(&entry.original_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &data)?;
        fs::remove_file(&src)?;
        self.remove_from_journal(id)?;
        Ok(dest)
    }

    /// Elimina definitivamente un elemento en cuarentena.
    pub fn delete(&self, id: &str) -> io::Result<()> {
        let src = self.dir.join(format!("{id}.qbin"));
        if src.exists() {
            fs::remove_file(&src)?;
        }
        self.remove_from_journal(id)
    }

    /// Lista los elementos en cuarentena.
    pub fn list(&self) -> io::Result<Vec<QuarantineEntry>> {
        if !self.journal.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&self.journal)?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, '\t').collect();
            if parts.len() == 4 {
                out.push(QuarantineEntry {
                    id: parts[0].to_string(),
                    original_path: unescape(parts[1]),
                    threat: unescape(parts[2]),
                    timestamp: parts[3].trim().parse().unwrap_or(0),
                });
            }
        }
        Ok(out)
    }

    fn remove_from_journal(&self, id: &str) -> io::Result<()> {
        let entries = self.list()?;
        let mut text = String::new();
        for e in entries.into_iter().filter(|e| e.id != id) {
            text.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                e.id,
                escape(&e.original_path),
                escape(&e.threat),
                e.timestamp
            ));
        }
        fs::write(&self.journal, text)
    }
}

fn xor(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn append(path: &Path, line: &str) -> io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn unescape(s: &str) -> String {
    s.replace("\\t", "\t")
        .replace("\\n", "\n")
        .replace("\\\\", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ngav-qtest-{}-{}", tag, now()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn quarantine_restore_roundtrip() {
        let base = temp_dir("roundtrip");
        let qdir = base.join("q");
        let q = Quarantine::new(&qdir);

        let sample = base.join("sample.bin");
        fs::write(&sample, b"EVIL-PAYLOAD-CONTENT").unwrap();

        let id = q.quarantine_file(&sample, "Test.Threat").unwrap();
        assert!(!sample.exists(), "original debe eliminarse");
        let listed = q.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].threat, "Test.Threat");

        let restored = q.restore(&id).unwrap();
        assert_eq!(fs::read(&restored).unwrap(), b"EVIL-PAYLOAD-CONTENT");
        assert_eq!(q.list().unwrap().len(), 0);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn delete_removes_entry() {
        let base = temp_dir("delete");
        let q = Quarantine::new(base.join("q"));
        let sample = base.join("s.bin");
        fs::write(&sample, b"data").unwrap();
        let id = q.quarantine_file(&sample, "T").unwrap();
        q.delete(&id).unwrap();
        assert_eq!(q.list().unwrap().len(), 0);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn xor_is_reversible() {
        let data = b"arbitrary bytes \x00\xff\x10";
        assert_eq!(xor(&xor(data)), data);
    }
}
