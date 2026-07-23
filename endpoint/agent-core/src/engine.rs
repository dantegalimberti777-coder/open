//! Motor de detección: orquesta las capas (firmas, heurística, reputación) y
//! produce un veredicto por fichero a través del motor de decisión.
//!
//! Este es el núcleo del enfoque híbrido: cada fichero pasa por un triage
//! barato y solo se aplican capas más costosas cuando hace falta.

use crate::decision::{self, Decision, Signal, Source, Thresholds, Verdict};
use crate::hash::{to_hex, Sha256};
use crate::heuristics;
use crate::reputation::ReputationSource;
use crate::signatures::SignatureDb;
use crate::staticanalysis;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub struct Engine<'a> {
    signatures: &'a SignatureDb,
    reputation: Option<&'a dyn ReputationSource>,
    thresholds: Thresholds,
    max_file_size: u64,
}

#[derive(Debug, Clone)]
pub struct FileVerdict {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub decision: Decision,
    /// Nombre de la amenaza si una firma acertó.
    pub threat_name: Option<String>,
}

impl FileVerdict {
    pub fn verdict(&self) -> Verdict {
        self.decision.verdict
    }
}

impl<'a> Engine<'a> {
    pub fn new(signatures: &'a SignatureDb) -> Self {
        Engine {
            signatures,
            reputation: None,
            thresholds: Thresholds::default(),
            max_file_size: 256 * 1024 * 1024,
        }
    }

    pub fn with_reputation(mut self, rep: &'a dyn ReputationSource) -> Self {
        self.reputation = Some(rep);
        self
    }

    pub fn with_thresholds(mut self, t: Thresholds) -> Self {
        self.thresholds = t;
        self
    }

    pub fn with_max_file_size(mut self, n: u64) -> Self {
        self.max_file_size = n;
        self
    }

    /// Escanea un fichero del disco.
    pub fn scan_path(&self, path: &Path) -> io::Result<FileVerdict> {
        let meta = fs::metadata(path)?;
        let size = meta.len();

        // Ficheros muy grandes: se digieren en streaming (hash) pero no se
        // cargan enteros para heurística de contenido (se muestrea el inicio).
        let (digest, content) = if size > self.max_file_size {
            let digest = hash_file_streaming(path)?;
            let head = read_head(path, 1024 * 1024)?; // primer 1 MB para heurística
            (digest, head)
        } else {
            let data = fs::read(path)?;
            let mut h = Sha256::new();
            h.update(&data);
            (h.finalize(), data)
        };

        Ok(self.evaluate(path.to_path_buf(), size, &digest, &content))
    }

    /// Evalúa contenido ya leído (útil para tests y para el escaneo en memoria).
    pub fn evaluate(
        &self,
        path: PathBuf,
        size: u64,
        digest: &[u8; 32],
        content: &[u8],
    ) -> FileVerdict {
        let sha_hex = to_hex(digest);
        let mut signals: Vec<Signal> = Vec::new();
        let mut threat_name = None;

        // 1) Firmas (veto duro si acierta).
        if let Some(hit) = self.signatures.scan(digest, content) {
            threat_name = Some(hit.name.clone());
            signals.push(Signal::hard(
                Source::Signature,
                format!("firma: {} ({:?})", hit.name, hit.kind),
            ));
        }

        // 2) Heurística estática.
        signals.push(heuristics::analyze(content));

        // 2b) Análisis estático estructural (solo ejecutables PE/ELF/Mach-O).
        // Señal conservadora: únicamente se emite si el binario presenta un
        // riesgo estructural apreciable (empaquetado/ofuscación, RWX, etc.),
        // para no penalizar ejecutables legítimos y evitar falsos positivos.
        if staticanalysis::looks_executable(content) {
            if let Some(report) = staticanalysis::analyze(content) {
                if report.risk > 0.2 {
                    let detail = if report.indicators.is_empty() {
                        "análisis estructural".to_string()
                    } else {
                        report.indicators.join("; ")
                    };
                    signals.push(Signal::new(
                        Source::StaticAnalysis,
                        report.risk,
                        format!("estático: {detail}"),
                    ));
                }
            }
        }

        // 3) Reputación (si hay fuente configurada).
        if let Some(rep) = self.reputation {
            signals.push(rep.signal(&sha_hex));
        }

        let decision = decision::decide(&signals, self.thresholds);

        FileVerdict {
            path,
            sha256: sha_hex,
            size,
            decision,
            threat_name,
        }
    }
}

fn hash_file_streaming(path: &Path) -> io::Result<[u8; 32]> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize())
}

fn read_head(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::LocalReputationCache;

    fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    }

    #[test]
    fn clean_file_is_clean() {
        let db = SignatureDb::new();
        let engine = Engine::new(&db);
        let content = b"just some normal document text";
        let v = engine.evaluate(
            "a.txt".into(),
            content.len() as u64,
            &digest(content),
            content,
        );
        assert_eq!(v.verdict(), Verdict::Clean);
        assert!(v.threat_name.is_none());
    }

    #[test]
    fn signature_hit_is_malicious() {
        let mut db = SignatureDb::new();
        let content = b"known bad bytes";
        db.add_hash(&to_hex(&digest(content)), "Test.Known");
        let engine = Engine::new(&db);
        let v = engine.evaluate(
            "b.bin".into(),
            content.len() as u64,
            &digest(content),
            content,
        );
        assert_eq!(v.verdict(), Verdict::Malicious);
        assert_eq!(v.threat_name.as_deref(), Some("Test.Known"));
    }

    #[test]
    fn bad_reputation_pushes_malicious() {
        let db = SignatureDb::new();
        let content = b"unknown-to-signatures but bad reputation";
        let mut rep = LocalReputationCache::new();
        rep.add_bad(&to_hex(&digest(content)));
        let engine = Engine::new(&db).with_reputation(&rep);
        let v = engine.evaluate(
            "c.bin".into(),
            content.len() as u64,
            &digest(content),
            content,
        );
        assert!(matches!(
            v.verdict(),
            Verdict::Malicious | Verdict::Suspicious
        ));
    }
}
