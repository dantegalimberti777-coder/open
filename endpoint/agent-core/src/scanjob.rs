//! Trabajo de escaneo con progreso en tiempo real.
//!
//! Recolecta la lista de ficheros a analizar (zonas/procesos según el modo),
//! y luego los escanea uno a uno actualizando un `Progress` compartido para que
//! la interfaz muestre una barra de avance con porcentaje.

use crate::decision::Verdict;
use crate::engine::Engine;
use crate::quarantine::Quarantine;
use crate::sysscan::{self, ScanMode};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Máximo de ficheros a recolectar (cota de memoria para escaneos profundos).
const MAX_FILES: usize = 1_000_000;

/// Ficheros por encima de este tamaño se omiten (como en los AV comerciales):
/// leerlos enteros sería lento y rara vez aportan detección estática. Evita que
/// el escaneo se atasque en ficheros enormes (imágenes de disco, VMs, etc.).
const MAX_SCAN_BYTES: u64 = 128 * 1024 * 1024; // 128 MB

#[derive(Clone)]
pub struct HitInfo {
    pub path: String,
    pub verdict: String,
    pub score: f64,
    pub threat: String,
    pub quarantined: bool,
    pub reasons: Vec<String>,
}

pub struct Progress {
    pub mode: String,
    pub total: usize,
    pub done: usize,
    pub current: String,
    pub finished: bool,
    pub started_at: u64,
    pub scanned: usize,
    pub skipped: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub hits: Vec<HitInfo>,
    pub error: Option<String>,
}

impl Progress {
    pub fn new(mode: ScanMode) -> Self {
        Progress {
            mode: mode.label().to_string(),
            total: 0,
            done: 0,
            current: "Preparando…".to_string(),
            finished: false,
            started_at: now(),
            scanned: 0,
            skipped: 0,
            malicious: 0,
            suspicious: 0,
            hits: Vec::new(),
            error: None,
        }
    }

    pub fn percent(&self) -> u32 {
        if self.finished {
            return 100;
        }
        if self.total == 0 {
            return 0;
        }
        ((self.done as f64 / self.total as f64) * 100.0).min(99.0) as u32
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Recolecta los ficheros a escanear.
///
/// - Si `custom` es `Some`, escanea solo esa ruta (fichero o carpeta), sin
///   procesos (escaneo dirigido por el usuario).
/// - Si es `None`, usa las zonas del `mode` + los ejecutables de los procesos
///   en ejecución (escaneo de la CPU).
pub fn collect(mode: ScanMode, custom: Option<PathBuf>) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();

    let roots: Vec<PathBuf> = if let Some(c) = custom {
        if c.is_file() {
            return vec![c];
        }
        vec![c]
    } else {
        // Procesos en ejecución (escaneo de la CPU), en ambos modos.
        for p in sysscan::process_executables() {
            files.push(p);
            if files.len() >= MAX_FILES {
                return files;
            }
        }
        sysscan::scan_roots(mode)
    };

    let mut stack: Vec<PathBuf> = roots;
    while let Some(dir) = stack.pop() {
        if sysscan::is_excluded(&dir) {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if !sysscan::is_excluded(&path) {
                    stack.push(path);
                }
            } else if meta.is_file() {
                files.push(path);
                if files.len() >= MAX_FILES {
                    return files;
                }
            }
        }
    }

    // Dedupe (un proceso puede estar también en una zona).
    files.sort();
    files.dedup();
    files
}

/// Ejecuta el escaneo completo, actualizando `progress`.
pub fn run(
    engine: &Engine,
    quarantine: &Quarantine,
    do_quarantine: bool,
    mode: ScanMode,
    custom: Option<PathBuf>,
    progress: &Arc<Mutex<Progress>>,
) {
    // Fase 1: recolección (contar para el %).
    {
        let mut p = progress.lock().unwrap();
        p.current = "Enumerando ficheros y procesos…".to_string();
    }
    let files = collect(mode, custom);
    {
        let mut p = progress.lock().unwrap();
        p.total = files.len();
    }

    // Fase 2: escaneo con progreso.
    for (i, path) in files.iter().enumerate() {
        {
            let mut p = progress.lock().unwrap();
            p.done = i;
            p.current = path.display().to_string();
        }

        // Omitir ficheros demasiado grandes (evita bloqueos y lecturas lentas).
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_SCAN_BYTES {
                let mut p = progress.lock().unwrap();
                p.skipped += 1;
                continue;
            }
        }

        match engine.scan_path(path) {
            Ok(v) => {
                let mut p = progress.lock().unwrap();
                p.scanned += 1;
                let is_hit = v.verdict() != Verdict::Clean;
                if v.verdict() == Verdict::Malicious {
                    p.malicious += 1;
                } else if v.verdict() == Verdict::Suspicious {
                    p.suspicious += 1;
                }
                drop(p);

                if is_hit {
                    let mut quarantined = false;
                    if do_quarantine && v.verdict() == Verdict::Malicious {
                        quarantined = quarantine
                            .quarantine_file(&v.path, v.threat_name.as_deref().unwrap_or("Malware"))
                            .is_ok();
                    }
                    let mut p = progress.lock().unwrap();
                    p.hits.push(HitInfo {
                        path: v.path.display().to_string(),
                        verdict: format!("{}", v.verdict()),
                        score: v.decision.score,
                        threat: v.threat_name.clone().unwrap_or_default(),
                        quarantined,
                        reasons: v.decision.reasons.clone(),
                    });
                }
            }
            Err(_) => {
                let mut p = progress.lock().unwrap();
                p.skipped += 1;
            }
        }
    }

    let mut p = progress.lock().unwrap();
    p.done = p.total;
    p.finished = true;
    p.current = "Completado".to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_math() {
        let mut p = Progress::new(ScanMode::Quick);
        assert_eq!(p.percent(), 0);
        p.total = 200;
        p.done = 100;
        assert_eq!(p.percent(), 50);
        p.finished = true;
        assert_eq!(p.percent(), 100);
    }

    #[test]
    fn percent_caps_below_100_until_finished() {
        let mut p = Progress::new(ScanMode::Deep);
        p.total = 10;
        p.done = 10;
        // Sin finished, no debe llegar a 100 (evita "100% pero sigue").
        assert_eq!(p.percent(), 99);
    }
}
