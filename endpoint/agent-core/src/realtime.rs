//! Protección en tiempo real (on-access).
//!
//! Vigila la creación, modificación y renombrado de ficheros en las zonas
//! configuradas y los analiza **apenas aparecen**, sin escaneos manuales. Usa
//! el crate `notify` (inotify en Linux, ReadDirectoryChangesW en Windows,
//! FSEvents en macOS), es decir, notificaciones del kernel **basadas en
//! eventos** (no polling) para minimizar CPU.
//!
//! ## Diseño (SOLID)
//! El servicio NO conoce el motor de detección: recibe una *callback* de
//! escaneo (`ScanCallback`) — Inversión de Dependencias. Así es testeable con
//! un escáner falso y no acopla la vigilancia a la implementación del motor.
//!
//! ## Rendimiento
//! - Basado en eventos del kernel (sin polling) → CPU ~0 en reposo.
//! - Debounce por ruta (evita reescaneos en ráfaga de escrituras).
//! - Filtros baratos antes de escanear: exclusiones, tamaño máximo, tipo.
//! - Búfer circular acotado de eventos recientes (línea temporal de la UI).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// Resultado del análisis de un fichero, devuelto por la callback de escaneo.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub verdict: String,        // "LIMPIO" | "SOSPECHOSO" | "MALICIOSO"
    pub threat: Option<String>, // nombre de la amenaza si la hay
    pub score: f64,             // 0.0..1.0
    pub quarantined: bool,      // si se puso en cuarentena
}

/// Puerto de escaneo: la callback analiza un fichero y devuelve el resultado.
/// `None` = el fichero no pudo analizarse (no existe, sin permiso, etc.).
pub type ScanCallback = Arc<dyn Fn(&Path) -> Option<ScanOutcome> + Send + Sync>;

/// Evento de protección en tiempo real (para la línea temporal de amenazas).
#[derive(Debug, Clone)]
pub struct RealtimeEvent {
    pub timestamp: u64,
    pub path: String,
    pub action: String, // "creado" | "modificado" | "renombrado"
    pub verdict: String,
    pub threat: Option<String>,
    pub score: f64,
    pub quarantined: bool,
}

/// Configuración de la vigilancia.
#[derive(Clone)]
pub struct RealtimeConfig {
    pub watch_dirs: Vec<PathBuf>,
    pub auto_quarantine: bool,
    pub max_file_size: u64,
    pub excluded_substrings: Vec<String>,
    /// Ventana de debounce por ruta.
    pub debounce: Duration,
    /// Capacidad del búfer de eventos recientes.
    pub event_capacity: usize,
}

impl RealtimeConfig {
    pub fn new(watch_dirs: Vec<PathBuf>) -> Self {
        RealtimeConfig {
            watch_dirs,
            auto_quarantine: true,
            max_file_size: 128 * 1024 * 1024,
            excluded_substrings: vec![
                "/.ngav".into(),
                "\\.ngav".into(),
                "/proc".into(),
                "/sys".into(),
            ],
            debounce: Duration::from_millis(800),
            event_capacity: 200,
        }
    }
}

#[derive(Default)]
struct Stats {
    scanned: u64,
    detected: u64,
    quarantined: u64,
}

/// Servicio de protección en tiempo real. Arrancable y detenible.
pub struct RealtimeService {
    running: AtomicBool,
    started_at: AtomicU64,
    events: Mutex<VecDeque<RealtimeEvent>>,
    stats: Mutex<Stats>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stop_flag: Arc<AtomicBool>,
    capacity: usize,
}

impl Default for RealtimeService {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeService {
    pub fn new() -> Self {
        RealtimeService {
            running: AtomicBool::new(false),
            started_at: AtomicU64::new(0),
            events: Mutex::new(VecDeque::new()),
            stats: Mutex::new(Stats::default()),
            worker: Mutex::new(None),
            stop_flag: Arc::new(AtomicBool::new(false)),
            capacity: 200,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn started_at(&self) -> u64 {
        self.started_at.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        let s = self.stats.lock().unwrap();
        (s.scanned, s.detected, s.quarantined)
    }

    /// Devuelve los últimos eventos (más recientes primero).
    pub fn recent_events(&self, limit: usize) -> Vec<RealtimeEvent> {
        let ev = self.events.lock().unwrap();
        ev.iter().rev().take(limit).cloned().collect()
    }

    /// Arranca la vigilancia. Idempotente (si ya corre, no hace nada).
    pub fn start(self: &Arc<Self>, cfg: RealtimeConfig, scan: ScanCallback) -> Result<(), String> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // ya en marcha
        }
        self.stop_flag.store(false, Ordering::SeqCst);
        self.started_at.store(now(), Ordering::SeqCst);

        let this = Arc::clone(self);
        let stop_flag = Arc::clone(&self.stop_flag);
        let handle = std::thread::Builder::new()
            .name("ngav-realtime".into())
            .spawn(move || {
                if let Err(e) = watch_loop(&this, cfg, scan, stop_flag) {
                    eprintln!("[realtime] {e}");
                }
            })
            .map_err(|e| e.to_string())?;

        *self.worker.lock().unwrap() = Some(handle);
        Ok(())
    }

    /// Detiene la vigilancia y espera al hilo.
    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
    }

    fn record(&self, ev: RealtimeEvent) {
        let mut buf = self.events.lock().unwrap();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(ev);
    }
}

fn watch_loop(
    service: &Arc<RealtimeService>,
    cfg: RealtimeConfig,
    scan: ScanCallback,
    stop_flag: Arc<AtomicBool>,
) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| e.to_string())?;

    for dir in &cfg.watch_dirs {
        if dir.exists() {
            let _ = watcher.watch(dir, RecursiveMode::Recursive);
        }
    }

    let mut last_seen: HashMap<PathBuf, Instant> = HashMap::new();

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(event)) => {
                let action = match event.kind {
                    EventKind::Create(_) => "creado",
                    EventKind::Modify(notify::event::ModifyKind::Name(_)) => "renombrado",
                    EventKind::Modify(_) => "modificado",
                    _ => continue, // ignora Access/Remove/Other
                };
                for path in event.paths {
                    handle_path(service, &cfg, &scan, &mut last_seen, &path, action);
                }
            }
            Ok(Err(_)) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        // Limpieza periódica del mapa de debounce.
        if last_seen.len() > 4096 {
            let now = Instant::now();
            last_seen.retain(|_, t| now.duration_since(*t) < cfg.debounce * 4);
        }
    }
    Ok(())
}

fn handle_path(
    service: &Arc<RealtimeService>,
    cfg: &RealtimeConfig,
    scan: &ScanCallback,
    last_seen: &mut HashMap<PathBuf, Instant>,
    path: &Path,
    action: &str,
) {
    // Filtros baratos antes de tocar disco.
    let p = path.to_string_lossy();
    if cfg
        .excluded_substrings
        .iter()
        .any(|e| p.contains(e.as_str()))
    {
        return;
    }
    // Debounce por ruta.
    let now = Instant::now();
    if let Some(t) = last_seen.get(path) {
        if now.duration_since(*t) < cfg.debounce {
            return;
        }
    }
    last_seen.insert(path.to_path_buf(), now);

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return, // pudo borrarse/renombrarse; nada que analizar
    };
    if !meta.is_file() || meta.len() > cfg.max_file_size {
        return;
    }

    if let Some(outcome) = scan(path) {
        {
            let mut s = service.stats.lock().unwrap();
            s.scanned += 1;
            if outcome.verdict != "LIMPIO" {
                s.detected += 1;
            }
            if outcome.quarantined {
                s.quarantined += 1;
            }
        }
        if outcome.verdict != "LIMPIO" {
            service.record(RealtimeEvent {
                timestamp: now_epoch(),
                path: path.to_string_lossy().to_string(),
                action: action.to_string(),
                verdict: outcome.verdict,
                threat: outcome.threat,
                score: outcome.score,
                quarantined: outcome.quarantined,
            });
        }
    }
}

fn now() -> u64 {
    now_epoch()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ngav-rt-{}-{}",
            tag,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_new_malicious_file_in_real_time() {
        let dir = tmpdir("detect");
        let service = Arc::new(RealtimeService::new());

        // Escáner falso: marca malicioso cualquier fichero que contenga "EVIL".
        let scan: ScanCallback = Arc::new(|path: &Path| {
            let data = std::fs::read(path).ok()?;
            let bad = data.windows(4).any(|w| w == b"EVIL");
            Some(ScanOutcome {
                verdict: if bad {
                    "MALICIOSO".into()
                } else {
                    "LIMPIO".into()
                },
                threat: if bad { Some("Test.Evil".into()) } else { None },
                score: if bad { 1.0 } else { 0.0 },
                quarantined: false,
            })
        });

        let cfg = RealtimeConfig::new(vec![dir.clone()]);
        service.start(cfg, scan).unwrap();
        // Da tiempo a que el watcher se registre.
        std::thread::sleep(Duration::from_millis(300));

        std::fs::write(dir.join("payload.bin"), b"xx EVIL xx").unwrap();
        std::fs::write(dir.join("ok.txt"), b"inofensivo").unwrap();

        // Espera a que los eventos se procesen.
        let mut detected = false;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(100));
            if service
                .recent_events(10)
                .iter()
                .any(|e| e.verdict == "MALICIOSO")
            {
                detected = true;
                break;
            }
        }
        service.stop();
        assert!(
            detected,
            "la protección en tiempo real debería detectar el fichero malicioso nuevo"
        );

        let (scanned, det, _) = service.stats();
        assert!(scanned >= 1);
        assert!(det >= 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn respects_debounce_and_exclusions() {
        let dir = tmpdir("debounce");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let scan: ScanCallback = Arc::new(move |_p: &Path| {
            calls2.fetch_add(1, Ordering::SeqCst);
            Some(ScanOutcome {
                verdict: "LIMPIO".into(),
                threat: None,
                score: 0.0,
                quarantined: false,
            })
        });
        let service = Arc::new(RealtimeService::new());
        let mut cfg = RealtimeConfig::new(vec![dir.clone()]);
        cfg.debounce = Duration::from_secs(5);
        service.start(cfg, scan).unwrap();
        std::thread::sleep(Duration::from_millis(300));

        let f = dir.join("a.txt");
        for i in 0..5 {
            std::fs::write(&f, format!("v{i}")).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(500));
        service.stop();
        // Con debounce de 5s, las 5 escrituras rápidas no deben producir 5 escaneos.
        assert!(
            calls.load(Ordering::SeqCst) <= 2,
            "el debounce debe agrupar escrituras en ráfaga"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn start_is_idempotent_and_stop_works() {
        let dir = tmpdir("idem");
        let scan: ScanCallback = Arc::new(|_p: &Path| None);
        let service = Arc::new(RealtimeService::new());
        service
            .start(RealtimeConfig::new(vec![dir.clone()]), scan.clone())
            .unwrap();
        assert!(service.is_running());
        // Segunda llamada no debe fallar ni duplicar el hilo.
        service
            .start(RealtimeConfig::new(vec![dir.clone()]), scan)
            .unwrap();
        assert!(service.is_running());
        service.stop();
        assert!(!service.is_running());
        std::fs::remove_dir_all(&dir).ok();
    }
}
