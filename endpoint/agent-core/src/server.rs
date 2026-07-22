//! Servidor HTTP embebido que sirve la interfaz de escritorio (SPA) y expone
//! el motor de detección por una API JSON local.
//!
//! Solo escucha en localhost (127.0.0.1) — la UI es un cliente local del
//! servicio, igual que en el diseño (la UI nunca tiene privilegios y habla con
//! el servicio por un canal local). Implementado sobre `std::net` (sin
//! dependencias externas): HTTP/1.1 mínimo, un hilo por conexión.
//!
//! Escaneos: se lanzan en segundo plano (`/api/scan/start`) y la UI consulta el
//! progreso con porcentaje (`/api/scan/progress?id=`).

use crate::config::Config;
use crate::engine::Engine;
use crate::licensing::{self, License};
use crate::quarantine::Quarantine;
use crate::realtime::{RealtimeConfig, RealtimeService, ScanCallback, ScanOutcome};
use crate::reputation::{CloudReputationClient, LocalReputationCache, ReputationSource};
use crate::scanjob::{self, Progress};
use crate::signatures::SignatureDb;
use crate::sysscan::ScanMode;
use crate::{eicar_test_bytes, updater, VERSION};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// Recursos estáticos de la UI (empaquetados en el binario).
const INDEX_HTML: &str = include_str!("../ui/index.html");
const STYLES_CSS: &str = include_str!("../ui/styles.css");
const APP_JS: &str = include_str!("../ui/app.js");

struct AppState {
    cfg: Config,
    signatures: Arc<RwLock<SignatureDb>>,
    local_rep: Arc<LocalReputationCache>,
    jobs: Mutex<HashMap<String, Arc<Mutex<Progress>>>>,
    last_update: Mutex<Option<u64>>,
    license: Mutex<License>,
    realtime: Arc<RealtimeService>,
}

struct Request {
    method: String,
    path: String,
    query: String,
    body: String,
    host: String,
    origin: String,
}

/// Tope de tamaño del cuerpo de una petición (anti-DoS de memoria).
const MAX_BODY: usize = 1024 * 1024; // 1 MiB

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Arranca el servidor de la UI. Bloquea aceptando conexiones.
pub fn serve(cfg: Config, addr: &str) -> std::io::Result<()> {
    cfg.ensure_dirs()?;

    // Palabras clave heurísticas opcionales (fichero externo; no se envía por
    // defecto para no incrustar cadenas de IOC en el binario).
    crate::heuristics::load_keywords_file(&cfg.data_dir.join("heuristics.txt"));

    let mut signatures = SignatureDb::new();
    signatures.add_hash(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File",
    );
    // Firma EICAR por patrón: la cadena COMPLETA del fichero de prueba estándar
    // (no sólo "EICAR", que causaría falsos positivos en ficheros que la
    // mencionan, p. ej. logs o el propio journal de cuarentena).
    let _ = signatures.load_from_str(
        "pattern 45494341522d5354414e444152442d414e544956495255532d544553542d46494c45 EICAR-Pattern",
    );
    if let Ok(text) = std::fs::read_to_string(&cfg.signatures_path) {
        let _ = signatures.load_from_str(&text);
    }

    let mut local_rep = LocalReputationCache::new();
    local_rep.add_bad("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

    let license = License::load_or_init(&cfg.license_path);

    let state = Arc::new(AppState {
        cfg,
        signatures: Arc::new(RwLock::new(signatures)),
        local_rep: Arc::new(local_rep),
        jobs: Mutex::new(HashMap::new()),
        last_update: Mutex::new(None),
        license: Mutex::new(license),
        realtime: Arc::new(RealtimeService::new()),
    });

    // Auto-actualización silenciosa al arrancar (si hay servidor configurado).
    if state.cfg.cloud_url.is_some() {
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = do_update(&st);
        });
    }

    // Protección en tiempo real: se activa por defecto si la licencia lo permite.
    if state
        .license
        .lock()
        .map(|l| l.is_functional())
        .unwrap_or(false)
    {
        start_realtime(&state);
    }

    let listener = TcpListener::bind(addr)?;
    println!("NGAV UI en http://{addr}  (Ctrl+C para salir)");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(s, st) {
                        eprintln!("[ui] conexión: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[ui] accept: {e}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) -> std::io::Result<()> {
    let req = match read_request(&mut stream)? {
        Some(r) => r,
        None => return Ok(()),
    };

    // Seguridad: rechaza peticiones de orígenes no locales (CSRF/DNS-rebinding).
    if !is_local_origin(&req) {
        return write_response(
            &mut stream,
            "403 Forbidden",
            "application/json",
            br#"{"error":"origen no permitido"}"#,
        );
    }

    let (status, content_type, body): (&str, &str, Vec<u8>) =
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") | ("GET", "/index.html") => {
                ("200 OK", "text/html; charset=utf-8", INDEX_HTML.into())
            }
            ("GET", "/styles.css") => ("200 OK", "text/css; charset=utf-8", STYLES_CSS.into()),
            ("GET", "/app.js") => (
                "200 OK",
                "application/javascript; charset=utf-8",
                APP_JS.into(),
            ),
            ("GET", "/api/status") => (
                "200 OK",
                "application/json",
                api_status(&state).into_bytes(),
            ),
            ("GET", "/api/quarantine") => (
                "200 OK",
                "application/json",
                api_quarantine_list(&state).into_bytes(),
            ),
            ("POST", "/api/scan/start") => (
                "200 OK",
                "application/json",
                api_scan_start(&state, &req.body).into_bytes(),
            ),
            ("GET", "/api/scan/progress") => (
                "200 OK",
                "application/json",
                api_scan_progress(&state, &req.query).into_bytes(),
            ),
            ("GET", "/api/license") => (
                "200 OK",
                "application/json",
                api_license(&state).into_bytes(),
            ),
            ("POST", "/api/license/activate") => (
                "200 OK",
                "application/json",
                api_license_activate(&state, &req.body).into_bytes(),
            ),
            ("POST", "/api/checkout") => (
                "200 OK",
                "application/json",
                api_checkout(&state, &req.body).into_bytes(),
            ),
            ("GET", "/api/realtime") => (
                "200 OK",
                "application/json",
                api_realtime_status(&state).into_bytes(),
            ),
            ("GET", "/api/realtime/events") => (
                "200 OK",
                "application/json",
                api_realtime_events(&state).into_bytes(),
            ),
            ("POST", "/api/realtime/start") => (
                "200 OK",
                "application/json",
                api_realtime_start(&state).into_bytes(),
            ),
            ("POST", "/api/realtime/stop") => (
                "200 OK",
                "application/json",
                api_realtime_stop(&state).into_bytes(),
            ),
            ("POST", "/api/optimize") => (
                "200 OK",
                "application/json",
                api_optimize(&state).into_bytes(),
            ),
            ("POST", "/api/update") => (
                "200 OK",
                "application/json",
                api_update(&state).into_bytes(),
            ),
            ("POST", "/api/selftest") => (
                "200 OK",
                "application/json",
                api_selftest(&state).into_bytes(),
            ),
            ("POST", "/api/quarantine/action") => (
                "200 OK",
                "application/json",
                api_quarantine_action(&state, &req.body).into_bytes(),
            ),
            _ => (
                "404 Not Found",
                "application/json",
                br#"{"error":"no encontrado"}"#.to_vec(),
            ),
        };

    write_response(&mut stream, status, content_type, &body)
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let mut it = request_line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let raw_path = it.next().unwrap_or("/").to_string();
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_path, String::new()),
    };

    let mut content_length = 0usize;
    let mut host = String::new();
    let mut origin = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = lower.strip_prefix("host:") {
            host = v.trim().to_string();
        } else if let Some(v) = lower.strip_prefix("origin:") {
            origin = v.trim().to_string();
        }
    }

    // Anti-DoS: rechaza cuerpos por encima del tope.
    if content_length > MAX_BODY {
        return Ok(None);
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf)?;
        body = String::from_utf8_lossy(&buf).to_string();
    }

    Ok(Some(Request {
        method,
        path,
        query,
        body,
        host,
        origin,
    }))
}

/// Sólo se aceptan peticiones cuyo `Host`/`Origin` apunte a localhost. Bloquea
/// ataques de DNS-rebinding y CSRF desde el navegador contra la API local.
fn is_local_origin(req: &Request) -> bool {
    let host_ok = req.host.is_empty()
        || req.host.starts_with("127.0.0.1")
        || req.host.starts_with("localhost")
        || req.host.starts_with("[::1]");
    let origin_ok = req.origin.is_empty()
        || req.origin.contains("127.0.0.1")
        || req.origin.contains("localhost")
        || req.origin.contains("[::1]");
    host_ok && origin_ok
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

// --- Handlers de la API (JSON construido a mano, sin serde) ---

fn api_status(state: &AppState) -> String {
    let q = Quarantine::new(&state.cfg.quarantine_dir);
    let qn = q.list().map(|v| v.len()).unwrap_or(0);
    let sig_count = state.signatures.read().map(|s| s.len()).unwrap_or(0);
    let idx_exists = state.cfg.index_path.exists();
    let mut score = 85i32;
    if sig_count == 0 {
        score -= 40;
    }
    score -= (qn as i32).min(20);
    let cloud = state.cfg.cloud_url.clone().unwrap_or_default();
    let last_update = state.last_update.lock().ok().and_then(|g| *g).unwrap_or(0);
    let (lstate, days_left) = state
        .license
        .lock()
        .map(|l| (l.state().as_str().to_string(), l.days_left()))
        .unwrap_or_else(|_| ("trial".to_string(), 0));
    format!(
        r#"{{"version":"{}","protection":"active","signatures":{},"quarantine":{},"scanned_before":{},"cloud":"{}","last_update":{},"score":{},"license_state":"{}","days_left":{},"realtime":{}}}"#,
        VERSION,
        sig_count,
        qn,
        idx_exists,
        json_escape(&cloud),
        last_update,
        score,
        lstate,
        days_left,
        state.realtime.is_running()
    )
}

fn api_quarantine_list(state: &AppState) -> String {
    let q = Quarantine::new(&state.cfg.quarantine_dir);
    let items = q.list().unwrap_or_default();
    let mut parts = Vec::new();
    for e in items {
        parts.push(format!(
            r#"{{"id":"{}","threat":"{}","path":"{}","timestamp":{}}}"#,
            json_escape(&e.id),
            json_escape(&e.threat),
            json_escape(&e.original_path),
            e.timestamp
        ));
    }
    format!(r#"{{"items":[{}]}}"#, parts.join(","))
}

fn api_quarantine_action(state: &AppState, body: &str) -> String {
    let id = json_field(body, "id").unwrap_or_default();
    let action = json_field(body, "action").unwrap_or_default();
    let q = Quarantine::new(&state.cfg.quarantine_dir);
    let result = match action.as_str() {
        "restore" => q.restore(&id).map(|p| p.display().to_string()),
        "delete" => q.delete(&id).map(|_| "eliminado".to_string()),
        _ => Err(std::io::Error::other("acción desconocida")),
    };
    match result {
        Ok(msg) => format!(r#"{{"ok":true,"message":"{}"}}"#, json_escape(&msg)),
        Err(e) => format!(
            r#"{{"ok":false,"error":"{}"}}"#,
            json_escape(&e.to_string())
        ),
    }
}

/// Lanza un escaneo en segundo plano y devuelve el id del trabajo.
fn api_scan_start(state: &Arc<AppState>, body: &str) -> String {
    // Control de licencia: bloquea el escaneo si la prueba expiró y no hay
    // suscripción activa.
    let functional = state
        .license
        .lock()
        .map(|l| l.is_functional())
        .unwrap_or(true);
    if !functional {
        return r#"{"ok":false,"error":"license_required","message":"Tu prueba de 14 días ha finalizado. Suscríbete para seguir protegido."}"#.to_string();
    }

    let mode = ScanMode::from_arg(&json_field(body, "mode").unwrap_or_default());
    let custom = json_field(body, "path")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    let do_q = body.contains("\"quarantine\":true");

    let job_id = format!(
        "{}-{}",
        now(),
        state.jobs.lock().map(|j| j.len()).unwrap_or(0)
    );
    let progress = Arc::new(Mutex::new(Progress::new(mode)));
    if let Ok(mut jobs) = state.jobs.lock() {
        jobs.insert(job_id.clone(), Arc::clone(&progress));
    }

    let st = Arc::clone(state);
    std::thread::spawn(move || {
        // Guard de lectura de firmas durante todo el escaneo.
        let guard = match st.signatures.read() {
            Ok(g) => g,
            Err(_) => return,
        };
        let cloud = st
            .cfg
            .cloud_url
            .as_deref()
            .and_then(CloudReputationClient::from_url);
        let rep: &dyn ReputationSource = match &cloud {
            Some(c) => c,
            None => st.local_rep.as_ref(),
        };
        let engine = Engine::new(&guard)
            .with_reputation(rep)
            .with_thresholds(st.cfg.thresholds)
            .with_max_file_size(st.cfg.max_file_size);
        let q = Quarantine::new(&st.cfg.quarantine_dir);
        scanjob::run(&engine, &q, do_q, mode, custom, &progress);
    });

    format!(
        r#"{{"ok":true,"job_id":"{}","mode":"{}"}}"#,
        json_escape(&job_id),
        mode.label()
    )
}

/// Devuelve el progreso de un trabajo de escaneo (para la barra con %).
fn api_scan_progress(state: &AppState, query: &str) -> String {
    let id = query_param(query, "id").unwrap_or_default();
    let progress = state.jobs.lock().ok().and_then(|j| j.get(&id).cloned());
    let progress = match progress {
        Some(p) => p,
        None => return r#"{"ok":false,"error":"trabajo no encontrado"}"#.to_string(),
    };
    let p = progress.lock().unwrap();

    let hits: Vec<String> = p
        .hits
        .iter()
        .map(|h| {
            let reasons: Vec<String> = h
                .reasons
                .iter()
                .map(|r| format!(r#""{}""#, json_escape(r)))
                .collect();
            format!(
                r#"{{"path":"{}","verdict":"{}","score":{:.2},"threat":"{}","quarantined":{},"reasons":[{}]}}"#,
                json_escape(&h.path),
                json_escape(&h.verdict),
                h.score,
                json_escape(&h.threat),
                h.quarantined,
                reasons.join(",")
            )
        })
        .collect();

    format!(
        r#"{{"ok":true,"mode":"{}","percent":{},"total":{},"done":{},"finished":{},"current":"{}","scanned":{},"skipped":{},"malicious":{},"suspicious":{},"hits":[{}]}}"#,
        json_escape(&p.mode),
        p.percent(),
        p.total,
        p.done,
        p.finished,
        json_escape(&p.current),
        p.scanned,
        p.skipped,
        p.malicious,
        p.suspicious,
        hits.join(",")
    )
}

fn api_license(state: &AppState) -> String {
    let l = match state.license.lock() {
        Ok(l) => l,
        Err(_) => return r#"{"ok":false}"#.to_string(),
    };
    format!(
        r#"{{"ok":true,"state":"{}","days_left":{},"trial_days":{},"price":"{}","period":"{}","plan":"{}","until":{},"has_key":{}}}"#,
        l.state().as_str(),
        l.days_left(),
        licensing::TRIAL_DAYS,
        licensing::PRICE_USD,
        licensing::BILLING_PERIOD,
        json_escape(licensing::PLAN_NAME),
        l.active_until,
        !l.license_key.is_empty()
    )
}

fn api_license_activate(state: &AppState, body: &str) -> String {
    let key = json_field(body, "key").unwrap_or_default();
    if key.trim().is_empty() {
        return r#"{"ok":false,"error":"clave vacía"}"#.to_string();
    }

    // Validación: contra el servicio de licencias si está configurado; si no,
    // modo demo (acepta claves con el prefijo NGAV- y otorga 30 días).
    let thirty_days = 30 * 86_400;
    let (valid, until) = match state.cfg.license_url.as_deref() {
        Some(url) => match licensing::validate_key(url, &key) {
            Ok((v, u)) => (
                v,
                if u > 0 {
                    u
                } else {
                    licensing::now() + thirty_days
                },
            ),
            Err(e) => return format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e)),
        },
        None => (key.starts_with("NGAV-"), licensing::now() + thirty_days),
    };

    if !valid {
        return r#"{"ok":false,"error":"clave de licencia inválida"}"#.to_string();
    }

    match state.license.lock() {
        Ok(mut l) => {
            if let Err(e) = l.activate(&key, until, &state.cfg.license_path) {
                return format!(
                    r#"{{"ok":false,"error":"{}"}}"#,
                    json_escape(&e.to_string())
                );
            }
            format!(
                r#"{{"ok":true,"state":"{}","until":{}}}"#,
                l.state().as_str(),
                until
            )
        }
        Err(_) => r#"{"ok":false,"error":"lock"}"#.to_string(),
    }
}

fn api_checkout(state: &AppState, body: &str) -> String {
    let email = json_field(body, "email").unwrap_or_default();
    match state.cfg.license_url.as_deref() {
        Some(url) => match licensing::start_checkout(url, &email) {
            Ok((checkout_url, key)) => format!(
                r#"{{"ok":true,"url":"{}","demo_key":"{}"}}"#,
                json_escape(&checkout_url),
                json_escape(&key)
            ),
            Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e)),
        },
        None => r#"{"ok":false,"error":"El servicio de suscripción no está configurado (define NGAV_LICENSE_URL)."}"#.to_string(),
    }
}

// --- Protección en tiempo real ---

/// Construye la callback de escaneo para tiempo real, reutilizando el `Engine`
/// (sin duplicar la lógica de detección). Captura Arcs compartidos, no `AppState`
/// entero, para evitar ciclos de referencia.
fn build_scan_callback(state: &Arc<AppState>) -> ScanCallback {
    let signatures = Arc::clone(&state.signatures);
    let local_rep = Arc::clone(&state.local_rep);
    let cfg = state.cfg.clone();
    Arc::new(move |path: &Path| -> Option<ScanOutcome> {
        let guard = signatures.read().ok()?;
        let engine = Engine::new(&guard)
            .with_reputation(local_rep.as_ref())
            .with_thresholds(cfg.thresholds)
            .with_max_file_size(cfg.max_file_size);
        let v = engine.scan_path(path).ok()?;
        let verdict = format!("{}", v.verdict());
        let mut quarantined = false;
        if v.verdict() == crate::decision::Verdict::Malicious {
            let q = Quarantine::new(&cfg.quarantine_dir);
            quarantined = q
                .quarantine_file(&v.path, v.threat_name.as_deref().unwrap_or("Malware"))
                .is_ok();
        }
        Some(ScanOutcome {
            verdict,
            threat: v.threat_name.clone(),
            score: v.decision.score,
            quarantined,
        })
    })
}

/// Arranca la vigilancia en tiempo real sobre las zonas de riesgo del sistema.
fn start_realtime(state: &Arc<AppState>) {
    let dirs = crate::sysscan::scan_roots(ScanMode::Quick);
    let mut rt_cfg = RealtimeConfig::new(dirs);
    rt_cfg.max_file_size = state.cfg.max_file_size;
    // Excluir la carpeta de datos del propio agente (cuarentena, journal,
    // índice, licencia, firmas) para no auto-escanearse ni entrar en bucles.
    rt_cfg
        .excluded_substrings
        .push(state.cfg.data_dir.to_string_lossy().to_string());
    let scan = build_scan_callback(state);
    if let Err(e) = state.realtime.start(rt_cfg, scan) {
        eprintln!("[realtime] no se pudo iniciar: {e}");
    }
}

fn api_realtime_status(state: &AppState) -> String {
    let (scanned, detected, quarantined) = state.realtime.stats();
    format!(
        r#"{{"ok":true,"running":{},"started_at":{},"scanned":{},"detected":{},"quarantined":{}}}"#,
        state.realtime.is_running(),
        state.realtime.started_at(),
        scanned,
        detected,
        quarantined
    )
}

fn api_realtime_start(state: &Arc<AppState>) -> String {
    let functional = state
        .license
        .lock()
        .map(|l| l.is_functional())
        .unwrap_or(true);
    if !functional {
        return r#"{"ok":false,"error":"license_required"}"#.to_string();
    }
    start_realtime(state);
    api_realtime_status(state)
}

fn api_realtime_stop(state: &AppState) -> String {
    state.realtime.stop();
    api_realtime_status(state)
}

fn api_realtime_events(state: &AppState) -> String {
    let events = state.realtime.recent_events(100);
    let items: Vec<String> = events
        .iter()
        .map(|e| {
            format!(
                r#"{{"timestamp":{},"path":"{}","action":"{}","verdict":"{}","threat":"{}","score":{:.2},"quarantined":{}}}"#,
                e.timestamp,
                json_escape(&e.path),
                json_escape(&e.action),
                json_escape(&e.verdict),
                json_escape(e.threat.as_deref().unwrap_or("")),
                e.score,
                e.quarantined
            )
        })
        .collect();
    format!(r#"{{"ok":true,"events":[{}]}}"#, items.join(","))
}

/// Optimiza el sistema: limpia temporales reposados y libera memoria. Protege
/// la carpeta de datos del propio agente.
fn api_optimize(state: &AppState) -> String {
    let exclude = vec![state.cfg.data_dir.to_string_lossy().to_string()];
    // Sólo temporales sin tocar en los últimos 10 minutos (evita los activos).
    let report = crate::optimizer::optimize(&exclude, std::time::Duration::from_secs(600));
    format!(
        r#"{{"ok":true,"files_deleted":{},"bytes_freed":{},"dirs_scanned":{},"errors":{},"ram_total":{},"ram_avail_before":{},"ram_avail_after":{},"ram_freed":{}}}"#,
        report.clean.files_deleted,
        report.clean.bytes_freed,
        report.clean.dirs_scanned,
        report.clean.errors,
        report.ram_total,
        report.ram_avail_before,
        report.ram_avail_after,
        report.ram_freed()
    )
}

fn do_update(state: &AppState) -> Result<usize, String> {
    let url = state
        .cfg
        .cloud_url
        .clone()
        .or_else(|| std::env::var("NGAV_UPDATE_URL").ok())
        .ok_or("no hay servidor de actualizaciones configurado")?;
    let mut guard = state.signatures.write().map_err(|_| "lock envenenado")?;
    let res = updater::update_signatures(&url, &mut guard, Some(&state.cfg.signatures_path))?;
    if let Ok(mut lu) = state.last_update.lock() {
        *lu = Some(now());
    }
    Ok(res.rules_loaded)
}

fn api_update(state: &AppState) -> String {
    match do_update(state) {
        Ok(n) => format!(
            r#"{{"ok":true,"rules_loaded":{},"signatures":{}}}"#,
            n,
            state.signatures.read().map(|s| s.len()).unwrap_or(0)
        ),
        Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e)),
    }
}

fn api_selftest(state: &AppState) -> String {
    let dir = std::env::temp_dir().join("ngav-ui-selftest");
    if std::fs::create_dir_all(&dir).is_err() {
        return r#"{"ok":false,"error":"no se pudo crear temp"}"#.to_string();
    }
    let p = dir.join("eicar.com");
    if std::fs::write(&p, eicar_test_bytes()).is_err() {
        return r#"{"ok":false,"error":"no se pudo escribir eicar"}"#.to_string();
    }
    let guard = match state.signatures.read() {
        Ok(g) => g,
        Err(_) => return r#"{"ok":false,"error":"lock"}"#.to_string(),
    };
    let engine = Engine::new(&guard)
        .with_reputation(state.local_rep.as_ref())
        .with_thresholds(state.cfg.thresholds);
    let out = match engine.scan_path(&p) {
        Ok(v) => format!(
            r#"{{"ok":{},"verdict":"{}","threat":"{}","sha256":"{}"}}"#,
            v.verdict() == crate::decision::Verdict::Malicious,
            v.verdict(),
            json_escape(v.threat_name.as_deref().unwrap_or("")),
            v.sha256
        ),
        Err(e) => format!(
            r#"{{"ok":false,"error":"{}"}}"#,
            json_escape(&e.to_string())
        ),
    };
    let _ = std::fs::remove_file(&p);
    out
}

// --- Utilidades ---

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(url_decode(v));
            }
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8 as char);
                    i += 3;
                    continue;
                }
                out.push('%');
                i += 1;
            }
            b'+' => {
                out.push(' ');
                i += 1;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Extractor mínimo de un campo string de un JSON plano: `"key":"value"`.
fn json_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    match n {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        other => out.push(other),
                    }
                }
            }
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_extraction() {
        assert_eq!(
            json_field(r#"{"mode":"deep","quarantine":true}"#, "mode"),
            Some("deep".to_string())
        );
        assert_eq!(json_field(r#"{"a":"b"}"#, "missing"), None);
    }

    #[test]
    fn query_parsing() {
        assert_eq!(query_param("id=123-4&x=y", "id"), Some("123-4".to_string()));
        assert_eq!(query_param("a=b", "id"), None);
    }

    #[test]
    fn url_decoding() {
        assert_eq!(url_decode("a%2Fb+c"), "a/b c");
    }

    #[test]
    fn json_escape_handles_quotes() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }
}
