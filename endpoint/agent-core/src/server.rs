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
use crate::quarantine::Quarantine;
use crate::reputation::{CloudReputationClient, LocalReputationCache, ReputationSource};
use crate::scanjob::{self, Progress};
use crate::signatures::SignatureDb;
use crate::sysscan::ScanMode;
use crate::{updater, EICAR_TEST_STRING, VERSION};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// Recursos estáticos de la UI (empaquetados en el binario).
const INDEX_HTML: &str = include_str!("../ui/index.html");
const STYLES_CSS: &str = include_str!("../ui/styles.css");
const APP_JS: &str = include_str!("../ui/app.js");

struct AppState {
    cfg: Config,
    signatures: RwLock<SignatureDb>,
    local_rep: LocalReputationCache,
    jobs: Mutex<HashMap<String, Arc<Mutex<Progress>>>>,
    last_update: Mutex<Option<u64>>,
}

struct Request {
    method: String,
    path: String,
    query: String,
    body: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Arranca el servidor de la UI. Bloquea aceptando conexiones.
pub fn serve(cfg: Config, addr: &str) -> std::io::Result<()> {
    cfg.ensure_dirs()?;

    let mut signatures = SignatureDb::new();
    signatures.add_hash(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File",
    );
    let _ = signatures.load_from_str("pattern 4549434152 EICAR-Pattern");
    if let Ok(text) = std::fs::read_to_string(&cfg.signatures_path) {
        let _ = signatures.load_from_str(&text);
    }

    let mut local_rep = LocalReputationCache::new();
    local_rep.add_bad("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

    let state = Arc::new(AppState {
        cfg,
        signatures: RwLock::new(signatures),
        local_rep,
        jobs: Mutex::new(HashMap::new()),
        last_update: Mutex::new(None),
    });

    // Auto-actualización silenciosa al arrancar (si hay servidor configurado).
    if state.cfg.cloud_url.is_some() {
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = do_update(&st);
        });
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
        }
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
    }))
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
    format!(
        r#"{{"version":"{}","protection":"active","signatures":{},"quarantine":{},"scanned_before":{},"cloud":"{}","last_update":{},"score":{}}}"#,
        VERSION,
        sig_count,
        qn,
        idx_exists,
        json_escape(&cloud),
        last_update,
        score
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
            None => &st.local_rep,
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
    if std::fs::write(&p, EICAR_TEST_STRING).is_err() {
        return r#"{"ok":false,"error":"no se pudo escribir eicar"}"#.to_string();
    }
    let guard = match state.signatures.read() {
        Ok(g) => g,
        Err(_) => return r#"{"ok":false,"error":"lock"}"#.to_string(),
    };
    let engine = Engine::new(&guard)
        .with_reputation(&state.local_rep)
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
