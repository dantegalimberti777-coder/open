//! Servidor HTTP embebido que sirve la interfaz de escritorio (SPA) y expone
//! el motor de detección por una API JSON local.
//!
//! Solo escucha en localhost (127.0.0.1) — la UI es un cliente local del
//! servicio, igual que en el diseño (la UI nunca tiene privilegios y habla con
//! el servicio por un canal local). Implementado sobre `std::net` (sin
//! dependencias externas): HTTP/1.1 mínimo, un hilo por conexión.

use crate::config::Config;
use crate::decision::Verdict;
use crate::engine::{Engine, FileVerdict};
use crate::quarantine::Quarantine;
use crate::reputation::{CloudReputationClient, LocalReputationCache, ReputationSource};
use crate::scanner::{scan_tree, ScanIndex};
use crate::signatures::SignatureDb;
use crate::{EICAR_TEST_STRING, VERSION};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

// Recursos estáticos de la UI (empaquetados en el binario).
const INDEX_HTML: &str = include_str!("../ui/index.html");
const STYLES_CSS: &str = include_str!("../ui/styles.css");
const APP_JS: &str = include_str!("../ui/app.js");

struct AppState {
    cfg: Config,
    signatures: SignatureDb,
    local_rep: LocalReputationCache,
}

struct Request {
    method: String,
    path: String,
    body: String,
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
        signatures,
        local_rep,
    });

    let listener = TcpListener::bind(addr)?;
    println!("NGAV UI en http://{addr}  (Ctrl+C para salir)");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(s, &st) {
                        eprintln!("[ui] conexión: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[ui] accept: {e}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, state: &AppState) -> std::io::Result<()> {
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
            ("GET", "/api/status") => {
                ("200 OK", "application/json", api_status(state).into_bytes())
            }
            ("GET", "/api/quarantine") => (
                "200 OK",
                "application/json",
                api_quarantine_list(state).into_bytes(),
            ),
            ("POST", "/api/scan") => (
                "200 OK",
                "application/json",
                api_scan(state, &req.body).into_bytes(),
            ),
            ("POST", "/api/selftest") => (
                "200 OK",
                "application/json",
                api_selftest(state).into_bytes(),
            ),
            ("POST", "/api/quarantine/action") => (
                "200 OK",
                "application/json",
                api_quarantine_action(state, &req.body).into_bytes(),
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
    let path = it.next().unwrap_or("/").to_string();

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
        if let Some(v) = trimmed.strip_prefix("Content-Length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf)?;
        body = String::from_utf8_lossy(&buf).to_string();
    }

    Ok(Some(Request { method, path, body }))
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

// --- Handlers de la API (construyen JSON a mano, sin serde) ---

fn api_status(state: &AppState) -> String {
    let q = Quarantine::new(&state.cfg.quarantine_dir);
    let qn = q.list().map(|v| v.len()).unwrap_or(0);
    let idx_exists = state.cfg.index_path.exists();
    // Puntuación de protección simple (demostrativa): base alta si hay firmas,
    // penaliza si hay elementos en cuarentena sin resolver.
    let mut score = 85i32;
    if state.signatures.is_empty() {
        score -= 40;
    }
    score -= (qn as i32).min(20);
    let cloud = state.cfg.cloud_url.clone().unwrap_or_default();
    format!(
        r#"{{"version":"{}","protection":"active","signatures":{},"quarantine":{},"scanned_before":{},"cloud":"{}","score":{}}}"#,
        VERSION,
        state.signatures.len(),
        qn,
        idx_exists,
        json_escape(&cloud),
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

fn build_engine<'a>(state: &'a AppState, cloud: &'a Option<CloudReputationClient>) -> Engine<'a> {
    let rep: &dyn ReputationSource = match cloud {
        Some(c) => c,
        None => &state.local_rep,
    };
    Engine::new(&state.signatures)
        .with_reputation(rep)
        .with_thresholds(state.cfg.thresholds)
        .with_max_file_size(state.cfg.max_file_size)
}

fn api_scan(state: &AppState, body: &str) -> String {
    let path = json_field(body, "path").unwrap_or_default();
    let do_q = body.contains("\"quarantine\":true");
    if path.is_empty() {
        return r#"{"ok":false,"error":"falta la ruta"}"#.to_string();
    }
    let target = std::path::PathBuf::from(&path);
    let meta = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(e) => {
            return format!(
                r#"{{"ok":false,"error":"{}"}}"#,
                json_escape(&e.to_string())
            )
        }
    };

    let cloud = state
        .cfg
        .cloud_url
        .as_deref()
        .and_then(CloudReputationClient::from_url);
    let engine = build_engine(state, &cloud);
    let q = Quarantine::new(&state.cfg.quarantine_dir);

    let mut hits: Vec<String> = Vec::new();
    let mut seen = 0usize;
    let mut scanned = 0usize;
    let mut skipped = 0usize;
    let mut malicious = 0usize;
    let mut suspicious = 0usize;

    let mut record = |v: &FileVerdict, q: &Quarantine| {
        let mut quarantined = false;
        if do_q && v.verdict() == Verdict::Malicious {
            quarantined = q
                .quarantine_file(&v.path, v.threat_name.as_deref().unwrap_or("Malware"))
                .is_ok();
        }
        let reasons: Vec<String> = v
            .decision
            .reasons
            .iter()
            .map(|r| format!(r#""{}""#, json_escape(r)))
            .collect();
        hits.push(format!(
            r#"{{"path":"{}","verdict":"{}","score":{:.2},"threat":"{}","quarantined":{},"reasons":[{}]}}"#,
            json_escape(&v.path.display().to_string()),
            v.verdict(),
            v.decision.score,
            json_escape(v.threat_name.as_deref().unwrap_or("")),
            quarantined,
            reasons.join(",")
        ));
    };

    if meta.is_dir() {
        let mut index = ScanIndex::load(&state.cfg.index_path);
        if let Ok(stats) = scan_tree(&engine, &target, &mut index, |v| {
            match v.verdict() {
                Verdict::Malicious => malicious += 1,
                Verdict::Suspicious => suspicious += 1,
                Verdict::Clean => {}
            }
            record(v, &q);
        }) {
            seen = stats.files_seen;
            scanned = stats.files_scanned;
            skipped = stats.files_skipped;
            malicious = stats.malicious;
            suspicious = stats.suspicious;
        }
        let _ = index.save(&state.cfg.index_path);
    } else if let Ok(v) = engine.scan_path(&target) {
        seen = 1;
        scanned = 1;
        match v.verdict() {
            Verdict::Malicious => malicious += 1,
            Verdict::Suspicious => suspicious += 1,
            Verdict::Clean => {}
        }
        if v.verdict() != Verdict::Clean {
            record(&v, &q);
        }
    }

    format!(
        r#"{{"ok":true,"summary":{{"seen":{seen},"scanned":{scanned},"skipped":{skipped},"malicious":{malicious},"suspicious":{suspicious}}},"hits":[{}]}}"#,
        hits.join(",")
    )
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
    let cloud = None;
    let engine = build_engine(state, &cloud);
    let out = match engine.scan_path(&p) {
        Ok(v) => format!(
            r#"{{"ok":{},"verdict":"{}","threat":"{}","sha256":"{}"}}"#,
            v.verdict() == Verdict::Malicious,
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

// --- Utilidades JSON mínimas ---

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
/// Suficiente para los cuerpos simples que envía la UI.
fn json_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    let rest = rest.strip_prefix('"')?;
    // Leer hasta la comilla de cierre no escapada.
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
            json_field(r#"{"path":"/tmp/x","quarantine":true}"#, "path"),
            Some("/tmp/x".to_string())
        );
        assert_eq!(
            json_field(r#"{"action":"restore","id":"abc"}"#, "id"),
            Some("abc".to_string())
        );
        assert_eq!(json_field(r#"{"a":"b"}"#, "missing"), None);
    }

    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("line\nbreak"), "line\\nbreak");
    }
}
