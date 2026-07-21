//! Auto-actualización de la base de firmas desde la nube.
//!
//! Descarga la base de firmas más reciente desde un servidor de actualizaciones
//! (`GET {url}/v1/signatures`), la persiste y la fusiona en la base en memoria.
//!
//! NOTA MVP: en producción el paquete iría FIRMADO (Ed25519) y verificado con
//! TUF + anti-rollback antes de aplicarse (ver docs/arquitectura.md §8). Aquí se
//! implementa el mecanismo de transporte y aplicación; la verificación
//! criptográfica es el siguiente paso del roadmap.

use crate::signatures::SignatureDb;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub struct UpdateResult {
    pub rules_loaded: usize,
    pub bytes: usize,
}

/// Descarga y aplica la base de firmas. Devuelve el nº de reglas cargadas.
/// `base_url` es como `http://host:port`.
pub fn update_signatures(
    base_url: &str,
    db: &mut SignatureDb,
    persist_path: Option<&std::path::Path>,
) -> Result<UpdateResult, String> {
    let (host, port) = parse_http_url(base_url).ok_or("URL de actualización inválida")?;
    let body = http_get(&host, port, "/v1/signatures").map_err(|e| e.to_string())?;

    let loaded = db.load_from_str(&body)?;

    if let Some(path) = persist_path {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, &body).map_err(|e| e.to_string())?;
    }

    Ok(UpdateResult {
        rules_loaded: loaded,
        bytes: body.len(),
    })
}

fn parse_http_url(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("http://")?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    match hostport.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((hostport.to_string(), 80)),
    }
}

fn http_get(host: &str, port: u16, path: &str) -> std::io::Result<String> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)?;
    let timeout = Duration::from_secs(5);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ngav-updater/0.1\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    // Separa cabeceras del cuerpo.
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:8080"),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            parse_http_url("http://host:9000/x"),
            Some(("host".to_string(), 9000))
        );
        assert_eq!(parse_http_url("https://x"), None);
    }
}
