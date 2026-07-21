//! Análisis de reputación: consulta la reputación de un fichero por su hash.
//!
//! Dos implementaciones:
//! - `LocalReputationCache`: allowlist/denylist local (funciona offline). Es la
//!   primera línea y evita consultas de red innecesarias.
//! - `CloudReputationClient`: consulta el servicio de reputación en la nube vía
//!   HTTP (cliente mínimo sobre `std::net`). Solo se usa ante incertidumbre.
//!
//! La reputación aporta *inteligencia colectiva*: un binario visto en millones
//! de equipos durante años es probablemente legítimo; uno recién aparecido y
//! sin firma es sospechoso.

use crate::decision::{Signal, Source};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationVerdict {
    /// Conocido bueno (prevalente, firmado, en allowlist).
    Good,
    /// Conocido malo (en denylist / threat intel).
    Bad,
    /// Desconocido: no hay información suficiente.
    Unknown,
}

pub trait ReputationSource {
    fn lookup(&self, hash_hex: &str) -> ReputationVerdict;

    /// Traduce el veredicto de reputación en una señal para el motor de decisión.
    fn signal(&self, hash_hex: &str) -> Signal {
        match self.lookup(hash_hex) {
            ReputationVerdict::Bad => {
                Signal::new(Source::Reputation, 0.95, "hash en denylist de reputación")
            }
            ReputationVerdict::Good => {
                Signal::new(Source::Reputation, 0.0, "hash prevalente/allowlist")
            }
            ReputationVerdict::Unknown => Signal::new(
                Source::Reputation,
                0.3,
                "reputación desconocida (fichero raro)",
            ),
        }
    }
}

#[derive(Default)]
pub struct LocalReputationCache {
    good: HashSet<String>,
    bad: HashSet<String>,
}

impl LocalReputationCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_good(&mut self, hash_hex: &str) {
        self.good.insert(hash_hex.to_ascii_lowercase());
    }

    pub fn add_bad(&mut self, hash_hex: &str) {
        self.bad.insert(hash_hex.to_ascii_lowercase());
    }
}

impl ReputationSource for LocalReputationCache {
    fn lookup(&self, hash_hex: &str) -> ReputationVerdict {
        let h = hash_hex.to_ascii_lowercase();
        if self.bad.contains(&h) {
            ReputationVerdict::Bad
        } else if self.good.contains(&h) {
            ReputationVerdict::Good
        } else {
            ReputationVerdict::Unknown
        }
    }
}

/// Cliente HTTP mínimo hacia el servicio de reputación en la nube.
/// Endpoint esperado: `GET {base}/v1/reputation/{hash}` -> JSON con
/// `"verdict":"good|bad|unknown"`.
pub struct CloudReputationClient {
    host: String,
    port: u16,
    timeout: Duration,
}

impl CloudReputationClient {
    /// Crea el cliente a partir de una URL `http://host:port`.
    pub fn from_url(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("http://")?;
        let (hostport, _) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (hostport.to_string(), 80u16),
        };
        Some(CloudReputationClient {
            host,
            port,
            timeout: Duration::from_secs(3),
        })
    }

    fn http_get(&self, path: &str) -> std::io::Result<String> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: ngav-agent/0.1\r\n\r\n",
            self.host
        );
        stream.write_all(req.as_bytes())?;
        let mut buf = String::new();
        stream.read_to_string(&mut buf)?;
        Ok(buf)
    }
}

impl ReputationSource for CloudReputationClient {
    fn lookup(&self, hash_hex: &str) -> ReputationVerdict {
        let path = format!("/v1/reputation/{}", hash_hex.to_ascii_lowercase());
        match self.http_get(&path) {
            Ok(resp) => parse_verdict(&resp),
            // Sin conectividad: degradación elegante -> desconocido, no bloquea.
            Err(_) => ReputationVerdict::Unknown,
        }
    }
}

/// Extrae el veredicto de una respuesta (busca el campo en el cuerpo JSON).
fn parse_verdict(resp: &str) -> ReputationVerdict {
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or(resp);
    let b = body.to_ascii_lowercase();
    if b.contains("\"verdict\":\"bad\"") || b.contains("\"verdict\": \"bad\"") {
        ReputationVerdict::Bad
    } else if b.contains("\"verdict\":\"good\"") || b.contains("\"verdict\": \"good\"") {
        ReputationVerdict::Good
    } else {
        ReputationVerdict::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_cache_lookup() {
        let mut c = LocalReputationCache::new();
        c.add_bad("AABB");
        c.add_good("CCDD");
        assert_eq!(c.lookup("aabb"), ReputationVerdict::Bad);
        assert_eq!(c.lookup("ccdd"), ReputationVerdict::Good);
        assert_eq!(c.lookup("0000"), ReputationVerdict::Unknown);
    }

    #[test]
    fn bad_reputation_produces_high_signal() {
        let mut c = LocalReputationCache::new();
        c.add_bad("dead");
        assert!(c.signal("dead").score > 0.9);
        assert_eq!(c.signal("beef").score, 0.3); // unknown
    }

    #[test]
    fn url_parsing() {
        let c = CloudReputationClient::from_url("http://127.0.0.1:8080/x").unwrap();
        assert_eq!(c.host, "127.0.0.1");
        assert_eq!(c.port, 8080);
        assert!(CloudReputationClient::from_url("https://x").is_none());
    }

    #[test]
    fn verdict_parsing() {
        assert_eq!(
            parse_verdict("HTTP/1.1 200 OK\r\n\r\n{\"verdict\":\"bad\"}"),
            ReputationVerdict::Bad
        );
        assert_eq!(
            parse_verdict("HTTP/1.1 200 OK\r\n\r\n{\"verdict\":\"good\"}"),
            ReputationVerdict::Good
        );
    }
}
