//! Motor de firmas: denylist por hash SHA-256 y patrones de bytes (YARA-lite).
//!
//! Formato de la base de firmas (texto, una regla por línea):
//! ```text
//! # comentario
//! sha256 <64-hex> <nombre-amenaza>
//! pattern <hex-bytes> <nombre-amenaza>
//! ```
//! El formato de texto se elige para el MVP por simplicidad y auditabilidad;
//! en producción se sustituiría por un blob binario firmado y mapeado en
//! memoria (mmap) con Bloom filter para descarte O(1).

use crate::hash::to_hex;

#[derive(Debug, Clone)]
pub struct SignatureHit {
    pub name: String,
    pub kind: SignatureKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    Hash,
    Pattern,
}

#[derive(Default)]
pub struct SignatureDb {
    /// hash hex (minúsculas) -> nombre de amenaza.
    hashes: std::collections::HashMap<String, String>,
    /// (bytes del patrón, nombre).
    patterns: Vec<(Vec<u8>, String)>,
}

impl SignatureDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.hashes.len() + self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Carga reglas desde el texto de una base de firmas. Ignora líneas vacías
    /// y comentarios. Devuelve el número de reglas cargadas.
    pub fn load_from_str(&mut self, text: &str) -> Result<usize, String> {
        let mut loaded = 0;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, char::is_whitespace);
            let kind = parts.next().unwrap_or("");
            match kind {
                "sha256" => {
                    let h = parts
                        .next()
                        .ok_or_else(|| format!("línea {}: falta hash", lineno + 1))?;
                    let name = parts.next().unwrap_or("Malware.Generic").trim();
                    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(format!("línea {}: hash inválido", lineno + 1));
                    }
                    self.hashes.insert(h.to_ascii_lowercase(), name.to_string());
                    loaded += 1;
                }
                "pattern" => {
                    let hex = parts
                        .next()
                        .ok_or_else(|| format!("línea {}: falta patrón", lineno + 1))?;
                    let name = parts.next().unwrap_or("Malware.Pattern").trim();
                    let bytes = parse_hex(hex)
                        .ok_or_else(|| format!("línea {}: patrón hex inválido", lineno + 1))?;
                    if bytes.is_empty() {
                        return Err(format!("línea {}: patrón vacío", lineno + 1));
                    }
                    self.patterns.push((bytes, name.to_string()));
                    loaded += 1;
                }
                other => {
                    return Err(format!(
                        "línea {}: tipo desconocido '{}'",
                        lineno + 1,
                        other
                    ));
                }
            }
        }
        Ok(loaded)
    }

    /// Añade una firma de hash programáticamente (usado en tests y en pushes
    /// de emergencia).
    pub fn add_hash(&mut self, hash_hex: &str, name: &str) {
        self.hashes
            .insert(hash_hex.to_ascii_lowercase(), name.to_string());
    }

    /// Comprueba un fichero ya digerido (hash) y su contenido contra la base.
    /// Devuelve el primer acierto (los hits de hash tienen prioridad por ser
    /// deterministas y de coste O(1)).
    pub fn scan(&self, digest: &[u8; 32], content: &[u8]) -> Option<SignatureHit> {
        let hex = to_hex(digest);
        if let Some(name) = self.hashes.get(&hex) {
            return Some(SignatureHit {
                name: name.clone(),
                kind: SignatureKind::Hash,
            });
        }
        for (pat, name) in &self.patterns {
            if contains_subslice(content, pat) {
                return Some(SignatureHit {
                    name: name.clone(),
                    kind: SignatureKind::Pattern,
                });
            }
        }
        None
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Búsqueda de subsecuencia de bytes (naïve). Para el MVP es suficiente; en
/// producción se usaría Aho-Corasick para buscar miles de patrones a la vez.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;

    fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    }

    #[test]
    fn loads_and_matches_hash() {
        let mut db = SignatureDb::new();
        let d = digest(b"malicious content");
        let hex = to_hex(&d);
        let rules = format!("sha256 {hex} Test.Malware\n# comment\n");
        assert_eq!(db.load_from_str(&rules).unwrap(), 1);
        let hit = db.scan(&d, b"malicious content").unwrap();
        assert_eq!(hit.name, "Test.Malware");
        assert_eq!(hit.kind, SignatureKind::Hash);
    }

    #[test]
    fn matches_byte_pattern() {
        let mut db = SignatureDb::new();
        // "EVIL" = 45 56 49 4c ; "VIL" = 56 49 4c (subcadena presente)
        db.load_from_str("pattern 45564949 Test.Wrong\npattern 56494c Test.EvilSubstr")
            .unwrap();
        let content = b"prefix EVIL suffix";
        let d = digest(content);
        let hit = db.scan(&d, content).unwrap();
        assert_eq!(hit.name, "Test.EvilSubstr");
        assert_eq!(hit.kind, SignatureKind::Pattern);
    }

    #[test]
    fn clean_file_no_hit() {
        let mut db = SignatureDb::new();
        db.add_hash(&to_hex(&digest(b"bad")), "Bad");
        let content = b"totally fine";
        assert!(db.scan(&digest(content), content).is_none());
    }

    #[test]
    fn rejects_invalid_hash() {
        let mut db = SignatureDb::new();
        assert!(db.load_from_str("sha256 xyz Bad").is_err());
    }
}
