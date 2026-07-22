//! Heurística estática: reglas expertas baratas sobre el contenido del fichero.
//!
//! Produce una señal en [0.0, 1.0] combinando:
//!   1. Indicadores **estructurales** (entropía, cabecera PE) — sin cadenas.
//!   2. Palabras clave de indicadores (IOC) **cargadas en tiempo de ejecución**
//!      desde un fichero de datos opcional.
//!
//! ## Por qué las IOC NO van embebidas en el binario
//! Incrustar nombres de herramientas/técnicas de ataque (p. ej. utilidades de
//! volcado de credenciales o comandos de ransomware) como cadenas literales hace
//! que **otros antivirus (incl. Windows Defender) marquen nuestro propio `.exe`
//! como malicioso** ("el programa contiene/ejecuta comandos de atacante"). Por
//! eso el binario **no** contiene esas cadenas: las palabras clave se cargan de
//! un fichero externo opcional (`<data_dir>/heuristics.txt`) o se inyectan por
//! código. La detección de esas técnicas se cubre además con firmas (patrones
//! hex, que no son cadenas legibles) y, en la Etapa 2, con el motor de
//! comportamiento en tiempo de ejecución.

use crate::decision::{Signal, Source};
use crate::entropy;
use std::sync::OnceLock;

/// Palabra clave heurística cargada en runtime: (bytes en minúsculas, peso, etiqueta).
type Keyword = (Vec<u8>, f64, String);

static KEYWORDS: OnceLock<Vec<Keyword>> = OnceLock::new();

/// Inyecta la tabla de palabras clave (una sola vez). Uso: el agente la llama
/// al arrancar tras leer el fichero de indicadores, o los tests para probar.
/// Devuelve `true` si se estableció (si ya estaba puesta, no hace nada).
pub fn set_keywords(list: Vec<(String, f64, String)>) -> bool {
    let parsed: Vec<Keyword> = list
        .into_iter()
        .map(|(needle, weight, label)| (needle.to_ascii_lowercase().into_bytes(), weight, label))
        .collect();
    KEYWORDS.set(parsed).is_ok()
}

/// Carga palabras clave desde un fichero de texto opcional. Formato por línea:
/// `keyword|peso|etiqueta` (las líneas vacías y las que empiezan por `#` se
/// ignoran). Silencioso si el fichero no existe.
pub fn load_keywords_file(path: &std::path::Path) -> usize {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return 0,
    };
    let mut list = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() == 3 {
            if let Ok(w) = parts[1].trim().parse::<f64>() {
                list.push((parts[0].trim().to_string(), w, parts[2].trim().to_string()));
            }
        }
    }
    let n = list.len();
    set_keywords(list);
    n
}

fn keywords() -> &'static [Keyword] {
    KEYWORDS.get().map(|v| v.as_slice()).unwrap_or(&[])
}

pub struct HeuristicResult {
    pub score: f64,
    pub reasons: Vec<String>,
}

/// Analiza el contenido y devuelve una señal heurística.
pub fn analyze(content: &[u8]) -> Signal {
    let r = analyze_detailed(content);
    let reason = if r.reasons.is_empty() {
        "sin indicadores".to_string()
    } else {
        r.reasons.join("; ")
    };
    Signal::new(Source::Heuristic, r.score, reason)
}

pub fn analyze_detailed(content: &[u8]) -> HeuristicResult {
    let mut score = 0.0f64;
    let mut reasons = Vec::new();

    // 1) Entropía: comprimido/cifrado/empaquetado (señal estructural, sin cadenas).
    let e = entropy::shannon(content);
    if e > 7.5 && content.len() > 512 {
        score += 0.4;
        reasons.push(format!("entropía muy alta ({e:.2} bits/byte)"));
    } else if e > 7.2 && content.len() > 512 {
        score += 0.2;
        reasons.push(format!("entropía alta ({e:.2} bits/byte)"));
    }

    // 2) Ejecutable PE (cabecera MZ) — contexto, no malicia por sí mismo.
    if content.starts_with(b"MZ") {
        reasons.push("ejecutable PE".to_string());
        if e > 7.2 {
            score += 0.15; // PE + entropía alta => posible empaquetado
        }
    }

    // 3) Palabras clave de indicadores (sólo si se han cargado en runtime).
    let kws = keywords();
    if !kws.is_empty() {
        let lower = to_lower(content);
        for (needle, weight, label) in kws {
            if window_contains(&lower, needle) {
                score += weight;
                reasons.push(label.clone());
            }
        }
    }

    HeuristicResult {
        score: score.clamp(0.0, 1.0),
        reasons,
    }
}

fn to_lower(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_low_score() {
        let s = analyze(b"Hello, this is a perfectly normal text file. Nothing to see here.");
        assert!(s.score < 0.3, "score {} too high for benign text", s.score);
    }

    #[test]
    fn high_entropy_blob_flagged() {
        let data: Vec<u8> = (0..2048u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let r = analyze_detailed(&data);
        assert!(r.score > 0.0, "entropía alta debería puntuar");
    }

    #[test]
    fn pe_header_is_noted() {
        let mut data = vec![b'M', b'Z'];
        data.extend_from_slice(b"resto de un ejecutable de ejemplo");
        let r = analyze_detailed(&data);
        assert!(r.reasons.iter().any(|s| s.contains("PE")));
    }

    #[test]
    fn loaded_keywords_are_matched() {
        // Las IOC se inyectan en runtime (no están en el binario).
        set_keywords(vec![(
            "eviltoken".to_string(),
            0.9,
            "indicador de prueba".to_string(),
        )]);
        let r = analyze_detailed(b"contenido con EVILTOKEN dentro");
        assert!(r.reasons.iter().any(|s| s == "indicador de prueba"));
        assert!(r.score >= 0.9);
    }
}
