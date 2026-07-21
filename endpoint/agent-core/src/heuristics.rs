//! Heurística estática: reglas expertas baratas sobre el contenido del fichero.
//!
//! Produce una señal en [0.0, 1.0] combinando indicadores estructurales y de
//! contenido sospechosos. No es determinista como las firmas: complementa la
//! detección de variantes y familias sin firma exacta, a costa de más falsos
//! positivos (por eso su peso en la decisión es moderado).

use crate::decision::{Signal, Source};
use crate::entropy;

/// Cadenas asociadas a técnicas frecuentes de malware/scripting ofuscado.
/// Cada acierto suma peso. Lista ilustrativa (MVP); en producción vendría de
/// reglas actualizables desde la nube.
const SUSPICIOUS_STRINGS: &[(&[u8], f64, &str)] = &[
    (b"powershell -enc", 0.35, "PowerShell codificado"),
    (b"powershell -e ", 0.30, "PowerShell codificado"),
    (
        b"FromBase64String",
        0.20,
        "decodificación base64 en memoria",
    ),
    (b"CreateRemoteThread", 0.35, "inyección de hilo remoto"),
    (b"VirtualAllocEx", 0.25, "asignación de memoria remota"),
    (b"WriteProcessMemory", 0.30, "escritura en proceso ajeno"),
    (b"SetWindowsHookEx", 0.30, "hook global (posible keylogger)"),
    (b"GetAsyncKeyState", 0.25, "captura de teclado"),
    (
        b"vssadmin delete shadows",
        0.5,
        "borrado de shadow copies (ransomware)",
    ),
    (
        b"wbadmin delete catalog",
        0.4,
        "borrado de backups (ransomware)",
    ),
    (b"bcdedit /set", 0.25, "manipulación de arranque"),
    (
        b"schtasks /create",
        0.15,
        "persistencia por tarea programada",
    ),
    (b"reg add", 0.10, "modificación de registro"),
    (b"cmd.exe /c", 0.10, "ejecución de shell"),
    (b"Invoke-Expression", 0.25, "ejecución dinámica (IEX)"),
    (b"DownloadString", 0.20, "descarga y ejecución"),
];

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

    // 1) Entropía: comprimido/cifrado/empaquetado.
    let e = entropy::shannon(content);
    if e > 7.5 && content.len() > 512 {
        score += 0.4;
        reasons.push(format!("entropía muy alta ({e:.2} bits/byte)"));
    } else if e > 7.2 && content.len() > 512 {
        score += 0.2;
        reasons.push(format!("entropía alta ({e:.2} bits/byte)"));
    }

    // 2) Ejecutable PE (cabecera MZ) — contexto, no malicia por sí mismo.
    let is_pe = content.starts_with(b"MZ");
    if is_pe {
        reasons.push("ejecutable PE".to_string());
        // PE + entropía muy alta refuerza sospecha de empaquetado.
        if e > 7.2 {
            score += 0.15;
        }
    }

    // 3) Cadenas sospechosas (búsqueda case-insensitive simple).
    let lower = to_lower(content);
    for (needle, weight, label) in SUSPICIOUS_STRINGS {
        let needle_lower = to_lower(needle);
        if window_contains(&lower, &needle_lower) {
            score += weight;
            reasons.push((*label).to_string());
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
    fn ransomware_indicators_score_high() {
        let content = b"cmd.exe /c vssadmin delete shadows /all /quiet && wbadmin delete catalog";
        let r = analyze_detailed(content);
        assert!(
            r.score >= 0.6,
            "score {} too low for ransomware iocs",
            r.score
        );
    }

    #[test]
    fn keylogger_indicators_flagged() {
        let content = b"...SetWindowsHookEx...GetAsyncKeyState...";
        let s = analyze(content);
        assert!(s.score > 0.3);
    }

    #[test]
    fn high_entropy_blob_flagged() {
        let data: Vec<u8> = (0..2048u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let r = analyze_detailed(&data);
        assert!(r.score > 0.0);
    }
}
