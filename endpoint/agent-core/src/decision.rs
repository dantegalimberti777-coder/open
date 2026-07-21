//! Motor de decisión: fusiona las señales de las distintas capas de detección
//! en un veredicto final ponderado.
//!
//! Filosofía de defensa en profundidad: ninguna capa decide sola. Las firmas
//! confirmadas actúan como veto duro (bloqueo inmediato); el resto de señales
//! (heurística, reputación, ML/comportamiento) se combinan de forma ponderada
//! y se calibran contra umbrales configurables por política.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Verdict::Clean => "LIMPIO",
            Verdict::Suspicious => "SOSPECHOSO",
            Verdict::Malicious => "MALICIOSO",
        };
        write!(f, "{s}")
    }
}

/// Identifica la capa de detección que produjo una señal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Signature,
    Heuristic,
    Reputation,
    Behavior,
    Anomaly,
    MachineLearning,
}

impl Source {
    /// Peso relativo de cada capa en la fusión. Las firmas se tratan aparte
    /// (veto), por eso su peso aquí no se usa para la media ponderada.
    fn weight(self) -> f64 {
        match self {
            Source::Signature => 0.0, // veto, no promedia
            Source::Reputation => 0.35,
            Source::Behavior => 0.30,
            Source::MachineLearning => 0.25,
            Source::Heuristic => 0.20,
            Source::Anomaly => 0.15,
        }
    }
}

/// Una señal parcial: `score` en [0.0, 1.0] donde 1.0 = máxima malicia.
#[derive(Debug, Clone)]
pub struct Signal {
    pub source: Source,
    pub score: f64,
    pub reason: String,
    /// Si es `true`, un score alto fuerza veredicto MALICIOSO (veto duro).
    pub hard_block: bool,
}

impl Signal {
    pub fn new(source: Source, score: f64, reason: impl Into<String>) -> Self {
        Signal {
            source,
            score: score.clamp(0.0, 1.0),
            reason: reason.into(),
            hard_block: false,
        }
    }

    pub fn hard(source: Source, reason: impl Into<String>) -> Self {
        Signal {
            source,
            score: 1.0,
            reason: reason.into(),
            hard_block: true,
        }
    }
}

/// Umbrales de decisión, configurables por política (balanceado por defecto).
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub suspicious: f64,
    pub malicious: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            suspicious: 0.45,
            malicious: 0.75,
        }
    }
}

impl Thresholds {
    /// Modo agresivo: baja los umbrales (más detección, más riesgo de FP).
    pub fn aggressive() -> Self {
        Thresholds {
            suspicious: 0.35,
            malicious: 0.6,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub score: f64,
    pub reasons: Vec<String>,
}

/// Combina las señales en una decisión final.
pub fn decide(signals: &[Signal], thresholds: Thresholds) -> Decision {
    let mut reasons = Vec::new();

    // 1) Veto duro: cualquier señal hard_block con score alto => MALICIOSO.
    for s in signals {
        if s.hard_block && s.score >= 0.999 {
            reasons.push(format!("[{:?}] {} (veto)", s.source, s.reason));
            return Decision {
                verdict: Verdict::Malicious,
                score: 1.0,
                reasons,
            };
        }
    }

    // 2) Media ponderada del resto de señales.
    let mut weighted_sum = 0.0;
    let mut weight_total = 0.0;
    for s in signals {
        let w = s.source.weight();
        if w > 0.0 {
            weighted_sum += w * s.score;
            weight_total += w;
            if s.score > 0.05 {
                reasons.push(format!(
                    "[{:?}] {} (score {:.2})",
                    s.source, s.reason, s.score
                ));
            }
        }
    }

    let score = if weight_total > 0.0 {
        weighted_sum / weight_total
    } else {
        0.0
    };

    let verdict = if score >= thresholds.malicious {
        Verdict::Malicious
    } else if score >= thresholds.suspicious {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    Decision {
        verdict,
        score,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_veto_is_malicious() {
        let signals = vec![Signal::hard(Source::Signature, "EICAR-Test-File")];
        let d = decide(&signals, Thresholds::default());
        assert_eq!(d.verdict, Verdict::Malicious);
        assert_eq!(d.score, 1.0);
    }

    #[test]
    fn clean_file_stays_clean() {
        let signals = vec![
            Signal::new(Source::Heuristic, 0.1, "low entropy"),
            Signal::new(Source::Reputation, 0.0, "known good"),
        ];
        let d = decide(&signals, Thresholds::default());
        assert_eq!(d.verdict, Verdict::Clean);
    }

    #[test]
    fn combined_weak_signals_become_suspicious() {
        let signals = vec![
            Signal::new(Source::Heuristic, 0.6, "high entropy"),
            Signal::new(Source::Reputation, 0.6, "rare, unsigned"),
            Signal::new(Source::Behavior, 0.5, "spawns child processes"),
        ];
        let d = decide(&signals, Thresholds::default());
        assert!(matches!(
            d.verdict,
            Verdict::Suspicious | Verdict::Malicious
        ));
    }

    #[test]
    fn strong_reputation_and_behavior_is_malicious() {
        let signals = vec![
            Signal::new(Source::Reputation, 0.95, "known bad in cloud"),
            Signal::new(Source::Behavior, 0.9, "mass file encryption"),
            Signal::new(Source::MachineLearning, 0.85, "model: malware 0.85"),
        ];
        let d = decide(&signals, Thresholds::default());
        assert_eq!(d.verdict, Verdict::Malicious);
    }
}
