//! Motor de análisis de comportamiento (Etapa 2).
//!
//! Consume un flujo de **eventos abstractos** del sistema y acumula
//! **indicadores** por proceso (mapeados a tácticas/técnicas MITRE ATT&CK),
//! produciendo una **puntuación de riesgo**. La decisión **nunca depende de una
//! sola técnica**: se combinan múltiples indicadores mediante fusión *noisy-OR*.
//!
//! ## Diseño (SOLID + anti-falso-positivo)
//! El núcleo trabaja con **categorías abstractas** (`enum Indicator`), no con
//! nombres de herramientas ni de APIs de Windows en texto plano. Así el binario
//! **no contiene cadenas** que otros antivirus marquen (lección de la Etapa 1).
//! El mapeo concreto «evento del SO → indicador» lo hace el **sensor**
//! (adaptador de plataforma: ETW en Windows, eBPF/proc en Linux), que es
//! *data-driven* y vive fuera de este núcleo. Así el motor es 100% testeable con
//! secuencias sintéticas, sin depender del sistema operativo.
//!
//! ## Explicabilidad
//! Cada alerta genera un informe legible ("por qué es peligroso"): técnicas
//! ATT&CK detectadas + puntuación, para mostrar al usuario.

use std::collections::HashMap;

/// Indicador de comportamiento (categoría abstracta ligada a MITRE ATT&CK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Indicator {
    ProcessInjection,         // T1055
    ReflectiveLoad,           // T1620
    ProcessHollowing,         // T1055.012
    ApcInjection,             // T1055.004
    CredentialAccess,         // T1003
    DefenseEvasion,           // T1562
    LivingOffTheLand,         // T1218
    ShadowCopyDeletion,       // T1490
    MassFileEncryption,       // ransomware (impacto)
    RegistryPersistence,      // T1547
    ScheduledTaskPersistence, // T1053
    WmiExecution,             // T1047
    ServiceInstall,           // T1543
    DriverLoad,               // T1014
    Keylogging,               // T1056
    C2Beacon,                 // T1071
    Exfiltration,             // T1041
}

impl Indicator {
    /// Peso de evidencia en [0,1] para la fusión noisy-OR.
    pub fn weight(self) -> f64 {
        use Indicator::*;
        match self {
            ProcessHollowing => 0.55,
            ShadowCopyDeletion => 0.55,
            CredentialAccess => 0.5,
            MassFileEncryption => 0.5,
            ReflectiveLoad => 0.45,
            DefenseEvasion => 0.45,
            ProcessInjection => 0.4,
            ApcInjection => 0.4,
            DriverLoad => 0.4,
            Keylogging => 0.4,
            Exfiltration => 0.4,
            C2Beacon => 0.35,
            WmiExecution => 0.25,
            ServiceInstall => 0.25,
            LivingOffTheLand => 0.25,
            RegistryPersistence => 0.2,
            ScheduledTaskPersistence => 0.2,
        }
    }

    /// Identificador de técnica MITRE ATT&CK.
    pub fn mitre(self) -> &'static str {
        use Indicator::*;
        match self {
            ProcessInjection => "T1055",
            ReflectiveLoad => "T1620",
            ProcessHollowing => "T1055.012",
            ApcInjection => "T1055.004",
            CredentialAccess => "T1003",
            DefenseEvasion => "T1562",
            LivingOffTheLand => "T1218",
            ShadowCopyDeletion => "T1490",
            MassFileEncryption => "T1486",
            RegistryPersistence => "T1547",
            ScheduledTaskPersistence => "T1053",
            WmiExecution => "T1047",
            ServiceInstall => "T1543",
            DriverLoad => "T1014",
            Keylogging => "T1056",
            C2Beacon => "T1071",
            Exfiltration => "T1041",
        }
    }

    /// Descripción legible (para el informe al usuario).
    pub fn describe(self) -> &'static str {
        use Indicator::*;
        match self {
            ProcessInjection => "inyección de código en otro proceso",
            ReflectiveLoad => "carga reflexiva de módulo en memoria",
            ProcessHollowing => "vaciado y reemplazo de un proceso (hollowing)",
            ApcInjection => "inyección mediante colas APC",
            CredentialAccess => "acceso a credenciales del sistema",
            DefenseEvasion => "intento de desactivar defensas de seguridad",
            LivingOffTheLand => "abuso de herramientas legítimas del sistema",
            ShadowCopyDeletion => "borrado de copias de seguridad (shadow copies)",
            MassFileEncryption => "cifrado masivo de ficheros",
            RegistryPersistence => "persistencia mediante el registro",
            ScheduledTaskPersistence => "persistencia mediante tarea programada",
            WmiExecution => "ejecución a través de WMI",
            ServiceInstall => "instalación de un servicio",
            DriverLoad => "carga de un driver",
            Keylogging => "captura de pulsaciones de teclado",
            C2Beacon => "comunicación con servidor de control (C2)",
            Exfiltration => "posible exfiltración de datos",
        }
    }
}

/// Veredicto del motor de comportamiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Benign,
    Suspicious,
    Malicious,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Benign => "BENIGNO",
            RiskLevel::Suspicious => "SOSPECHOSO",
            RiskLevel::Malicious => "MALICIOSO",
        }
    }
}

/// Umbrales de decisión (configurables por política).
#[derive(Debug, Clone, Copy)]
pub struct RiskThresholds {
    pub suspicious: f64,
    pub malicious: f64,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        RiskThresholds {
            suspicious: 0.45,
            malicious: 0.75,
        }
    }
}

/// Evento abstracto observado por el sensor. `indicators` son las categorías
/// que el sensor asignó a partir de la actividad real (datos de runtime).
#[derive(Debug, Clone)]
pub struct SystemEvent {
    pub pid: u32,
    pub ppid: u32,
    pub indicators: Vec<Indicator>,
    /// Contexto legible (nombre de proceso, ruta, etc.) — dato de runtime.
    pub detail: String,
}

impl SystemEvent {
    pub fn new(pid: u32, indicators: Vec<Indicator>) -> Self {
        SystemEvent {
            pid,
            ppid: 0,
            indicators,
            detail: String::new(),
        }
    }
}

/// Estado de riesgo acumulado de un proceso (y su árbol).
#[derive(Debug, Clone, Default)]
struct ProcessRisk {
    ppid: u32,
    indicators: Vec<Indicator>, // distintos, en orden de aparición
}

impl ProcessRisk {
    fn add(&mut self, ind: Indicator) {
        if !self.indicators.contains(&ind) {
            self.indicators.push(ind);
        }
    }

    /// Fusión *noisy-OR*: combina evidencia independiente. Varios indicadores
    /// débiles escalan, pero ninguno solo llega al máximo.
    fn score(&self) -> f64 {
        let mut inv = 1.0f64;
        for ind in &self.indicators {
            inv *= 1.0 - ind.weight();
        }
        1.0 - inv
    }
}

/// Alerta de comportamiento con explicación.
#[derive(Debug, Clone)]
pub struct RiskAlert {
    pub pid: u32,
    pub score: f64,
    pub level: RiskLevel,
    pub indicators: Vec<Indicator>,
    pub explanation: String,
}

/// Motor de comportamiento: acumula indicadores por proceso y puntúa el riesgo.
pub struct BehaviorEngine {
    processes: HashMap<u32, ProcessRisk>,
    thresholds: RiskThresholds,
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new(RiskThresholds::default())
    }
}

impl BehaviorEngine {
    pub fn new(thresholds: RiskThresholds) -> Self {
        BehaviorEngine {
            processes: HashMap::new(),
            thresholds,
        }
    }

    /// Procesa un evento; devuelve una alerta si el proceso alcanza un nivel de
    /// riesgo accionable (sospechoso o malicioso).
    pub fn observe(&mut self, ev: &SystemEvent) -> Option<RiskAlert> {
        let (score, indicators) = {
            let entry = self.processes.entry(ev.pid).or_default();
            if ev.ppid != 0 {
                entry.ppid = ev.ppid;
            }
            for ind in &ev.indicators {
                entry.add(*ind);
            }
            (entry.score(), entry.indicators.clone())
        };

        let level = self.level_for(score);
        if level == RiskLevel::Benign {
            return None;
        }
        Some(RiskAlert {
            pid: ev.pid,
            score,
            level,
            explanation: explain(&indicators, score, level),
            indicators,
        })
    }

    fn level_for(&self, score: f64) -> RiskLevel {
        if score >= self.thresholds.malicious {
            RiskLevel::Malicious
        } else if score >= self.thresholds.suspicious {
            RiskLevel::Suspicious
        } else {
            RiskLevel::Benign
        }
    }

    /// Puntuación actual de un proceso (0 si desconocido).
    pub fn score_of(&self, pid: u32) -> f64 {
        self.processes.get(&pid).map(|p| p.score()).unwrap_or(0.0)
    }

    /// Olvida el estado de un proceso terminado (libera memoria).
    pub fn forget(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }
}

/// Genera un informe legible del riesgo (para la interfaz / el usuario).
pub fn explain(indicators: &[Indicator], score: f64, level: RiskLevel) -> String {
    let mut out = format!(
        "Riesgo {} (puntuación {:.2}). Motivos detectados:",
        level.as_str(),
        score
    );
    for ind in indicators {
        out.push_str(&format!("\n  • [{}] {}", ind.mitre(), ind.describe()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use Indicator::*;

    #[test]
    fn single_weak_indicator_is_not_malicious() {
        let mut eng = BehaviorEngine::default();
        // Persistencia por registro sola: sospechosa a lo sumo, no maliciosa.
        let alert = eng.observe(&SystemEvent::new(100, vec![RegistryPersistence]));
        assert!(alert.is_none() || alert.unwrap().level != RiskLevel::Malicious);
    }

    #[test]
    fn injection_chain_escalates_to_malicious() {
        let mut eng = BehaviorEngine::default();
        // Cadena típica de inyección: allocate+write+remote-thread (mapeados por
        // el sensor a estas categorías) + acceso a credenciales + evasión.
        eng.observe(&SystemEvent::new(200, vec![ProcessInjection]));
        eng.observe(&SystemEvent::new(200, vec![CredentialAccess]));
        let alert = eng
            .observe(&SystemEvent::new(200, vec![DefenseEvasion]))
            .expect("debería alertar");
        assert_eq!(alert.level, RiskLevel::Malicious);
        assert!(alert.explanation.contains("T1055"));
        assert!(alert.explanation.contains("T1003"));
    }

    #[test]
    fn ransomware_pattern_is_malicious() {
        let mut eng = BehaviorEngine::default();
        eng.observe(&SystemEvent::new(300, vec![ShadowCopyDeletion]));
        let alert = eng
            .observe(&SystemEvent::new(300, vec![MassFileEncryption]))
            .expect("debería alertar");
        assert_eq!(alert.level, RiskLevel::Malicious);
        assert!(alert.explanation.contains("T1490"));
    }

    #[test]
    fn duplicate_indicators_do_not_double_count() {
        let mut eng = BehaviorEngine::default();
        eng.observe(&SystemEvent::new(400, vec![ProcessHollowing]));
        let s1 = eng.score_of(400);
        eng.observe(&SystemEvent::new(400, vec![ProcessHollowing]));
        let s2 = eng.score_of(400);
        assert_eq!(s1, s2, "un mismo indicador no debe sumar dos veces");
    }

    #[test]
    fn noisy_or_is_monotonic_and_bounded() {
        let mut eng = BehaviorEngine::default();
        eng.observe(&SystemEvent::new(500, vec![LivingOffTheLand]));
        let s1 = eng.score_of(500);
        eng.observe(&SystemEvent::new(500, vec![WmiExecution, ServiceInstall]));
        let s2 = eng.score_of(500);
        assert!(s2 > s1, "más indicadores => más riesgo");
        assert!(s2 < 1.0, "la puntuación nunca alcanza 1.0");
    }

    #[test]
    fn forget_clears_state() {
        let mut eng = BehaviorEngine::default();
        eng.observe(&SystemEvent::new(600, vec![ProcessHollowing]));
        assert!(eng.score_of(600) > 0.0);
        eng.forget(600);
        assert_eq!(eng.score_of(600), 0.0);
    }
}
