//! Selección de objetivos de escaneo por modo y enumeración de procesos en
//! ejecución (para el "escaneo profundo de la CPU").
//!
//! - Escaneo RÁPIDO: zonas de alto riesgo (temporales, descargas, autoarranque,
//!   perfiles de usuario) + procesos en ejecución.
//! - Escaneo PROFUNDO: unidad(es) completa(s) del sistema + procesos.
//!
//! Multiplataforma con detección en tiempo de compilación/ejecución.

use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Quick,
    Deep,
}

impl ScanMode {
    pub fn from_arg(s: &str) -> ScanMode {
        match s {
            "deep" | "full" | "profundo" => ScanMode::Deep,
            _ => ScanMode::Quick,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Quick => "rápido",
            ScanMode::Deep => "profundo",
        }
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

/// Directorios raíz a escanear según el modo.
pub fn scan_roots(mode: ScanMode) -> Vec<PathBuf> {
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();

    if cfg!(target_os = "windows") {
        let userprofile = env_path("USERPROFILE");
        let appdata = env_path("APPDATA");
        let localappdata = env_path("LOCALAPPDATA");
        let temp = env_path("TEMP");
        let sysdrive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());

        match mode {
            ScanMode::Quick => {
                if let Some(t) = temp {
                    roots.insert(t);
                }
                if let Some(u) = &userprofile {
                    roots.insert(u.join("Downloads"));
                    roots.insert(u.join("Desktop"));
                }
                if let Some(a) = appdata {
                    roots.insert(a);
                }
                if let Some(l) = localappdata {
                    roots.insert(l.join("Temp"));
                }
                if let Some(u) = &userprofile {
                    roots.insert(u.join(
                        "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    ));
                }
            }
            ScanMode::Deep => {
                // Unidad del sistema completa.
                roots.insert(PathBuf::from(format!("{sysdrive}\\")));
                if let Some(u) = userprofile {
                    roots.insert(u);
                }
            }
        }
    } else {
        // Unix (Linux/macOS)
        let home = env_path("HOME");
        match mode {
            ScanMode::Quick => {
                roots.insert(PathBuf::from("/tmp"));
                if let Some(h) = &home {
                    roots.insert(h.join("Downloads"));
                    roots.insert(h.join("Descargas"));
                    roots.insert(h.join("Desktop"));
                    roots.insert(h.join(".config"));
                    roots.insert(h.join(".local/share"));
                }
            }
            ScanMode::Deep => {
                if let Some(h) = home {
                    roots.insert(h);
                }
                roots.insert(PathBuf::from("/usr"));
                roots.insert(PathBuf::from("/opt"));
                roots.insert(PathBuf::from("/etc"));
                roots.insert(PathBuf::from("/tmp"));
            }
        }
    }

    // Solo rutas existentes.
    roots.into_iter().filter(|p| p.exists()).collect()
}

/// Directorios que NUNCA se recorren (pseudo-FS, dispositivos, datos del propio
/// agente) para evitar bucles, ruido o auto-escaneo.
pub fn is_excluded(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy();
    const EXCLUDED: &[&str] = &["/proc", "/sys", "/dev", "/run", "/.ngav", "\\.ngav"];
    EXCLUDED.iter().any(|e| s.contains(e))
}

/// Enumera los ejecutables de los procesos en ejecución (escaneo de la CPU).
pub fn process_executables() -> Vec<PathBuf> {
    // `mut` sólo se usa en Linux (rama /proc); en otros SO el conjunto queda
    // vacío hasta implementar la API nativa correspondiente.
    #[allow(unused_mut)]
    let mut set: BTreeSet<PathBuf> = BTreeSet::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.chars().all(|c| c.is_ascii_digit()) {
                    let exe = e.path().join("exe");
                    if let Ok(target) = std::fs::read_link(&exe) {
                        if target.exists() {
                            set.insert(target);
                        }
                    }
                }
            }
        }
    }

    // En Windows NO lanzamos PowerShell/cmd para enumerar procesos: ejecutar
    // comandos externos es un patrón que Windows Defender marca como
    // comportamiento malicioso ("el programa ejecuta comandos"). La enumeración
    // de procesos en Windows se implementará con la API nativa Toolhelp32
    // (CreateToolhelp32Snapshot) — sin lanzar procesos — en la Etapa 2 (motor de
    // comportamiento). Hasta entonces, el escaneo de procesos queda vacío en
    // Windows (el escaneo de ficheros no se ve afectado).

    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing() {
        assert_eq!(ScanMode::from_arg("deep"), ScanMode::Deep);
        assert_eq!(ScanMode::from_arg("full"), ScanMode::Deep);
        assert_eq!(ScanMode::from_arg("quick"), ScanMode::Quick);
        assert_eq!(ScanMode::from_arg("otra"), ScanMode::Quick);
    }

    #[test]
    fn exclusions() {
        assert!(is_excluded(std::path::Path::new("/proc/1/exe")));
        assert!(is_excluded(std::path::Path::new("/home/u/.ngav/x")));
        assert!(!is_excluded(std::path::Path::new("/home/u/Downloads/x")));
    }

    #[test]
    fn roots_exist() {
        // Al menos /tmp existe en el entorno de test (Unix).
        let roots = scan_roots(ScanMode::Quick);
        for r in &roots {
            assert!(r.exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn processes_enumerated() {
        // En Linux debe haber al menos un proceso (este test).
        let procs = process_executables();
        assert!(!procs.is_empty(), "debería enumerar procesos vía /proc");
    }
}
