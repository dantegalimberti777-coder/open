//! Optimización del sistema: limpieza de ficheros temporales y liberación de
//! memoria. Es el motor detrás del botón **"Optimizar"** de la interfaz.
//!
//! ## Qué hace (y qué no, honestamente)
//! - **Temporales:** borra ficheros de las carpetas temporales que llevan un
//!   tiempo sin modificarse (para no tocar los que están en uso). Reporta cuántos
//!   ficheros y cuántos bytes liberó. Salta ficheros bloqueados y la carpeta de
//!   datos del propio antivirus.
//! - **RAM:** lee la memoria disponible del sistema (antes/después) y **recorta
//!   la memoria de trabajo del propio proceso** del agente (operación benigna).
//!   Un programa de usuario no puede "vaciar" la RAM de todo el sistema sin
//!   tocar otros procesos de forma invasiva; por eso el foco real está en
//!   liberar espacio de temporales y en reportar el estado de la memoria.
//!
//! Multiplataforma: la lectura de RAM y el recorte de working-set usan
//! `/proc/meminfo` en Linux y las APIs oficiales de Windows
//! (GlobalMemoryStatusEx / SetProcessWorkingSetSize).

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Resultado de la limpieza de temporales.
#[derive(Debug, Clone, Default)]
pub struct CleanReport {
    pub files_deleted: u64,
    pub bytes_freed: u64,
    pub dirs_scanned: usize,
    pub errors: u64,
}

/// Resultado global de "Optimizar".
#[derive(Debug, Clone, Default)]
pub struct OptimizeReport {
    pub clean: CleanReport,
    pub ram_total: u64,
    pub ram_avail_before: u64,
    pub ram_avail_after: u64,
}

impl OptimizeReport {
    /// RAM liberada (puede ser 0 o negativa según la actividad del sistema; se
    /// reporta 0 si no aumentó).
    pub fn ram_freed(&self) -> u64 {
        self.ram_avail_after.saturating_sub(self.ram_avail_before)
    }
}

/// Directorios temporales del sistema según la plataforma (sólo los existentes).
pub fn temp_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut push = |p: Option<PathBuf>| {
        if let Some(p) = p {
            dirs.push(p);
        }
    };
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);

    if cfg!(target_os = "windows") {
        push(env("TEMP"));
        push(env("TMP"));
        push(env("LOCALAPPDATA").map(|p| p.join("Temp")));
        push(env("windir").map(|p| p.join("Temp")));
    } else {
        push(Some(PathBuf::from("/tmp")));
        push(Some(PathBuf::from("/var/tmp")));
        push(env("HOME").map(|p| p.join(".cache")));
        push(env("TMPDIR"));
    }

    // Normaliza: existentes y sin duplicados.
    dirs.retain(|p| p.exists());
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Limpia ficheros temporales de `dirs` que llevan al menos `min_age` sin
/// modificarse. `exclude` son subcadenas de ruta a respetar (p. ej. la carpeta
/// de datos del agente).
pub fn clean_temp(dirs: &[PathBuf], min_age: Duration, exclude: &[String]) -> CleanReport {
    let mut report = CleanReport::default();
    let now = SystemTime::now();
    let mut stack: Vec<PathBuf> = dirs.to_vec();

    while let Some(dir) = stack.pop() {
        if is_excluded(&dir, exclude) {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                report.errors += 1;
                continue;
            }
        };
        report.dirs_scanned += 1;
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue; // no seguimos symlinks
            }
            if meta.is_dir() {
                if !is_excluded(&path, exclude) {
                    stack.push(path);
                }
                continue;
            }
            if !meta.is_file() || is_excluded(&path, exclude) {
                continue;
            }
            // Sólo ficheros "reposados" (evita los que están en uso).
            let age = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or(Duration::ZERO);
            if age < min_age {
                continue;
            }
            let size = meta.len();
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    report.files_deleted += 1;
                    report.bytes_freed += size;
                }
                Err(_) => report.errors += 1, // bloqueado / sin permiso: se ignora
            }
        }
    }
    report
}

fn is_excluded(path: &std::path::Path, exclude: &[String]) -> bool {
    let s = path.to_string_lossy();
    exclude
        .iter()
        .any(|e| !e.is_empty() && s.contains(e.as_str()))
}

/// Ejecuta la optimización completa. `exclude` protege rutas (p. ej. data_dir).
pub fn optimize(exclude: &[String], min_age: Duration) -> OptimizeReport {
    let (total, avail_before) = read_ram().unwrap_or((0, 0));
    let clean = clean_temp(&temp_dirs(), min_age, exclude);
    trim_working_set();
    let (_t2, avail_after) = read_ram().unwrap_or((total, avail_before));
    OptimizeReport {
        clean,
        ram_total: total,
        ram_avail_before: avail_before,
        ram_avail_after: avail_after,
    }
}

// --- Lectura de RAM (total, disponible) en bytes ---

#[cfg(target_os = "linux")]
pub fn read_ram() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("MemAvailable:") {
            avail = parse_kb(v);
        }
    }
    if total > 0 {
        Some((total, avail))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_kb(s: &str) -> u64 {
    // Formato: "  16384000 kB"
    s.split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

#[cfg(windows)]
pub fn read_ram() -> Option<(u64, u64)> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    unsafe {
        let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
        ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut ms).is_ok() {
            Some((ms.ullTotalPhys, ms.ullAvailPhys))
        } else {
            None
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn read_ram() -> Option<(u64, u64)> {
    None
}

// --- Recorte de la memoria de trabajo del propio proceso ---

#[cfg(windows)]
fn trim_working_set() {
    use windows::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
    // (SIZE_T)-1 en ambos parámetros indica a Windows que recorte el working set.
    unsafe {
        let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }
}

#[cfg(not(windows))]
fn trim_working_set() {
    // En Linux/macOS el recorte de RSS lo gestiona el asignador/kernel; no hay
    // una llamada portable equivalente y benigna. No-op.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ngav-opt-{}-{}",
            tag,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn deletes_reposed_files_and_reports_bytes() {
        let d = tmp("del");
        std::fs::write(d.join("a.tmp"), vec![0u8; 1000]).unwrap();
        std::fs::write(d.join("b.tmp"), vec![0u8; 2000]).unwrap();
        // min_age 0 => todos elegibles.
        let r = clean_temp(std::slice::from_ref(&d), Duration::ZERO, &[]);
        assert_eq!(r.files_deleted, 2);
        assert_eq!(r.bytes_freed, 3000);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn keeps_recent_files() {
        let d = tmp("keep");
        std::fs::write(d.join("fresh.tmp"), b"reciente").unwrap();
        // min_age grande => el fichero recién creado NO se borra.
        let r = clean_temp(std::slice::from_ref(&d), Duration::from_secs(3600), &[]);
        assert_eq!(r.files_deleted, 0);
        assert!(d.join("fresh.tmp").exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn respects_exclusions() {
        let d = tmp("excl");
        let keep = d.join("guardado");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::write(keep.join("x.tmp"), b"no borrar").unwrap();
        let r = clean_temp(
            std::slice::from_ref(&d),
            Duration::ZERO,
            &["guardado".to_string()],
        );
        assert_eq!(r.files_deleted, 0);
        assert!(keep.join("x.tmp").exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn recurses_into_subdirs() {
        let d = tmp("rec");
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("deep.tmp"), vec![0u8; 500]).unwrap();
        let r = clean_temp(std::slice::from_ref(&d), Duration::ZERO, &[]);
        assert_eq!(r.files_deleted, 1);
        assert_eq!(r.bytes_freed, 500);
        std::fs::remove_dir_all(&d).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_ram_on_linux() {
        let (total, avail) = read_ram().expect("debería leer /proc/meminfo");
        assert!(total > 0);
        assert!(avail <= total);
    }
}
