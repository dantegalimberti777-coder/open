//! Configuración del agente y rutas de trabajo.

use crate::decision::Thresholds;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    /// Directorio base de datos del agente (índice, cuarentena, firmas).
    pub data_dir: PathBuf,
    /// Fichero de la base de firmas.
    pub signatures_path: PathBuf,
    /// Índice de escaneo incremental.
    pub index_path: PathBuf,
    /// Directorio de cuarentena.
    pub quarantine_dir: PathBuf,
    /// Umbrales de decisión.
    pub thresholds: Thresholds,
    /// URL del servicio de reputación en la nube (opcional).
    pub cloud_url: Option<String>,
    /// Fichero de estado de licencia (prueba/suscripción).
    pub license_path: PathBuf,
    /// URL del servicio de licencias/facturación (opcional).
    pub license_url: Option<String>,
    /// Tamaño máximo de fichero a leer completo en memoria (bytes).
    pub max_file_size: u64,
}

impl Config {
    pub fn with_data_dir(dir: PathBuf) -> Self {
        Config {
            signatures_path: dir.join("signatures.db"),
            index_path: dir.join("scan_index.tsv"),
            quarantine_dir: dir.join("quarantine"),
            license_path: dir.join("license.txt"),
            data_dir: dir,
            thresholds: Thresholds::default(),
            cloud_url: None,
            license_url: std::env::var("NGAV_LICENSE_URL").ok(),
            max_file_size: 256 * 1024 * 1024, // 256 MB
        }
    }

    /// Configuración por defecto en el directorio de datos estándar del usuario.
    pub fn default_paths() -> Self {
        let base = std::env::var_os("NGAV_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ngav")))
            .unwrap_or_else(|| PathBuf::from(".ngav"));
        Config::with_data_dir(base)
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.quarantine_dir)?;
        Ok(())
    }
}
