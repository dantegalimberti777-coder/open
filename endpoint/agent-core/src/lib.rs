//! # ngav-agent
//!
//! Núcleo del motor de detección híbrido del NGAV (MVP).
//!
//! Módulos:
//! - [`hash`]: SHA-256 en Rust puro (streaming).
//! - [`entropy`]: entropía de Shannon (indicador heurístico).
//! - [`signatures`]: firmas por hash y patrones de bytes.
//! - [`heuristics`]: heurística estática sobre el contenido.
//! - [`reputation`]: reputación local y cliente de nube.
//! - [`decision`]: fusión ponderada de señales -> veredicto.
//! - [`engine`]: orquestación por fichero.
//! - [`scanner`]: escaneo incremental de árboles de directorios.
//! - [`quarantine`]: aislamiento de ficheros maliciosos.
//! - [`config`]: configuración y rutas.

pub mod config;
pub mod decision;
pub mod engine;
pub mod entropy;
pub mod hash;
pub mod heuristics;
pub mod licensing;
pub mod quarantine;
pub mod reputation;
pub mod scanjob;
pub mod scanner;
pub mod server;
pub mod signatures;
pub mod sysscan;
pub mod updater;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cadena de prueba estándar EICAR (no es malware real; es el fichero de test
/// estándar de la industria antivirus). Se usa en el autotest para verificar
/// que el motor detecta correctamente.
pub const EICAR_TEST_STRING: &[u8] =
    br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_hash_is_the_known_value() {
        // SHA-256 público del fichero de prueba EICAR estándar.
        assert_eq!(
            hash::sha256_hex(EICAR_TEST_STRING),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }
}
