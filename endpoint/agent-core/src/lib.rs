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
pub mod realtime;
pub mod reputation;
pub mod scanjob;
pub mod scanner;
pub mod server;
pub mod signatures;
pub mod sysscan;
pub mod updater;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Devuelve la cadena de prueba estándar EICAR (no es malware: es el fichero de
/// test estándar de la industria antivirus). Se **ensambla en runtime** desde
/// fragmentos, con la parte central almacenada al revés, para que la cadena
/// EICAR completa **no aparezca literal dentro del binario**. Motivo: cualquier
/// antivirus (incl. Windows Defender) detecta como virus todo fichero que
/// contenga esa cadena; si estuviera en nuestro `.exe`, el propio ejecutable
/// sería marcado como EICAR. El autotest la usa para verificar el motor.
pub fn eicar_test_bytes() -> Vec<u8> {
    let prefix = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let suffix = "!$H+H*";
    // "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" almacenado invertido.
    let middle: String = "ELIF-TSET-SURIVITNA-DRADNATS-RACIE".chars().rev().collect();
    format!("{prefix}{middle}{suffix}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_hash_is_the_known_value() {
        // SHA-256 público del fichero de prueba EICAR estándar. Verifica que el
        // ensamblado en runtime produce exactamente la cadena EICAR.
        assert_eq!(
            hash::sha256_hex(&eicar_test_bytes()),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }
}
