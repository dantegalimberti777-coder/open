//! Cálculo de entropía de Shannon.
//!
//! La entropía alta (cercana a 8 bits/byte) indica datos comprimidos o
//! cifrados, típico de ejecutables empaquetados/ofuscados o de payloads de
//! ransomware. Es una señal heurística barata (una sola pasada).

/// Entropía de Shannon en bits por byte, en el rango [0.0, 8.0].
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_same_byte_is_zero() {
        assert_eq!(shannon(&[0x41; 1024]), 0.0);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn uniform_bytes_is_max() {
        let data: Vec<u8> = (0..=255u16).map(|x| x as u8).collect();
        let e = shannon(&data);
        assert!((e - 8.0).abs() < 1e-9, "entropy {e} should be ~8.0");
    }

    #[test]
    fn text_is_moderate() {
        let e = shannon(b"the quick brown fox jumps over the lazy dog");
        assert!(e > 3.0 && e < 5.5, "english text entropy {e} out of range");
    }
}
