//! Análisis estático de ejecutables (PE / ELF / Mach-O).
//!
//! Extrae estructura del binario **sin ejecutarlo** y deriva indicadores
//! estructurales de sospecha (empaquetado/ofuscación, secciones RWX, ausencia de
//! imports, overlay, entropía). Alimenta el motor de decisión con una señal
//! adicional, cumpliendo el requisito de "ANÁLISIS ESTÁTICO".
//!
//! Diseño anti-falso-positivo: trabaja sobre **estructura** (entropía, flags de
//! sección, conteos), no sobre cadenas de IOC; no incrusta nombres de malware en
//! el binario.

use crate::entropy;
use goblin::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinFormat {
    Pe,
    Elf,
    MachO,
    Unknown,
}

impl BinFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            BinFormat::Pe => "PE (Windows)",
            BinFormat::Elf => "ELF (Linux)",
            BinFormat::MachO => "Mach-O (macOS)",
            BinFormat::Unknown => "desconocido",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub raw_size: u64,
    pub entropy: f64,
    pub rwx: bool,
}

#[derive(Debug, Clone)]
pub struct StaticReport {
    pub format: BinFormat,
    pub is_64: bool,
    pub entry: u64,
    pub timestamp: u32,
    pub sections: Vec<SectionInfo>,
    pub imports: usize,
    pub exports: usize,
    pub overlay_size: u64,
    pub overall_entropy: f64,
    pub indicators: Vec<String>,
    pub risk: f64,
}

/// ¿El contenido parece un ejecutable (por su magic)? Barato, para no invocar el
/// parser en ficheros que no lo son.
pub fn looks_executable(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    data.starts_with(b"MZ")                                   // PE
        || data.starts_with(&[0x7f, b'E', b'L', b'F'])       // ELF
        || matches!(
            &data[..4],
            [0xfe, 0xed, 0xfa, 0xce]       // Mach-O 32 BE
                | [0xce, 0xfa, 0xed, 0xfe] // Mach-O 32 LE
                | [0xfe, 0xed, 0xfa, 0xcf] // Mach-O 64 BE
                | [0xcf, 0xfa, 0xed, 0xfe] // Mach-O 64 LE
                | [0xca, 0xfe, 0xba, 0xbe] // Mach-O universal (fat)
        )
}

/// Analiza el binario. Devuelve `None` si no es un ejecutable reconocible.
pub fn analyze(data: &[u8]) -> Option<StaticReport> {
    if !looks_executable(data) {
        return None;
    }
    let obj = Object::parse(data).ok()?;
    let overall_entropy = entropy::shannon(data);

    let mut report = match obj {
        Object::PE(pe) => analyze_pe(&pe, data),
        Object::Elf(elf) => analyze_elf(&elf, data),
        Object::Mach(_) => StaticReport {
            format: BinFormat::MachO,
            is_64: true,
            entry: 0,
            timestamp: 0,
            sections: Vec::new(),
            imports: 0,
            exports: 0,
            overlay_size: 0,
            overall_entropy,
            indicators: Vec::new(),
            risk: 0.0,
        },
        _ => return None,
    };
    report.overall_entropy = overall_entropy;

    compute_indicators(&mut report);
    Some(report)
}

fn section_entropy(data: &[u8], offset: usize, size: usize) -> f64 {
    let end = offset.saturating_add(size);
    if offset >= data.len() || size == 0 || end > data.len() {
        return 0.0;
    }
    entropy::shannon(&data[offset..end])
}

fn analyze_pe(pe: &goblin::pe::PE, data: &[u8]) -> StaticReport {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    let mut sections = Vec::new();
    let mut max_raw_end: u64 = 0;
    for s in &pe.sections {
        let name = s.name().unwrap_or("?").trim_end_matches('\0').to_string();
        let raw_off = s.pointer_to_raw_data as usize;
        let raw_size = s.size_of_raw_data as usize;
        let ent = section_entropy(data, raw_off, raw_size);
        let rwx = (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (s.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        max_raw_end = max_raw_end.max((raw_off + raw_size) as u64);
        sections.push(SectionInfo {
            name,
            raw_size: raw_size as u64,
            entropy: ent,
            rwx,
        });
    }
    let overlay = (data.len() as u64).saturating_sub(max_raw_end);

    StaticReport {
        format: BinFormat::Pe,
        is_64: pe.is_64,
        entry: pe.entry as u64,
        timestamp: pe.header.coff_header.time_date_stamp,
        sections,
        imports: pe.imports.len(),
        exports: pe.exports.len(),
        overlay_size: overlay,
        overall_entropy: 0.0,
        indicators: Vec::new(),
        risk: 0.0,
    }
}

fn analyze_elf(elf: &goblin::elf::Elf, data: &[u8]) -> StaticReport {
    const SHF_EXECINSTR: u64 = 0x4;
    const SHF_WRITE: u64 = 0x1;

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("?")
            .to_string();
        let ent = section_entropy(data, sh.sh_offset as usize, sh.sh_size as usize);
        let rwx = (sh.sh_flags & SHF_EXECINSTR) != 0 && (sh.sh_flags & SHF_WRITE) != 0;
        sections.push(SectionInfo {
            name,
            raw_size: sh.sh_size,
            entropy: ent,
            rwx,
        });
    }

    StaticReport {
        format: BinFormat::Elf,
        is_64: elf.is_64,
        entry: elf.entry,
        timestamp: 0,
        sections,
        imports: elf.dynsyms.iter().filter(|s| s.is_import()).count(),
        exports: elf.dynsyms.iter().filter(|s| !s.is_import()).count(),
        overlay_size: 0,
        overall_entropy: 0.0,
        indicators: Vec::new(),
        risk: 0.0,
    }
}

/// Deriva indicadores estructurales y una puntuación de riesgo (noisy-OR).
fn compute_indicators(r: &mut StaticReport) {
    let mut weights: Vec<f64> = Vec::new();

    if r.sections.iter().any(|s| s.rwx) {
        r.indicators
            .push("sección con permisos de escritura+ejecución (RWX)".into());
        weights.push(0.4);
    }
    let packed_section = r
        .sections
        .iter()
        .any(|s| s.entropy > 7.2 && s.raw_size > 1024);
    if packed_section {
        r.indicators
            .push("sección de alta entropía (posible empaquetado)".into());
        weights.push(0.35);
    }
    if r.format == BinFormat::Pe && r.imports == 0 {
        r.indicators
            .push("ejecutable sin imports (posible packer/ofuscación)".into());
        weights.push(0.3);
    }
    if r.overall_entropy > 7.5 {
        r.indicators.push(format!(
            "entropía global muy alta ({:.2})",
            r.overall_entropy
        ));
        weights.push(0.3);
    }
    // Overlay grande (>25% del contenido de secciones).
    let sections_size: u64 = r.sections.iter().map(|s| s.raw_size).sum();
    if r.overlay_size > 0 && sections_size > 0 && r.overlay_size > sections_size / 4 {
        r.indicators
            .push(format!("overlay grande ({} bytes)", r.overlay_size));
        weights.push(0.15);
    }

    // Fusión noisy-OR (varios indicadores escalan; ninguno solo llega al máximo).
    let mut inv = 1.0f64;
    for w in weights {
        inv *= 1.0 - w;
    }
    r.risk = 1.0 - inv;
}

/// Informe legible para CLI/UI.
pub fn describe(r: &StaticReport) -> String {
    let mut out = format!(
        "Formato: {}  ({}-bit)\nEntropía global: {:.2}\nSecciones: {}  Imports: {}  Exports: {}\nOverlay: {} bytes\nRiesgo estructural: {:.2}",
        r.format.as_str(),
        if r.is_64 { 64 } else { 32 },
        r.overall_entropy,
        r.sections.len(),
        r.imports,
        r.exports,
        r.overlay_size,
        r.risk
    );
    if !r.indicators.is_empty() {
        out.push_str("\nIndicadores:");
        for i in &r.indicators {
            out.push_str(&format!("\n  • {i}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_not_executable() {
        assert!(!looks_executable(b"esto es un documento normal"));
        assert!(analyze(b"esto es un documento normal").is_none());
    }

    #[test]
    fn detects_elf_magic() {
        assert!(looks_executable(&[0x7f, b'E', b'L', b'F', 0, 0]));
    }

    #[test]
    fn detects_pe_magic() {
        assert!(looks_executable(b"MZ\x90\x00rest"));
    }

    #[test]
    fn parses_real_elf_binary() {
        // Usa el propio ejecutable de test (un ELF real en Linux) si está.
        if let Ok(data) = std::fs::read("/proc/self/exe") {
            let r = analyze(&data).expect("debería parsear el ELF propio");
            assert_eq!(r.format, BinFormat::Elf);
            assert!(!r.sections.is_empty());
            assert!(r.entry > 0);
        }
    }

    #[test]
    fn high_entropy_section_flags_packing() {
        // Reporte sintético para probar el cálculo de indicadores.
        let mut r = StaticReport {
            format: BinFormat::Pe,
            is_64: true,
            entry: 0x1000,
            timestamp: 0,
            sections: vec![SectionInfo {
                name: ".text".into(),
                raw_size: 4096,
                entropy: 7.9,
                rwx: true,
            }],
            imports: 0,
            exports: 0,
            overlay_size: 0,
            overall_entropy: 7.8,
            indicators: Vec::new(),
            risk: 0.0,
        };
        compute_indicators(&mut r);
        assert!(r.risk > 0.6, "múltiples indicadores deben elevar el riesgo");
        assert!(r.indicators.iter().any(|i| i.contains("RWX")));
        assert!(r.indicators.iter().any(|i| i.contains("empaquetado")));
    }
}
