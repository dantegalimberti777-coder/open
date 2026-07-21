//! CLI del agente NGAV (MVP).
//!
//! Uso:
//!   ngav scan <ruta> [--quarantine] [--cloud <url>] [--aggressive]
//!   ngav quick <ruta>
//!   ngav selftest
//!   ngav quarantine list|restore <id>|delete <id>
//!   ngav status
//!   ngav version

use ngav_agent::config::Config;
use ngav_agent::decision::{Thresholds, Verdict};
use ngav_agent::engine::Engine;
use ngav_agent::quarantine::Quarantine;
use ngav_agent::reputation::{CloudReputationClient, LocalReputationCache, ReputationSource};
use ngav_agent::scanner::{scan_tree, ScanIndex};
use ngav_agent::signatures::SignatureDb;
use ngav_agent::{EICAR_TEST_STRING, VERSION};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return ExitCode::from(2);
    }

    let cmd = args[0].as_str();
    let rest = &args[1..];

    let result = match cmd {
        "scan" => cmd_scan(rest, false),
        "quick" => cmd_scan(rest, true),
        "serve" | "ui" => cmd_serve(rest),
        "selftest" => cmd_selftest(),
        "quarantine" => cmd_quarantine(rest),
        "status" => cmd_status(),
        "version" | "--version" | "-V" => {
            println!("ngav {VERSION}");
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(0)
        }
        other => {
            eprintln!("comando desconocido: {other}\n");
            print_usage();
            Ok(2)
        }
    };

    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    println!(
        r#"NGAV agent {VERSION} — motor de detección híbrido (MVP)

USO:
  ngav scan <ruta> [opciones]     Escanea un fichero o directorio (recursivo, incremental)
  ngav quick <ruta>               Escaneo rápido (equivalente a scan; alias)
  ngav selftest                   Verifica el motor con el fichero de prueba EICAR
  ngav quarantine list            Lista los elementos en cuarentena
  ngav quarantine restore <id>    Restaura un elemento
  ngav quarantine delete <id>     Elimina definitivamente un elemento
  ngav status                     Muestra el estado del agente
  ngav version                    Muestra la versión

  ngav serve [--port N] [--no-open]   Abre la INTERFAZ GRÁFICA en el navegador

OPCIONES (scan):
  --quarantine        Pone en cuarentena los ficheros MALICIOSOS detectados
  --cloud <url>       URL del servicio de reputación (http://host:port)
  --aggressive        Umbrales de detección agresivos (más detección, más FP)

Códigos de salida: 0 = limpio, 1 = error, 3 = amenazas encontradas.
"#
    );
}

/// Carga la base de firmas: siempre incluye la firma EICAR, y añade las reglas
/// del fichero de firmas si existe.
fn load_signatures(cfg: &Config) -> SignatureDb {
    let mut db = SignatureDb::new();
    // Firma EICAR embebida (siempre presente).
    db.add_hash(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File",
    );
    // Patrón EICAR también, por si el fichero está embebido en otro.
    let _ = db.load_from_str("pattern 4549434152 EICAR-Pattern"); // "EICAR"

    if let Ok(text) = std::fs::read_to_string(&cfg.signatures_path) {
        match db.load_from_str(&text) {
            Ok(n) => eprintln!(
                "[firmas] cargadas {n} reglas de {}",
                cfg.signatures_path.display()
            ),
            Err(e) => eprintln!("[firmas] aviso: {e}"),
        }
    }
    db
}

fn build_local_reputation() -> LocalReputationCache {
    let mut rep = LocalReputationCache::new();
    // El hash EICAR también se marca como malo en reputación (defensa en
    // profundidad: coincide con la firma).
    rep.add_bad("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    rep
}

fn cmd_scan(args: &[String], _quick: bool) -> Result<u8, String> {
    let mut target: Option<PathBuf> = None;
    let mut do_quarantine = false;
    let mut cloud_url: Option<String> = None;
    let mut thresholds = Thresholds::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quarantine" => do_quarantine = true,
            "--aggressive" => thresholds = Thresholds::aggressive(),
            "--cloud" => {
                i += 1;
                cloud_url = Some(args.get(i).ok_or("--cloud requiere una URL")?.clone());
            }
            other if other.starts_with("--") => {
                return Err(format!("opción desconocida: {other}"));
            }
            path => target = Some(PathBuf::from(path)),
        }
        i += 1;
    }

    let target = target.ok_or("falta la ruta a escanear")?;
    let cfg = {
        let mut c = Config::default_paths();
        c.thresholds = thresholds;
        c.cloud_url = cloud_url;
        c
    };
    cfg.ensure_dirs().map_err(|e| e.to_string())?;

    let db = load_signatures(&cfg);
    let local_rep = build_local_reputation();
    let cloud = cfg
        .cloud_url
        .as_deref()
        .and_then(CloudReputationClient::from_url);

    // Fuente de reputación efectiva: nube si está configurada, si no local.
    let rep: &dyn ReputationSource = match &cloud {
        Some(c) => c,
        None => &local_rep,
    };

    let engine = Engine::new(&db)
        .with_reputation(rep)
        .with_thresholds(cfg.thresholds)
        .with_max_file_size(cfg.max_file_size);

    println!("== NGAV scan: {} ==", target.display());
    let meta = std::fs::metadata(&target).map_err(|e| format!("{}: {e}", target.display()))?;

    let quarantine = Quarantine::new(&cfg.quarantine_dir);
    let mut found = 0usize;
    let mut quarantined = 0usize;

    let mut handle_hit = |v: &ngav_agent::engine::FileVerdict| {
        found += 1;
        let label = match v.verdict() {
            Verdict::Malicious => "MALICIOSO",
            Verdict::Suspicious => "SOSPECHOSO",
            Verdict::Clean => "LIMPIO",
        };
        println!(
            "[{label}] {}\n    sha256={}\n    score={:.2}{}",
            v.path.display(),
            v.sha256,
            v.decision.score,
            v.threat_name
                .as_ref()
                .map(|t| format!("  amenaza={t}"))
                .unwrap_or_default()
        );
        for r in &v.decision.reasons {
            println!("      - {r}");
        }
        if do_quarantine && v.verdict() == Verdict::Malicious {
            match quarantine.quarantine_file(&v.path, v.threat_name.as_deref().unwrap_or("Malware"))
            {
                Ok(id) => {
                    quarantined += 1;
                    println!("      -> puesto en cuarentena (id={id})");
                }
                Err(e) => eprintln!("      -> error al poner en cuarentena: {e}"),
            }
        }
    };

    if meta.is_dir() {
        let mut index = ScanIndex::load(&cfg.index_path);
        let stats =
            scan_tree(&engine, &target, &mut index, &mut handle_hit).map_err(|e| e.to_string())?;
        index.save(&cfg.index_path).map_err(|e| e.to_string())?;
        println!(
            "\n-- Resumen --\n  vistos: {}  escaneados: {}  saltados(incremental): {}\n  maliciosos: {}  sospechosos: {}  errores: {}",
            stats.files_seen,
            stats.files_scanned,
            stats.files_skipped,
            stats.malicious,
            stats.suspicious,
            stats.errors
        );
    } else {
        let v = engine.scan_path(&target).map_err(|e| e.to_string())?;
        if v.verdict() == Verdict::Clean {
            println!("[LIMPIO] {}\n    sha256={}", v.path.display(), v.sha256);
        } else {
            handle_hit(&v);
        }
    }

    if do_quarantine {
        println!("  puestos en cuarentena: {quarantined}");
    }

    Ok(if found > 0 { 3 } else { 0 })
}

fn cmd_serve(args: &[String]) -> Result<u8, String> {
    let mut port = 8777u16;
    let mut open = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or("--port requiere un número")?
                    .parse()
                    .map_err(|_| "puerto inválido")?;
            }
            "--no-open" => open = false,
            other => return Err(format!("opción desconocida: {other}")),
        }
        i += 1;
    }

    let cfg = Config::default_paths();
    let addr = format!("127.0.0.1:{port}");
    let url = format!("http://{addr}");
    println!("== NGAV — interfaz gráfica ==");
    println!("Abriendo {url}");
    if open {
        open_browser(&url);
    }
    ngav_agent::server::serve(cfg, &addr).map_err(|e| e.to_string())?;
    Ok(0)
}

/// Abre la URL en el navegador por defecto según el sistema operativo.
fn open_browser(url: &str) {
    let url = url.to_string();
    std::thread::spawn(move || {
        // Pequeña espera para que el servidor esté aceptando conexiones.
        std::thread::sleep(std::time::Duration::from_millis(400));
        let result = if cfg!(target_os = "windows") {
            std::process::Command::new("cmd")
                .args(["/C", "start", "", &url])
                .spawn()
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(&url).spawn()
        } else {
            std::process::Command::new("xdg-open").arg(&url).spawn()
        };
        if result.is_err() {
            eprintln!("(No se pudo abrir el navegador automáticamente; visita {url})");
        }
    });
}

fn cmd_selftest() -> Result<u8, String> {
    println!("== NGAV autotest (EICAR) ==");
    let dir = std::env::temp_dir().join("ngav-selftest");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let eicar_path = dir.join("eicar.com");
    std::fs::write(&eicar_path, EICAR_TEST_STRING).map_err(|e| e.to_string())?;

    let cfg = Config::default_paths();
    let db = load_signatures(&cfg);
    let rep = build_local_reputation();
    let engine = Engine::new(&db).with_reputation(&rep);

    let v = engine.scan_path(&eicar_path).map_err(|e| e.to_string())?;
    println!(
        "  fichero: {}\n  sha256: {}\n  veredicto: {}  amenaza: {}",
        v.path.display(),
        v.sha256,
        v.verdict(),
        v.threat_name.as_deref().unwrap_or("-")
    );

    std::fs::remove_file(&eicar_path).ok();

    if v.verdict() == Verdict::Malicious && v.threat_name.as_deref() == Some("EICAR-Test-File") {
        println!("  RESULTADO: OK — el motor detecta correctamente EICAR.");
        Ok(0)
    } else {
        println!("  RESULTADO: FALLO — EICAR no detectado como se esperaba.");
        Ok(1)
    }
}

fn cmd_quarantine(args: &[String]) -> Result<u8, String> {
    let cfg = Config::default_paths();
    cfg.ensure_dirs().map_err(|e| e.to_string())?;
    let q = Quarantine::new(&cfg.quarantine_dir);
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    match sub {
        "list" => {
            let items = q.list().map_err(|e| e.to_string())?;
            if items.is_empty() {
                println!("Cuarentena vacía.");
            } else {
                println!("Elementos en cuarentena ({}):", items.len());
                for e in items {
                    println!(
                        "  id={}  amenaza={}  origen={}",
                        e.id, e.threat, e.original_path
                    );
                }
            }
            Ok(0)
        }
        "restore" => {
            let id = args.get(1).ok_or("restore requiere un id")?;
            let p = q.restore(id).map_err(|e| e.to_string())?;
            println!("Restaurado a {}", p.display());
            Ok(0)
        }
        "delete" => {
            let id = args.get(1).ok_or("delete requiere un id")?;
            q.delete(id).map_err(|e| e.to_string())?;
            println!("Eliminado {id}");
            Ok(0)
        }
        other => Err(format!("subcomando de quarantine desconocido: {other}")),
    }
}

fn cmd_status() -> Result<u8, String> {
    let cfg = Config::default_paths();
    let db = load_signatures(&cfg);
    let q = Quarantine::new(&cfg.quarantine_dir);
    let qn = q.list().map(|v| v.len()).unwrap_or(0);
    println!("NGAV agent {VERSION}");
    println!("  protección: ACTIVA (motor híbrido)");
    println!("  firmas cargadas: {}", db.len());
    println!(
        "  reputación en nube: {}",
        cfg.cloud_url.as_deref().unwrap_or("(local)")
    );
    println!("  data dir: {}", cfg.data_dir.display());
    println!("  elementos en cuarentena: {qn}");
    println!("  índice de escaneo: {}", index_state(&cfg.index_path));
    Ok(0)
}

fn index_state(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) => format!("{} bytes", m.len()),
        Err(_) => "(sin escaneos previos)".to_string(),
    }
}
