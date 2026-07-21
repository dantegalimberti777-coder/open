//! Licenciamiento: prueba gratuita de 14 días y suscripción mensual (10 USD/mes).
//!
//! El agente registra el inicio de la prueba en un fichero local. Durante la
//! prueba y con una suscripción activa, todas las funciones están disponibles.
//! Al expirar la prueba sin suscripción, las funciones de escaneo se bloquean
//! hasta activar una licencia.
//!
//! La activación se valida (opcionalmente) contra el servicio de licencias en
//! la nube, que en producción integra el proveedor de pagos (Stripe).
//!
//! NOTA MVP: la validación local usa un token simple. En producción el
//! *entitlement* iría firmado (JWT/PASETO) y se verificaría con clave pública
//! embebida, con revocación remota (ver docs/arquitectura.md §9 y
//! docs/monetizacion.md).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const TRIAL_DAYS: i64 = 14;
pub const PRICE_USD: &str = "10";
pub const PLAN_NAME: &str = "NGAV Premium";
pub const BILLING_PERIOD: &str = "mes";
const SECS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Trial,
    Active,
    Expired,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Trial => "trial",
            State::Active => "active",
            State::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone)]
pub struct License {
    pub trial_start: u64,
    pub status: String,
    pub plan: String,
    pub license_key: String,
    pub active_until: u64,
}

impl License {
    /// Carga la licencia; si no existe, inicia la prueba (marca la fecha).
    pub fn load_or_init(path: &Path) -> License {
        if let Ok(text) = std::fs::read_to_string(path) {
            return License::parse(&text);
        }
        let lic = License {
            trial_start: now(),
            status: "trial".to_string(),
            plan: "free_trial".to_string(),
            license_key: String::new(),
            active_until: 0,
        };
        let _ = lic.save(path);
        lic
    }

    fn parse(text: &str) -> License {
        let mut lic = License {
            trial_start: now(),
            status: "trial".to_string(),
            plan: "free_trial".to_string(),
            license_key: String::new(),
            active_until: 0,
        };
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim();
                match k.trim() {
                    "trial_start" => lic.trial_start = v.parse().unwrap_or_else(|_| now()),
                    "status" => lic.status = v.to_string(),
                    "plan" => lic.plan = v.to_string(),
                    "license_key" => lic.license_key = v.to_string(),
                    "active_until" => lic.active_until = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        lic
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = format!(
            "trial_start={}\nstatus={}\nplan={}\nlicense_key={}\nactive_until={}\n",
            self.trial_start, self.status, self.plan, self.license_key, self.active_until
        );
        std::fs::write(path, text)
    }

    /// Estado efectivo en el instante `at`.
    pub fn state_at(&self, at: u64) -> State {
        if self.status == "active" && self.active_until > at {
            return State::Active;
        }
        if self.days_left_at(at) > 0 {
            State::Trial
        } else {
            State::Expired
        }
    }

    pub fn state(&self) -> State {
        self.state_at(now())
    }

    /// Días de prueba restantes (0 si expiró).
    pub fn days_left_at(&self, at: u64) -> i64 {
        let end = self.trial_start as i64 + TRIAL_DAYS * SECS_PER_DAY;
        let secs_left = end - at as i64;
        if secs_left <= 0 {
            0
        } else {
            (secs_left + SECS_PER_DAY - 1) / SECS_PER_DAY
        }
    }

    pub fn days_left(&self) -> i64 {
        self.days_left_at(now())
    }

    /// ¿Están habilitadas las funciones (prueba vigente o suscripción activa)?
    pub fn is_functional(&self) -> bool {
        !matches!(self.state(), State::Expired)
    }

    /// Activa una suscripción hasta `until` (unix). Persiste el cambio.
    pub fn activate(&mut self, key: &str, until: u64, path: &Path) -> std::io::Result<()> {
        self.status = "active".to_string();
        self.plan = PLAN_NAME.to_string();
        self.license_key = key.to_string();
        self.active_until = until;
        self.save(path)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- Comunicación con el servicio de licencias en la nube ---

/// Resultado de validar una clave: (válida, until_unix).
pub fn validate_key(license_url: &str, key: &str) -> Result<(bool, u64), String> {
    let (host, port) = parse_http_url(license_url).ok_or("URL de licencias inválida")?;
    let path = format!("/v1/license/validate?key={}", url_encode(key));
    let body = http_get(&host, port, &path).map_err(|e| e.to_string())?;
    let valid = body.contains("\"valid\":true");
    let until = extract_number(&body, "until").unwrap_or(0);
    Ok((valid, until))
}

/// Inicia el checkout de suscripción. Devuelve (url_de_pago, clave_demo_opcional).
pub fn start_checkout(license_url: &str, email: &str) -> Result<(String, String), String> {
    let (host, port) = parse_http_url(license_url).ok_or("URL de licencias inválida")?;
    let payload = format!("{{\"email\":\"{}\"}}", email.replace('"', ""));
    let body = http_post(&host, port, "/v1/checkout", &payload).map_err(|e| e.to_string())?;
    let url = extract_string(&body, "url").unwrap_or_default();
    let key = extract_string(&body, "key").unwrap_or_default();
    if url.is_empty() {
        return Err("respuesta de checkout sin URL".to_string());
    }
    Ok((url, key))
}

fn parse_http_url(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("http://")?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    match hostport.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((hostport.to_string(), 80)),
    }
}

fn http_get(host: &str, port: u16, path: &str) -> std::io::Result<String> {
    let mut stream = connect(host, port)?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ngav-license/0.1\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    read_body(stream)
}

fn http_post(host: &str, port: u16, path: &str, body: &str) -> std::io::Result<String> {
    let mut stream = connect(host, port)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    read_body(stream)
}

fn connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(format!("{host}:{port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(6)))?;
    stream.set_write_timeout(Some(Duration::from_secs(6)))?;
    Ok(stream)
}

fn read_body(mut stream: TcpStream) -> std::io::Result<String> {
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    Ok(raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn extract_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_number(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_trial_has_14_days() {
        let lic = License {
            trial_start: now(),
            status: "trial".into(),
            plan: "free_trial".into(),
            license_key: String::new(),
            active_until: 0,
        };
        assert_eq!(lic.days_left(), TRIAL_DAYS);
        assert_eq!(lic.state(), State::Trial);
        assert!(lic.is_functional());
    }

    #[test]
    fn expired_trial_is_blocked() {
        let past = now() - (TRIAL_DAYS as u64 + 1) * SECS_PER_DAY as u64;
        let lic = License {
            trial_start: past,
            status: "trial".into(),
            plan: "free_trial".into(),
            license_key: String::new(),
            active_until: 0,
        };
        assert_eq!(lic.days_left(), 0);
        assert_eq!(lic.state(), State::Expired);
        assert!(!lic.is_functional());
    }

    #[test]
    fn active_subscription_is_functional_even_after_trial() {
        let past = now() - 100 * SECS_PER_DAY as u64;
        let lic = License {
            trial_start: past,
            status: "active".into(),
            plan: PLAN_NAME.into(),
            license_key: "NGAV-XXXX".into(),
            active_until: now() + 30 * SECS_PER_DAY as u64,
        };
        assert_eq!(lic.state(), State::Active);
        assert!(lic.is_functional());
    }

    #[test]
    fn day_counts_down() {
        let mut lic = License {
            trial_start: now(),
            status: "trial".into(),
            plan: "free_trial".into(),
            license_key: String::new(),
            active_until: 0,
        };
        // Simula 5 días transcurridos.
        lic.trial_start = now() - 5 * SECS_PER_DAY as u64;
        assert_eq!(lic.days_left(), TRIAL_DAYS - 5);
    }

    #[test]
    fn json_extract() {
        assert_eq!(
            extract_string(r#"{"url":"http://x/y","key":"ABC"}"#, "url"),
            Some("http://x/y".to_string())
        );
        assert_eq!(
            extract_number(r#"{"valid":true,"until":1700000000}"#, "until"),
            Some(1_700_000_000)
        );
    }
}
