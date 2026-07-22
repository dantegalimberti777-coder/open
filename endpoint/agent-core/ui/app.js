// ===== NGAV UI — lógica de la SPA (sin frameworks) =====
"use strict";

const $ = (sel) => document.querySelector(sel);
const content = $("#content");
const pageTitle = $("#page-title");

const TITLES = {
  dashboard: "Panel",
  scanner: "Escáner",
  detections: "Detecciones",
  quarantine: "Cuarentena",
  tools: "Herramientas",
  optimize: "Optimizar",
  subscription: "Suscripción",
  settings: "Ajustes",
};

function fmtBytes(n) {
  if (!n) return "0 MB";
  const mb = n / (1024 * 1024);
  if (mb >= 1024) return (mb / 1024).toFixed(2) + " GB";
  return mb.toFixed(1) + " MB";
}

let statusCache = null;

// ---------- API ----------
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok && res.status !== 200) throw new Error("HTTP " + res.status);
  return res.json();
}
const getStatus = () => api("/api/status");
const getQuarantine = () => api("/api/quarantine");
const startScan = (mode, path, quarantine) =>
  api("/api/scan/start", { method: "POST", body: JSON.stringify({ mode, path, quarantine }) });
const getProgress = (id) => api("/api/scan/progress?id=" + encodeURIComponent(id));
const postSelftest = () => api("/api/selftest", { method: "POST", body: "{}" });
const postUpdate = () => api("/api/update", { method: "POST", body: "{}" });
const postOptimize = () => api("/api/optimize", { method: "POST", body: "{}" });
const getRealtime = () => api("/api/realtime");
const getRealtimeEvents = () => api("/api/realtime/events");
const startRealtime = () => api("/api/realtime/start", { method: "POST", body: "{}" });
const stopRealtime = () => api("/api/realtime/stop", { method: "POST", body: "{}" });
const getLicense = () => api("/api/license");
const postCheckout = (email) => api("/api/checkout", { method: "POST", body: JSON.stringify({ email }) });
const postActivate = (key) => api("/api/license/activate", { method: "POST", body: JSON.stringify({ key }) });
const postQAction = (id, action) =>
  api("/api/quarantine/action", { method: "POST", body: JSON.stringify({ id, action }) });

let licenseCache = null;

// ---------- Utilidades ----------
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2600);
}
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}
function scoreColor(n) {
  if (n >= 80) return "var(--ok)";
  if (n >= 55) return "var(--warn)";
  return "var(--danger)";
}
function scoreLabel(n) {
  if (n >= 80) return "Bueno";
  if (n >= 55) return "Aceptable";
  return "En riesgo";
}

// ---------- Vistas ----------
async function viewDashboard() {
  const s = statusCache || (await getStatus());
  statusCache = s;
  const circ = 2 * Math.PI * 84;
  const off = circ * (1 - s.score / 100);
  content.innerHTML = `
    <div class="grid">
      <div class="stack">
        <div class="card">
          <div class="card-row">
            <div class="card-ico">
              <svg viewBox="0 0 24 24"><path fill="currentColor" d="M15.5 14h-.8l-.3-.3a6.5 6.5 0 1 0-.7.7l.3.3v.8l5 5 1.5-1.5-5-5Zm-6 0A4.5 4.5 0 1 1 14 9.5 4.5 4.5 0 0 1 9.5 14Z"/></svg>
            </div>
            <div class="grow">
              <div class="card-title">Escáner</div>
              <div class="card-sub">Firmas cargadas: ${s.signatures} · ${s.scanned_before ? "Último escaneo registrado" : "Sin escaneos previos"}</div>
            </div>
            <button class="btn btn-primary" data-goto="scanner">Escanear</button>
          </div>
        </div>

        <div class="card">
          <div class="card-row">
            <div class="card-ico"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M13 3a9 9 0 0 0-9 9H1l4 4 4-4H6a7 7 0 1 1 2 4.9l-1.5 1.5A9 9 0 1 0 13 3Zm-1 5v5l4 2 .8-1.3-3.3-2V8Z"/></svg></div>
            <div class="grow">
              <div class="card-title">Historial de detecciones</div>
              <div class="card-sub">Elementos en cuarentena: ${s.quarantine}</div>
            </div>
            <button class="btn btn-ghost" data-goto="quarantine">Ver</button>
          </div>
        </div>

        <div class="card">
          <div class="card-row">
            <div class="card-ico" style="background:${s.realtime ? "rgba(23,185,120,.14)" : "rgba(245,166,35,.16)"};color:${s.realtime ? "var(--ok)" : "var(--warn)"}"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Z"/></svg></div>
            <div class="grow">
              <div class="card-title">Protección en tiempo real</div>
              <div class="card-sub" id="rt-sub" style="color:${s.realtime ? "var(--ok)" : "var(--warn)"};font-weight:600">${s.realtime ? "Activa · vigilando el sistema" : "Desactivada"}</div>
            </div>
            <button class="toggle ${s.realtime ? "on" : ""}" id="rt-toggle" role="switch" aria-checked="${s.realtime}"><span class="knob"></span></button>
          </div>
        </div>

        <div class="card">
          <div class="card-row">
            <div class="card-ico" style="background:rgba(47,107,255,.12)"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 0 1 6 0v3Z"/></svg></div>
            <div class="grow">
              <div class="card-title">Reputación en la nube</div>
              <div class="card-sub">${s.cloud ? esc(s.cloud) : "Modo local (offline)"}</div>
            </div>
            <button class="btn btn-ghost" data-goto="settings">Configurar</button>
          </div>
        </div>
      </div>

      <div class="card score-card">
        <div class="score-title">Puntuación de protección</div>
        <div class="gauge">
          <svg width="200" height="200" viewBox="0 0 200 200">
            <circle class="gauge-track" cx="100" cy="100" r="84"></circle>
            <circle class="gauge-fill" cx="100" cy="100" r="84"
              style="stroke:${scoreColor(s.score)};stroke-dasharray:${circ};stroke-dashoffset:${circ}"
              data-off="${off}"></circle>
          </svg>
          <div class="gauge-num">
            <div class="n">${s.score}</div>
            <div class="lbl">${scoreLabel(s.score)}</div>
          </div>
        </div>
        <button class="btn btn-primary" data-action="selftest" style="width:100%;margin-top:10px">Probar motor (EICAR)</button>
        <p class="card-sub" style="margin-top:12px">Verifica que la detección funciona con el fichero de prueba estándar.</p>
      </div>
    </div>`;
  // anima el medidor
  requestAnimationFrame(() => {
    const f = content.querySelector(".gauge-fill");
    if (f) f.style.strokeDashoffset = f.dataset.off;
  });

  // toggle de protección en tiempo real
  const rt = $("#rt-toggle");
  if (rt) {
    rt.onclick = async () => {
      const turningOn = !rt.classList.contains("on");
      rt.disabled = true;
      try {
        const r = turningOn ? await startRealtime() : await stopRealtime();
        if (r.ok === false && r.error === "license_required") {
          toast("Suscríbete para activar la protección en tiempo real");
          navigate("subscription");
          return;
        }
        const on = r.running;
        rt.classList.toggle("on", on);
        rt.setAttribute("aria-checked", on);
        const sub = $("#rt-sub");
        if (sub) {
          sub.textContent = on ? "Activa · vigilando el sistema" : "Desactivada";
          sub.style.color = on ? "var(--ok)" : "var(--warn)";
        }
        statusCache = null;
        toast(on ? "Protección en tiempo real activada" : "Protección en tiempo real desactivada");
      } catch (e) { toast("Error: " + e.message); }
      finally { rt.disabled = false; }
    };
  }
}

let scanning = false;

function viewScanner() {
  content.innerHTML = `
    <div class="grid">
      <div class="stack">
        <div class="card scan-choice" id="card-quick">
          <div class="card-row">
            <div class="card-ico"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M13 2 3 14h7l-1 8 11-14h-7l1-6z"/></svg></div>
            <div class="grow">
              <div class="card-title">Escaneo rápido</div>
              <div class="card-sub">Zonas de alto riesgo + procesos en ejecución. Rápido y ligero.</div>
            </div>
            <button class="btn btn-primary" id="btn-quick">Iniciar</button>
          </div>
        </div>
        <div class="card scan-choice" id="card-deep">
          <div class="card-row">
            <div class="card-ico" style="background:rgba(229,72,77,.12);color:var(--danger)"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm0 4a6 6 0 0 1 6 6h-2a4 4 0 0 0-4-4Zm0 12a6 6 0 0 1-6-6h2a4 4 0 0 0 4 4Z"/></svg></div>
            <div class="grow">
              <div class="card-title">Escaneo profundo</div>
              <div class="card-sub">Todo el sistema, CPU/procesos y disco. Análisis exhaustivo de virus, troyanos, rootkits y keyloggers.</div>
            </div>
            <button class="btn btn-ghost" id="btn-deep">Iniciar</button>
          </div>
        </div>
        <div class="card">
          <div class="card-title" style="font-size:15px">Escanear una ruta concreta</div>
          <div class="field">
            <input class="input" id="scan-path" placeholder="C:\\carpeta  o  /ruta/a/escanear" />
            <button class="btn btn-ghost" id="btn-path">Escanear ruta</button>
          </div>
        </div>
        <label class="check"><input type="checkbox" id="opt-q" checked /> Poner en cuarentena los archivos maliciosos automáticamente</label>
      </div>

      <div class="card score-card" id="scan-panel">
        <div class="score-title" id="scan-state">Listo para escanear</div>
        <div class="gauge">
          <svg width="200" height="200" viewBox="0 0 200 200">
            <circle class="gauge-track" cx="100" cy="100" r="84"></circle>
            <circle class="gauge-fill" id="scan-arc" cx="100" cy="100" r="84"
              style="stroke:var(--primary);stroke-dasharray:${2*Math.PI*84};stroke-dashoffset:${2*Math.PI*84}"></circle>
          </svg>
          <div class="gauge-num"><div class="n" id="scan-pct">0<span style="font-size:22px">%</span></div><div class="lbl" id="scan-mode">—</div></div>
        </div>
        <div class="progress on"><i id="scan-bar" style="width:0%"></i></div>
        <div class="scan-current" id="scan-current">—</div>
        <div class="summary-row" id="scan-counts" style="justify-content:center;margin-top:10px"></div>
      </div>
    </div>
    <div id="scan-result"></div>`;
  $("#btn-quick").onclick = () => runScan("quick");
  $("#btn-deep").onclick = () => runScan("deep");
  $("#btn-path").onclick = () => {
    const p = $("#scan-path").value.trim();
    if (!p) { toast("Indica una ruta"); return; }
    runScan("quick", p);
  };
}

async function runScan(mode, path) {
  if (scanning) { toast("Ya hay un escaneo en curso"); return; }
  const q = $("#opt-q") ? $("#opt-q").checked : true;
  const circ = 2 * Math.PI * 84;
  const setPct = (pct, arcColor) => {
    const bar = $("#scan-bar"), arc = $("#scan-arc"), num = $("#scan-pct");
    if (bar) bar.style.width = pct + "%";
    if (arc) { arc.style.strokeDashoffset = circ * (1 - pct / 100); if (arcColor) arc.style.stroke = arcColor; }
    if (num) num.innerHTML = pct + '<span style="font-size:22px">%</span>';
  };
  scanning = true;
  $("#scan-state").textContent = "Escaneando…";
  $("#scan-mode").textContent = mode === "deep" ? "profundo" : "rápido";
  $("#scan-result").innerHTML = "";
  setPct(0, "var(--primary)");

  try {
    const s = await startScan(mode, path || "", q);
    if (!s.ok) {
      scanning = false;
      $("#scan-state") && ($("#scan-state").textContent = "Listo para escanear");
      if (s.error === "license_required") {
        toast(s.message || "Tu prueba ha finalizado. Suscríbete para seguir.");
        navigate("subscription");
      } else {
        toast("Error: " + esc(s.error || ""));
      }
      return;
    }
    const id = s.job_id;

    // Poll de progreso
    await new Promise((resolve) => {
      const timer = setInterval(async () => {
        let p;
        try { p = await getProgress(id); } catch (_) { return; }
        if (!p.ok) return;
        setPct(p.percent, p.malicious > 0 ? "var(--danger)" : (p.suspicious > 0 ? "var(--warn)" : "var(--ok)"));
        $("#scan-current").textContent = p.current;
        $("#scan-counts").innerHTML =
          `<div class="stat"><div class="v">${p.done}/${p.total}</div><div class="k">Archivos</div></div>
           <div class="stat bad"><div class="v">${p.malicious}</div><div class="k">Maliciosos</div></div>
           <div class="stat warn"><div class="v">${p.suspicious}</div><div class="k">Sospechosos</div></div>`;
        if (p.finished) {
          clearInterval(timer);
          $("#scan-state").textContent = "Escaneo completado";
          $("#scan-current").textContent = `${p.scanned} archivos analizados`;
          renderScanResults(p);
          if (p.malicious > 0) toast(`${p.malicious} amenaza(s) detectada(s)`);
          statusCache = null;
          resolve();
        }
      }, 350);
    });
  } catch (e) {
    toast("Error: " + esc(e.message));
  } finally {
    scanning = false;
  }
}

function renderScanResults(p) {
  const out = $("#scan-result");
  if (!p.hits.length) {
    out.innerHTML = `<div class="card"><div class="empty"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Zm-1 15-4-4 1.4-1.4L11 13.2l4.6-4.6L17 10l-6 6Z"/></svg><div>Sin amenazas. Tu equipo está limpio.</div></div></div>`;
    return;
  }
  let html = `<div class="card"><div class="list-title">Amenazas detectadas (${p.hits.length})</div>`;
  for (const h of p.hits) {
    const isMal = h.verdict === "MALICIOSO";
    html += `<div class="result">
      <div class="result-head">
        <span class="tag ${isMal ? "tag-mal" : "tag-sus"}">${esc(h.verdict)}</span>
        <span class="result-path">${esc(h.path)}</span>
      </div>
      <div class="result-meta">score ${h.score.toFixed(2)}${h.threat ? " · amenaza: " + esc(h.threat) : ""}${h.quarantined ? " · en cuarentena ✓" : ""}</div>
      ${h.reasons.length ? `<ul class="reasons">${h.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    </div>`;
  }
  out.innerHTML = html + "</div>";
}

async function viewQuarantine() {
  const r = await getQuarantine();
  let body;
  if (!r.items.length) {
    body = `<div class="empty"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Z"/></svg><div>Cuarentena vacía.</div></div>`;
  } else {
    body = r.items.map((e) => `
      <div class="qitem">
        <div class="card-ico" style="background:rgba(229,72,77,.14);color:var(--danger);width:40px;height:40px">
          <svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M12 2 1 21h22L12 2Zm1 14h-2v2h2v-2Zm0-6h-2v4h2v-4Z"/></svg>
        </div>
        <div class="grow">
          <div class="result-path">${esc(e.threat || "Amenaza")}</div>
          <div class="result-meta">${esc(e.path)}</div>
        </div>
        <button class="btn btn-ghost btn-sm" data-q="restore" data-id="${esc(e.id)}">Restaurar</button>
        <button class="btn btn-ghost btn-sm" data-q="delete" data-id="${esc(e.id)}" style="color:var(--danger)">Eliminar</button>
      </div>`).join("");
  }
  content.innerHTML = `<div class="card"><div class="list-title">Elementos en cuarentena (${r.items.length})</div>${body}</div>`;
}

function viewTools() {
  content.innerHTML = `
    <div class="card">
      <div class="card-title">Herramientas</div>
      <p class="section-desc">Utilidades del motor de detección.</p>
      <div class="stack">
        <div class="card-row" style="border:1px solid var(--border);border-radius:10px;padding:14px">
          <div class="grow"><div class="card-title" style="font-size:15px">Autotest del motor</div><div class="card-sub">Escanea el fichero de prueba estándar EICAR y verifica la detección.</div></div>
          <button class="btn btn-primary btn-sm" data-action="selftest">Ejecutar</button>
        </div>
        <div class="card-row" style="border:1px solid var(--border);border-radius:10px;padding:14px">
          <div class="grow"><div class="card-title" style="font-size:15px">Buscar actualizaciones</div><div class="card-sub" id="upd-sub">Descarga las firmas más recientes desde la nube.</div></div>
          <button class="btn btn-primary btn-sm" data-action="update">Actualizar</button>
        </div>
        <div class="card-row" style="border:1px solid var(--border);border-radius:10px;padding:14px">
          <div class="grow"><div class="card-title" style="font-size:15px">Escaneo profundo del sistema</div><div class="card-sub">Todo el disco + CPU/procesos.</div></div>
          <button class="btn btn-ghost btn-sm" data-goto="scanner">Ir al escáner</button>
        </div>
      </div>
    </div>`;
}

async function viewDetections() {
  const [q, rt] = await Promise.all([getQuarantine(), getRealtimeEvents().catch(() => ({ events: [] }))]);
  const events = (rt.events || []);

  const timeline = events.length ? events.map((e) => {
    const isMal = e.verdict === "MALICIOSO";
    const when = e.timestamp ? new Date(e.timestamp * 1000).toLocaleString() : "";
    return `<div class="qitem">
      <span class="tag ${isMal ? "tag-mal" : "tag-sus"}">${esc(e.verdict)}</span>
      <div class="grow">
        <div class="result-path">${esc(e.threat || "Actividad sospechosa")}</div>
        <div class="result-meta">${esc(e.action)} · ${esc(e.path)}${e.quarantined ? " · en cuarentena ✓" : ""}</div>
      </div>
      <div class="result-meta" style="white-space:nowrap">${esc(when)}</div>
    </div>`;
  }).join("") :
    `<div class="empty"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M13 3a9 9 0 0 0-9 9H1l4 4 4-4H6a7 7 0 1 1 2 4.9l-1.5 1.5A9 9 0 1 0 13 3Zm-1 5v5l4 2 .8-1.3-3.3-2V8Z"/></svg><div>Sin actividad. La protección en tiempo real está vigilando.</div></div>`;

  const quarantined = q.items.length ? q.items.map((e) => `
    <div class="qitem">
      <span class="tag tag-mal">NEUTRALIZADA</span>
      <div class="grow"><div class="result-path">${esc(e.threat || "Amenaza")}</div><div class="result-meta">${esc(e.path)}</div></div>
    </div>`).join("") :
    `<div class="empty" style="padding:24px">Sin elementos en cuarentena.</div>`;

  content.innerHTML = `
    <div class="card">
      <div class="list-title">Línea temporal de amenazas (tiempo real)</div>
      <p class="section-desc">Actividad detectada automáticamente por la protección en tiempo real.</p>
      ${timeline}
    </div>
    <div class="card" style="margin-top:18px">
      <div class="list-title">Neutralizadas (cuarentena)</div>
      ${quarantined}
    </div>`;
}

async function viewSettings() {
  const s = statusCache || (await getStatus());
  content.innerHTML = `
    <div class="card" style="max-width:620px">
      <div class="card-title">Ajustes</div>
      <p class="section-desc">Configuración e información del agente.</p>
      <div class="kv"><span class="k">Versión del agente</span><span>${esc(s.version)}</span></div>
      <div class="kv"><span class="k">Firmas cargadas</span><span>${s.signatures}</span></div>
      <div class="kv"><span class="k">Protección en tiempo real</span><span style="color:var(--ok);font-weight:600">Activa</span></div>
      <div class="kv"><span class="k">Reputación en la nube</span><span>${s.cloud ? esc(s.cloud) : "Local (offline)"}</span></div>
      <div class="kv"><span class="k">Elementos en cuarentena</span><span>${s.quarantine}</span></div>
      <div class="kv"><span class="k">Tema</span><span><button class="btn btn-ghost btn-sm" id="set-theme">Cambiar claro/oscuro</button></span></div>
    </div>`;
  $("#set-theme").onclick = toggleTheme;
}

async function viewSubscription() {
  const l = await getLicense();
  licenseCache = l;
  const active = l.state === "active";
  const expired = l.state === "expired";
  const stateLabel = active ? "Suscripción activa" : (expired ? "Prueba finalizada" : `Prueba gratuita — ${l.days_left} día(s) restante(s)`);
  const stateColor = active ? "var(--ok)" : (expired ? "var(--danger)" : "var(--warn)");

  content.innerHTML = `
    <div class="grid">
      <div class="stack">
        <div class="card">
          <div class="card-row">
            <div class="card-ico" style="background:${expired ? "rgba(229,72,77,.12)" : "rgba(23,185,120,.14)"};color:${stateColor}">
              <svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Z"/></svg>
            </div>
            <div class="grow">
              <div class="card-title">${stateLabel}</div>
              <div class="card-sub">Plan ${esc(l.plan)} · ${l.trial_days} días de prueba, luego $${esc(l.price)}/${esc(l.period)}</div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="list-title">¿Ya tienes una clave de licencia?</div>
          <p class="section-desc">Introduce la clave que recibiste al suscribirte.</p>
          <div class="field">
            <input class="input" id="lic-key" placeholder="NGAV-XXXXXXXX" />
            <button class="btn btn-ghost" id="btn-activate">Activar</button>
          </div>
        </div>
      </div>

      <div class="card score-card price-card">
        <div class="price-tag">
          <span class="price-amount">$${esc(l.price)}</span>
          <span class="price-period">/${esc(l.period)}</span>
        </div>
        <div class="price-plan">${esc(l.plan)}</div>
        <ul class="price-feats">
          <li>Escaneo rápido y profundo del sistema</li>
          <li>Protección con motor híbrido (firmas + IA + reputación)</li>
          <li>Detección de virus, troyanos, ransomware y keyloggers</li>
          <li>Cuarentena y actualizaciones automáticas</li>
        </ul>
        <button class="btn btn-primary" id="btn-subscribe" style="width:100%">
          ${active ? "Gestionar suscripción" : `Suscribirse — $${esc(l.price)}/${esc(l.period)}`}
        </button>
        <p class="card-sub" style="margin-top:10px">${l.trial_days} días gratis. Cancela cuando quieras.</p>
      </div>
    </div>`;

  $("#btn-activate").onclick = doActivate;
  $("#btn-subscribe").onclick = doCheckout;
}

async function doCheckout() {
  const btn = $("#btn-subscribe");
  btn.disabled = true;
  try {
    const r = await postCheckout(""); // email opcional
    if (!r.ok) { toast(r.error || "No se pudo iniciar el pago"); btn.disabled = false; return; }
    // Modo Stripe: abre la URL de pago. Modo demo: ofrece activar la clave.
    if (r.demo_key) {
      const use = confirm(`Modo demo (sin pago real).\nClave emitida: ${r.demo_key}\n\n¿Activar ahora?`);
      if (use) {
        $("#lic-key") && ($("#lic-key").value = r.demo_key);
        await activateKey(r.demo_key);
      }
    } else if (r.url) {
      window.open(r.url, "_blank");
      toast("Se abrió la página de pago en una pestaña nueva");
    }
  } catch (e) { toast("Error: " + e.message); }
  finally { btn.disabled = false; }
}

async function doActivate() {
  const key = ($("#lic-key") && $("#lic-key").value.trim()) || "";
  if (!key) { toast("Introduce una clave"); return; }
  await activateKey(key);
}

async function activateKey(key) {
  try {
    const r = await postActivate(key);
    if (r.ok && r.state === "active") {
      toast("¡Suscripción activada! Gracias.");
      statusCache = null; licenseCache = null;
      await refreshLicenseBadge();
      navigate("subscription");
    } else {
      toast(r.error || "No se pudo activar");
    }
  } catch (e) { toast("Error: " + e.message); }
}

function viewOptimize() {
  content.innerHTML = `
    <div class="grid">
      <div class="stack">
        <div class="card">
          <div class="card-title">Optimizar el equipo</div>
          <p class="section-desc">Limpia archivos temporales que ya no se usan y libera memoria para que tu PC vaya más rápido.</p>
          <div class="card-row" style="border:1px solid var(--border);border-radius:10px;padding:14px;margin-top:6px">
            <div class="card-ico"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M6 2h12v2H6zM4 6h16l-1.5 14a2 2 0 0 1-2 1.8H7.5a2 2 0 0 1-2-1.8L4 6zm5 3v9h2V9H9zm4 0v9h2V9h-2z"/></svg></div>
            <div class="grow"><div class="card-title" style="font-size:15px">Archivos temporales</div><div class="card-sub">Carpetas temporales del sistema y del usuario (deja los que están en uso).</div></div>
          </div>
          <div class="card-row" style="border:1px solid var(--border);border-radius:10px;padding:14px;margin-top:10px">
            <div class="card-ico" style="background:rgba(23,185,120,.14);color:var(--ok)"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M4 4h16v6H4zM4 14h16v6H4zM7 6v2h2V6zm0 10v2h2v-2z"/></svg></div>
            <div class="grow"><div class="card-title" style="font-size:15px">Memoria RAM</div><div class="card-sub">Libera la memoria de trabajo y muestra la RAM disponible.</div></div>
          </div>
        </div>
        <div id="opt-result"></div>
      </div>

      <div class="card score-card">
        <div class="score-title">Optimización con un clic</div>
        <div style="font-size:56px;margin:14px 0" aria-hidden="true">🧹</div>
        <button class="btn btn-primary" id="btn-optimize" style="width:100%;font-size:16px;padding:14px">Optimizar ahora</button>
        <p class="card-sub" style="margin-top:12px">Seguro: no toca tus documentos, solo archivos temporales y caché.</p>
      </div>
    </div>`;
  $("#btn-optimize").onclick = doOptimize;
}

async function doOptimize() {
  const btn = $("#btn-optimize");
  const out = $("#opt-result");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "Optimizando…";
  out.innerHTML = "";
  try {
    const r = await postOptimize();
    if (!r.ok) { toast("No se pudo optimizar"); return; }
    const ramLine = r.ram_total > 0
      ? `<div class="stat"><div class="v">${fmtBytes(r.ram_avail_after)}</div><div class="k">RAM disponible</div></div>
         <div class="stat"><div class="v">${fmtBytes(r.ram_total)}</div><div class="k">RAM total</div></div>`
      : "";
    out.innerHTML = `<div class="card">
      <div class="list-title">✅ Optimización completada</div>
      <div class="summary-row" style="margin-top:8px">
        <div class="stat"><div class="v">${r.files_deleted}</div><div class="k">Archivos limpiados</div></div>
        <div class="stat" style="border-color:var(--ok)"><div class="v" style="color:var(--ok)">${fmtBytes(r.bytes_freed)}</div><div class="k">Espacio liberado</div></div>
        ${ramLine}
      </div>
      ${r.errors > 0 ? `<p class="card-sub" style="margin-top:10px">${r.errors} archivo(s) en uso no se pudieron borrar (es normal).</p>` : ""}
    </div>`;
    toast(`Liberado: ${fmtBytes(r.bytes_freed)} en ${r.files_deleted} archivos`);
    statusCache = null;
  } catch (e) {
    toast("Error: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

const VIEWS = {
  dashboard: viewDashboard,
  scanner: viewScanner,
  detections: viewDetections,
  quarantine: viewQuarantine,
  tools: viewTools,
  optimize: viewOptimize,
  subscription: viewSubscription,
  settings: viewSettings,
};

async function navigate(view) {
  pageTitle.textContent = TITLES[view] || "NGAV";
  document.querySelectorAll(".nav-item").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === view)
  );
  content.innerHTML = `<div class="empty">Cargando…</div>`;
  try {
    await VIEWS[view]();
  } catch (e) {
    content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

// ---------- Acciones globales (delegación de eventos) ----------
document.addEventListener("click", async (ev) => {
  const goto = ev.target.closest("[data-goto]");
  if (goto) { navigate(goto.dataset.goto); return; }

  const nav = ev.target.closest(".nav-item");
  if (nav) { navigate(nav.dataset.view); return; }

  const action = ev.target.closest("[data-action]");
  if (action && action.dataset.action === "selftest") {
    action.disabled = true;
    try {
      const r = await postSelftest();
      toast(r.ok ? `Motor OK — detectado: ${r.threat}` : `Fallo: ${r.error || r.verdict}`);
    } catch (e) { toast("Error: " + e.message); }
    finally { action.disabled = false; }
    return;
  }
  if (action && action.dataset.action === "update") {
    action.disabled = true;
    const sub = $("#upd-sub");
    if (sub) sub.textContent = "Actualizando…";
    try {
      const r = await postUpdate();
      if (r.ok) {
        toast(`Actualizado: ${r.rules_loaded} reglas (${r.signatures} firmas)`);
        if (sub) sub.textContent = `Última actualización: ahora · ${r.signatures} firmas`;
      } else {
        toast("Sin actualización: " + (r.error || ""));
        if (sub) sub.textContent = r.error || "No se pudo actualizar";
      }
      statusCache = null;
    } catch (e) { toast("Error: " + e.message); }
    finally { action.disabled = false; }
    return;
  }

  const q = ev.target.closest("[data-q]");
  if (q) {
    q.disabled = true;
    try {
      const r = await postQAction(q.dataset.id, q.dataset.q);
      toast(r.ok ? (q.dataset.q === "restore" ? "Restaurado" : "Eliminado") : "Error: " + r.error);
      statusCache = null;
      viewQuarantine();
    } catch (e) { toast("Error: " + e.message); }
    return;
  }
});

// ---------- Tema ----------
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("ngav-theme", t); } catch (_) {}
}
function toggleTheme() {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
}
$("#theme-toggle").onclick = toggleTheme;

// ---------- Banner de licencia (topbar) ----------
async function refreshLicenseBadge() {
  let l;
  try { l = await getLicense(); } catch (_) { return; }
  licenseCache = l;
  const badge = $("#lic-badge");
  const buy = $("#buy-btn");
  if (!badge || !buy) return;
  if (l.state === "active") {
    badge.style.display = "inline-flex";
    badge.className = "lic-badge lic-active";
    badge.innerHTML = "★ Premium";
    buy.style.display = "none";
  } else if (l.state === "expired") {
    badge.style.display = "inline-flex";
    badge.className = "lic-badge lic-expired";
    badge.innerHTML = "Prueba finalizada";
    buy.style.display = "inline-flex";
    buy.textContent = "Suscribirse";
  } else {
    badge.style.display = "inline-flex";
    badge.className = "lic-badge lic-trial";
    badge.innerHTML = `Prueba · ${l.days_left} día(s)`;
    buy.style.display = "inline-flex";
    buy.textContent = "Comprar ahora";
  }
}

// ---------- Init ----------
(async function init() {
  try {
    const saved = localStorage.getItem("ngav-theme");
    if (saved) applyTheme(saved);
  } catch (_) {}
  try {
    const s = await getStatus();
    statusCache = s;
    $("#foot-version").textContent = "v" + s.version;
    const pill = $("#status-pill");
    if (s.score < 55) { pill.className = "pill pill-warn"; pill.innerHTML = '<span class="dot"></span> Revisar'; }
  } catch (_) {}
  await refreshLicenseBadge();
  navigate("dashboard");
})();
