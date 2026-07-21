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
  settings: "Ajustes",
};

let statusCache = null;

// ---------- API ----------
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok && res.status !== 200) throw new Error("HTTP " + res.status);
  return res.json();
}
const getStatus = () => api("/api/status");
const getQuarantine = () => api("/api/quarantine");
const postScan = (path, quarantine) =>
  api("/api/scan", { method: "POST", body: JSON.stringify({ path, quarantine }) });
const postSelftest = () => api("/api/selftest", { method: "POST", body: "{}" });
const postQAction = (id, action) =>
  api("/api/quarantine/action", { method: "POST", body: JSON.stringify({ id, action }) });

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
            <div class="card-ico" style="background:rgba(23,185,120,.14);color:var(--ok)"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Z"/></svg></div>
            <div class="grow">
              <div class="card-title">Protección en tiempo real</div>
              <div class="card-sub" style="color:var(--ok);font-weight:600">Activa · motor híbrido</div>
            </div>
            <span class="pill pill-ok"><span class="dot"></span> ON</span>
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
}

function viewScanner() {
  content.innerHTML = `
    <div class="card">
      <div class="card-title">Escaneo de ruta</div>
      <p class="section-desc">Introduce una carpeta o fichero. El escaneo es recursivo e incremental (salta lo no modificado).</p>
      <div class="field">
        <input class="input" id="scan-path" placeholder="/ruta/a/escanear" value="" />
        <button class="btn btn-primary" id="btn-scan">Escaneo rápido</button>
        <button class="btn btn-ghost" id="btn-scan-q">Escanear + cuarentena</button>
      </div>
      <label class="check"><input type="checkbox" id="opt-q" /> Poner en cuarentena los archivos maliciosos automáticamente</label>
      <div class="progress" id="prog"><i></i></div>
      <div id="scan-result"></div>
    </div>`;
  $("#btn-scan").onclick = () => runScan(false);
  $("#btn-scan-q").onclick = () => runScan(true);
}

async function runScan(forceQ) {
  const path = $("#scan-path").value.trim();
  if (!path) { toast("Indica una ruta"); return; }
  const q = forceQ || $("#opt-q").checked;
  const prog = $("#prog");
  const out = $("#scan-result");
  prog.classList.add("on");
  out.innerHTML = "";
  try {
    const r = await postScan(path, q);
    if (!r.ok) { out.innerHTML = `<div class="empty">Error: ${esc(r.error)}</div>`; return; }
    const sm = r.summary;
    let html = `<div class="summary-row">
      <div class="stat"><div class="v">${sm.seen}</div><div class="k">Vistos</div></div>
      <div class="stat"><div class="v">${sm.scanned}</div><div class="k">Escaneados</div></div>
      <div class="stat"><div class="v">${sm.skipped}</div><div class="k">Saltados</div></div>
      <div class="stat bad"><div class="v">${sm.malicious}</div><div class="k">Maliciosos</div></div>
      <div class="stat warn"><div class="v">${sm.suspicious}</div><div class="k">Sospechosos</div></div>
    </div>`;
    if (r.hits.length === 0) {
      html += `<div class="empty"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Zm-1 15-4-4 1.4-1.4L11 13.2l4.6-4.6L17 10l-6 6Z"/></svg><div>Sin amenazas. Todo limpio.</div></div>`;
    } else {
      for (const h of r.hits) {
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
    }
    out.innerHTML = html;
    statusCache = null; // refrescar estado al volver al panel
    if (sm.malicious > 0) toast(`${sm.malicious} amenaza(s) detectada(s)`);
  } catch (e) {
    out.innerHTML = `<div class="empty">Error de conexión: ${esc(e.message)}</div>`;
  } finally {
    prog.classList.remove("on");
  }
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
          <div class="grow"><div class="card-title" style="font-size:15px">Escaneo rápido del sistema</div><div class="card-sub">Zonas de alto riesgo (temporal del usuario).</div></div>
          <button class="btn btn-ghost btn-sm" data-goto="scanner">Ir al escáner</button>
        </div>
      </div>
    </div>`;
}

async function viewDetections() {
  const r = await getQuarantine();
  const items = r.items;
  content.innerHTML = `
    <div class="card">
      <div class="list-title">Detecciones recientes</div>
      <p class="section-desc">Amenazas neutralizadas y puestas en cuarentena.</p>
      ${items.length ? items.map((e) => `
        <div class="qitem">
          <span class="tag tag-mal">NEUTRALIZADA</span>
          <div class="grow"><div class="result-path">${esc(e.threat || "Amenaza")}</div><div class="result-meta">${esc(e.path)}</div></div>
        </div>`).join("") :
        `<div class="empty"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1 3 5v6c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V5l-9-4Zm-1 15-4-4 1.4-1.4L11 13.2l4.6-4.6L17 10l-6 6Z"/></svg><div>Sin detecciones. Tu equipo está limpio.</div></div>`}
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

const VIEWS = {
  dashboard: viewDashboard,
  scanner: viewScanner,
  detections: viewDetections,
  quarantine: viewQuarantine,
  tools: viewTools,
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
  navigate("dashboard");
})();
