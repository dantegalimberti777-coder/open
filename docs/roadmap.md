# Fases de Desarrollo y Roadmap a 5 Años

División en fases con **funcionalidades, complejidad, tiempo estimado y prioridades**. Los tiempos
asumen un equipo pequeño-mediano especializado (crece por fase) y son estimaciones de planificación,
no compromisos. La secuencia prioriza **entregar protección real cuanto antes** y construir la
plataforma de aprendizaje de forma incremental.

> Leyenda de complejidad: 🟢 baja · 🟡 media · 🟠 alta · 🔴 muy alta.

---

## Fase 1 — MVP (Producto Mínimo Viable)

**Objetivo:** protección básica real en Windows con un agente que ya detiene amenazas conocidas y
ransomware evidente, con arquitectura preparada para crecer.

| Funcionalidad | Complejidad | Prioridad |
|---------------|-------------|-----------|
| Servicio/daemon + driver minifilter (Windows) | 🟠 | P0 |
| Escaneo on-access y bajo demanda (rápido/completo) | 🟡 | P0 |
| Motor de firmas (hash + YARA) + heurística básica | 🟡 | P0 |
| Detección por comportamiento básica + anti-ransomware (canary + suspensión) | 🟠 | P0 |
| Cuarentena cifrada e historial | 🟢 | P0 |
| Consulta de reputación en la nube (MVP) + caché local | 🟡 | P1 |
| UI de escritorio (estado, escaneos, cuarentena, config básica, modo oscuro) | 🟡 | P0 |
| Actualizaciones firmadas de firmas (TUF básico) | 🟠 | P0 |
| Licenciamiento básico (activación + token firmado) | 🟢 | P1 |
| Telemetría mínima con consentimiento | 🟢 | P1 |
| Autoprotección básica (watchdog, protección de servicio/ficheros) | 🟠 | P0 |

**Tiempo estimado:** ~4–6 meses. **Prioridad global:** validar detección, rendimiento y estabilidad
en Windows. Un modelo ML estático inicial (entrenado offline) puede incluirse como *early*.

---

## Fase 2 — Beta

**Objetivo:** endurecer detección con ML, cerrar el bucle de aprendizaje en la nube y ampliar
robustez con usuarios reales.

| Funcionalidad | Complejidad | Prioridad |
|---------------|-------------|-----------|
| ML estático en endpoint (ONNX) con pipeline de entrenamiento en nube | 🟠 | P0 |
| Sandbox en la nube para muestras sospechosas | 🟠 | P0 |
| Pipeline MLOps: ingesta → sandbox → etiquetado → entrenamiento → registro | 🔴 | P0 |
| Despliegue canario + shadow mode + rollback de modelos | 🟠 | P0 |
| Defensas anti-poisoning y validación (gates de promoción) | 🔴 | P0 |
| Detección de anomalías (línea base por host) | 🟠 | P1 |
| Threat intelligence externa (STIX/TAXII) integrada | 🟡 | P1 |
| Rollback transaccional anti-ransomware (revertir cambios) | 🟠 | P0 |
| Endurecimiento de autoprotección (PPL/ELAM) | 🟠 | P1 |
| Telemetría a escala (Kafka) + observabilidad | 🟠 | P1 |
| Programa de beta testers + bug bounty | 🟡 | P1 |

**Tiempo estimado:** ~4–6 meses tras el MVP. **Prioridad global:** calidad de detección (recall) con
FP bajos y aprendizaje continuo seguro funcionando de punta a punta.

---

## Fase 3 — Versión 1.0 (GA)

**Objetivo:** producto comercial pulido, multiplataforma y listo para consumidores/PYMEs.

| Funcionalidad | Complejidad | Prioridad |
|---------------|-------------|-----------|
| Soporte macOS y Linux (paridad de features clave) | 🟠 | P0 |
| Protección web/anti-phishing y control de USB | 🟡 | P1 |
| Estadísticas, informes y UX pulida | 🟢 | P1 |
| Sistema de licencias/billing completo (planes, renovaciones) | 🟡 | P0 |
| Optimización de rendimiento a SLOs (CPU/RAM/batería) | 🟠 | P0 |
| Endurecimiento de seguridad del producto (pentest, fuzzing continuo) | 🟠 | P0 |
| Actualizaciones de motor/cliente con instalación segura | 🟡 | P1 |
| Certificaciones iniciales (pruebas de laboratorios AV independientes) | 🟡 | P1 |
| Estabilidad, soporte y documentación de producto | 🟢 | P0 |

**Tiempo estimado:** ~4–6 meses tras la Beta. **Prioridad global:** estabilidad, rendimiento,
multiplataforma y reconocimiento por laboratorios independientes (AV-TEST/AV-Comparatives).

---

## Fase 4 — Versión Empresarial (EDR/XDR)

**Objetivo:** plataforma empresarial gestionada centralmente, con capacidades EDR y cumplimiento.

| Funcionalidad | Complejidad | Prioridad |
|---------------|-------------|-----------|
| Panel de administración multi-tenant (RBAC, SSO, MFA) | 🟠 | P0 |
| Gestión de políticas por grupos e inventario a escala | 🟠 | P0 |
| Capacidades EDR: línea de tiempo (MITRE ATT&CK), threat hunting, respuesta remota (aislar/kill) | 🔴 | P0 |
| Integraciones SIEM/SOAR, webhooks, API pública | 🟠 | P1 |
| Informes de cumplimiento (ISO 27001, SOC 2, GDPR, HIPAA) | 🟡 | P1 |
| Despliegue air-gapped / servidor on-premise de licencias y updates | 🟠 | P2 |
| Multi-región, residencia de datos, HA/DR | 🟠 | P1 |
| IA avanzada para triage (GNN/Transformers, asistente SOC) | 🔴 | P1 |
| Escalado a millones de endpoints (validado en carga) | 🔴 | P0 |

**Tiempo estimado:** ~6–9 meses tras 1.0 (parcialmente en paralelo). **Prioridad global:** gestión
central, EDR, escala y cumplimiento — el segmento de mayor valor comercial.

---

## Roadmap a 5 años (visión)

| Año | Focos estratégicos |
|-----|--------------------|
| **Año 1** | MVP → Beta → 1.0 en Windows/macOS/Linux. Motor híbrido + aprendizaje continuo seguro. Reconocimiento por laboratorios AV independientes. |
| **Año 2** | Versión empresarial (EDR), panel multi-tenant, integraciones SIEM/SOAR, certificaciones (SOC 2, ISO 27001). Escala a millones de endpoints. |
| **Año 3** | **XDR**: correlación cross-source (endpoint + red + identidad + cloud + email). IA de detección de campañas (grafos). Respuesta automatizada (SOAR nativo). Cobertura móvil (Android/iOS) y servidores/cloud workloads. |
| **Año 4** | **MDR** (servicio gestionado 24/7) y *managed hunting*. Protección de cargas cloud/contenedores/Kubernetes (CWPP). Modelos de IA on-device más potentes (aceleración NPU). Marketplace de integraciones. |
| **Año 5** | Plataforma de seguridad autónoma: detección y respuesta *self-healing*, *deception* a escala, threat intel propia líder, y expansión a IoT/OT. Investigación en defensa frente a malware asistido por IA. |

### Temas transversales durante los 5 años

- **Aprendizaje continuo seguro** como ventaja competitiva: mejora con cada endpoint, resistente a
  envenenamiento y evasión adversarial.
- **Privacidad y ética por diseño**: minimización, consentimiento, cumplimiento global.
- **Rendimiento**: mantener el liderazgo en bajo impacto medido por laboratorios independientes.
- **Confianza**: transparencia, auditorías, certificaciones y buen historial de FP bajos.
- **Anticipación**: prepararse para amenazas emergentes (malware generado por IA, ataques a la cadena
  de suministro, ransomware-as-a-service).

---

## Riesgos y mitigaciones (resumen)

| Riesgo | Mitigación |
|--------|-----------|
| Falsos positivos dañan la confianza | Clean set masivo, canario, acciones reversibles, allowlisting |
| Envenenamiento del aprendizaje | Validación multi-etapa, sin entrenamiento local, límites de influencia |
| Evasión adversarial del ML | Defensa en profundidad, comportamiento runtime, entrenamiento adversarial |
| Impacto en rendimiento | SLOs medidos en CI, triage barato, cómputo pesado en la nube |
| El AV como vector de ataque | Rust, separación de privilegios, fuzzing, bug bounty, mínimo privilegio |
| Escala/costes en la nube | Local-first, caché de edge, muestreo, autoescalado |
| Cumplimiento/privacidad | Minimización de datos, DPA, multi-región, certificaciones |
