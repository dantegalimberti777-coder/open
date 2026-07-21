# Interfaz — Cliente de Escritorio y Panel de Administración

Diseño de una interfaz **moderna, clara y con baja fricción**. Filosofía: "seguro por defecto,
tranquilo por diseño" — el usuario ve verde cuando está protegido y solo se le interrumpe cuando de
verdad importa.

---

## 1. Cliente de escritorio

**Stack:** Tauri (núcleo Rust + UI web con TypeScript/React o Svelte). Multiplataforma
(Windows/macOS/Linux). Diseño *responsive*, accesible (WCAG AA) y con **modo oscuro** nativo (sigue el
tema del SO, con override manual).

### 1.1 Pantallas y componentes

| Pantalla | Contenido | Notas de UX |
|----------|-----------|-------------|
| **Estado de protección** (home) | Indicador grande verde/ámbar/rojo, "Estás protegido", última actualización, resumen de amenazas bloqueadas | Un vistazo = tranquilidad; CTA contextual si algo requiere acción |
| **Escaneo rápido** | Botón prominente; escanea zonas de alto riesgo (memoria, autoruns, descargas) en segundos | Progreso claro, cancelable |
| **Escaneo completo** | Escaneo incremental de todo el disco en segundo plano | Estimación de tiempo, pausa/reanuda, "escanear cuando esté inactivo" |
| **Cuarentena** | Lista de elementos aislados: nombre, amenaza, fecha, acción | Restaurar / eliminar definitivamente / enviar para análisis (con doble confirmación) |
| **Historial** | Línea de tiempo de detecciones, escaneos y acciones | Filtros, búsqueda, exportar |
| **Actualizaciones** | Versión de firmas/modelos/motor, botón "buscar ahora", estado | Automático por defecto; transparencia del canal (canario/estable) |
| **Configuración avanzada** | Nivel de heurística, exclusiones, protección web, firewall, programación de escaneos, modo juego, telemetría/privacidad | Valores seguros por defecto; opciones avanzadas plegadas |
| **Estadísticas** | Amenazas bloqueadas, ficheros escaneados, impacto en rendimiento, tendencia | Gráficas claras, sin jerga |
| **Notificaciones** | Toasts no intrusivos; centro de notificaciones | Silenciables; solo urgentes interrumpen |

### 1.2 Principios de diseño

- **Progresiva:** lo simple visible, lo avanzado accesible pero oculto.
- **Explicable:** cada detección explica *por qué* (qué señal la disparó) para generar confianza.
- **No alarmista:** evitar el "miedo, incertidumbre y duda"; lenguaje claro y acciones concretas.
- **Accesibilidad:** contraste, navegación por teclado, lectores de pantalla, i18n desde el día 1.
- **Modo oscuro** y respeto de las preferencias del sistema (tema, movimiento reducido).

---

## 2. Panel de administración (consola empresarial)

**Stack:** SPA en TypeScript + React, backend multi-tenant. SSO (SAML/OIDC), RBAC.

### 2.1 Módulos

| Módulo | Función |
|--------|---------|
| **Dashboard** | Postura de seguridad de la organización: dispositivos protegidos, amenazas, incidentes abiertos, cumplimiento |
| **Dispositivos** | Inventario, estado de protección en tiempo real, versión, último visto; acciones remotas (escanear, aislar, actualizar) |
| **Incidentes (EDR)** | Alertas priorizadas, triage, línea de tiempo del ataque (mapeo MITRE ATT&CK), respuesta (kill/quarantine/aislar host) |
| **Políticas** | Reglas por grupo: calendarios, exclusiones, nivel de detección, protección web/USB, listas |
| **Cuarentena central** | Ver/gestionar cuarentena de toda la flota |
| **Informes** | Cumplimiento (ISO 27001, SOC 2, GDPR), KPIs, exportación programada |
| **Licencias** | Asientos, asignación por grupo, renovaciones |
| **Integraciones** | SIEM (syslog/CEF), webhooks, API keys, SSO |
| **Auditoría** | Log inmutable de acciones de administradores |

### 2.2 Consideraciones

- **Tiempo real** vía WebSocket/SSE para estado de dispositivos e incidentes.
- **Escala:** listados con paginación/virtualización para decenas de miles de dispositivos.
- **Seguridad del panel:** MFA obligatorio, RBAC granular, registro de auditoría, sesiones cortas.
- **Modo oscuro** también en la consola.

---

## 3. Notificaciones y comunicación con el usuario

- Endpoint → UI vía IPC seguro; eventos importantes generan toast + entrada en historial.
- Empresa: alertas críticas → email/SIEM/webhook además del panel.
- Filosofía anti-fatiga: agrupar, priorizar y silenciar lo rutinario; interrumpir solo lo accionable.
