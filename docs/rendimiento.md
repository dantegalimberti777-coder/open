# Rendimiento y Bajo Impacto en el Sistema

Objetivo: **impacto muy bajo** en CPU, RAM, disco y batería, manteniendo protección en tiempo real.
Un antivirus que ralentiza el equipo es desinstalado; el rendimiento es un requisito de producto, no
un extra.

---

## 1. Reducción de uso de CPU

1. **Triage barato primero.** El pre-filtro descarta con técnicas O(1) (allowlist firmado, Bloom
   filter, tipo de fichero) antes de invocar ML o heurística caras. La mayoría de ficheros nunca
   llegan a las capas costosas.
2. **Escaneo on-access selectivo.** Solo se escanea en eventos relevantes (apertura/ejecución/cierre
   tras escritura), no todo acceso. Exclusión inteligente de rutas de sistema confiables y firmadas.
3. **Caché de veredictos.** Un fichero ya escaneado y no modificado (mismo hash + timestamp) **no se
   reescanea**; el veredicto se cachea (en SQLite + memoria).
4. **Inferencia ML optimizada.** Modelos cuantizados (int8) en ONNX Runtime; modelos pequeños en el
   endpoint (gradient boosting / CNN ligera). Los modelos pesados se ejecutan en la nube.
5. **Núcleo en Rust** sin *garbage collector* → sin pausas y con uso predecible de CPU.
6. **Paralelismo controlado.** Pool de hilos limitado por prioridad baja; el escaneo cede ante la
   actividad del usuario.

## 2. Reducción de uso de RAM

1. **UI ligera con Tauri** (WebView del SO) en vez de Electron → decenas de MB en lugar de cientos.
2. **Bases de firmas mapeadas en memoria (mmap)** y estructuras compactas (Bloom filters, tablas hash
   perfectas) → solo se pagina lo usado.
3. **Streaming de ficheros grandes** (lectura por bloques) en vez de cargarlos enteros.
4. **Sin fugas** gracias a la seguridad de memoria de Rust; presupuestos de memoria por subsistema y
   *backpressure*.
5. **Descarga de modelos bajo demanda:** cargar en memoria solo los modelos activos según la política.

## 3. Escanear solo archivos modificados (escaneo incremental)

- **Índice de estado** en SQLite: `(ruta, hash, mtime, tamaño, veredicto, versión_firmas)`.
- Un fichero se reescanea **solo si** cambió su hash/mtime **o** si cambió la versión de firmas/modelo
  que lo evaluó. Esto hace que los escaneos completos posteriores sean drásticamente más rápidos.
- **Monitor de cambios del FS** (USN Journal en Windows, FSEvents en macOS, fanotify/inotify en Linux)
  para saber exactamente qué cambió desde el último escaneo, sin recorrer todo el disco.
- Escaneo rápido = solo áreas de alto riesgo (memoria, autoruns, procesos activos, temporales,
  descargas); escaneo completo = incremental sobre todo el disco.

## 4. Ejecutar tareas pesadas en segundo plano

1. **Colas por prioridad** con *idle scheduling*: el escaneo completo, la subida de telemetría y la
   actualización de modelos ocurren en segundo plano con prioridad de I/O y CPU bajas.
2. **Detección de inactividad/ociosidad.** Las tareas pesadas se aceleran cuando el equipo está
   inactivo o enchufado, y se pausan/ralentizan cuando el usuario trabaja o juega (**modo juego /
   modo no molestar**).
3. **Sandbox y análisis profundo en la nube**, nunca bloqueando el endpoint.
4. **Throttling adaptativo** según carga del sistema y temperatura.

## 5. Optimización de batería en portátiles

1. **Consciencia de energía:** detectar batería vs. corriente. Con batería, diferir escaneos
   completos, reducir frecuencia de telemetría y de consultas de red, y bajar el paralelismo.
2. **Agrupar trabajo (coalescing)** para permitir que la CPU entre en estados de bajo consumo
   (C-states) en lugar de despertares frecuentes.
3. **Respetar APIs de energía del SO** (power throttling / QoS classes en Windows/macOS) para que las
   tareas de fondo corran en núcleos eficientes.
4. **Sin *busy-waiting*;** todo basado en eventos.

## 6. Presupuestos y objetivos de rendimiento (SLOs de producto)

| Métrica | Objetivo |
|---------|----------|
| CPU en reposo (protección activa) | < 1–2 % medio |
| RAM del agente + UI | < ~200 MB en reposo |
| Latencia on-access (cache hit) | < 5 ms |
| Impacto en tiempo de arranque | < 1–2 s añadidos |
| Consultas de red por hora (idle) | mínimas, agrupadas |

Estos objetivos se miden en CI de rendimiento (benchmarks automatizados) y se vigilan por telemetría
agregada para prevenir regresiones entre versiones.
