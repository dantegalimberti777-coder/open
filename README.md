# NGAV — Antivirus de Nueva Generación con Aprendizaje Continuo

> Documento técnico de arquitectura para un producto **Next-Generation Antivirus (NGAV / EDR)** de nivel empresarial, con motor de detección híbrido y un pipeline de aprendizaje continuo seguro.

Este repositorio contiene el **diseño técnico completo**. El documento principal está en
[`docs/arquitectura.md`](docs/arquitectura.md), complementado por documentos de detalle en `docs/`.

## Índice de la documentación

| Documento | Contenido |
|-----------|-----------|
| [`docs/arquitectura.md`](docs/arquitectura.md) | Arquitectura completa, componentes, tecnologías, backend, escalabilidad |
| [`docs/motor-deteccion.md`](docs/motor-deteccion.md) | Motor híbrido: firmas, comportamiento, heurística, ML/IA, anomalías, reputación, sandbox |
| [`docs/aprendizaje-continuo.md`](docs/aprendizaje-continuo.md) | Pipeline MLOps, threat intelligence, defensa contra data poisoning y adversarial ML |
| [`docs/rendimiento.md`](docs/rendimiento.md) | Optimización de CPU, RAM, batería, escaneo incremental |
| [`docs/interfaz.md`](docs/interfaz.md) | Diseño del cliente de escritorio y panel de administración |
| [`docs/seguridad-producto.md`](docs/seguridad-producto.md) | Autoprotección (anti-tamper), self-defense, cadena de confianza |
| [`docs/roadmap.md`](docs/roadmap.md) | Fases MVP → Beta → 1.0 → Enterprise + roadmap a 5 años |
| [`docs/estructura-carpetas.md`](docs/estructura-carpetas.md) | Estructura de carpetas del monorepo |

## Resumen ejecutivo

**Objetivo:** detectar malware conocido y desconocido (zero-day), ransomware antes del cifrado,
spyware, troyanos, rootkits y keyloggers; aprender de nuevas amenazas sin depender solo de firmas;
minimizar falsos positivos; y mantener un impacto muy bajo en el rendimiento.

**Estrategia central:** un **motor de detección híbrido de defensa en profundidad** que combina ocho
técnicas complementarias, orquestadas por un motor de decisión que pondera el veredicto de cada capa.
El aprendizaje continuo se realiza **en la nube** (nunca entrenando modelos directamente en el
endpoint con datos no validados), con validación humana y automática antes de promover cualquier
modelo, protegiendo el sistema contra envenenamiento de datos (*data poisoning*) y ataques
adversariales.

**Principio ético y de privacidad:** telemetría minimizada, con consentimiento, anonimizada y
alineada con GDPR/CCPA. El producto se diseña para **defensa**, con transparencia sobre qué datos se
recopilan y por qué.
