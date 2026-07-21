# Monetización — Prueba de 14 días + $10/mes

Modelo comercial del NGAV: **14 días de prueba gratuita** y luego **suscripción de 10 USD/mes**.

## Cómo funciona

1. **Primer arranque:** el agente registra la fecha de inicio de la prueba en
   `~/.ngav/license.txt` (`trial_start`). Durante 14 días todas las funciones están disponibles.
2. **Cuenta atrás:** la interfaz muestra el banner «Prueba · N día(s)» y el botón «Comprar ahora».
3. **Al expirar la prueba** sin suscripción, el estado pasa a `expired` y **se bloquean los escaneos**
   (`/api/scan/start` devuelve `license_required`). La UI redirige a la pantalla de suscripción.
4. **Suscripción:** el usuario pulsa «Suscribirse — $10/mes» → el agente llama al servicio de
   licencias, que crea el pago. Tras pagar, el usuario recibe una **clave de licencia** y la activa en
   NGAV → Suscripción → Activar. El estado pasa a `active` con `active_until` (renovación mensual).

## Componentes

| Componente | Rol |
|------------|-----|
| `endpoint/agent-core/src/licensing.rs` | Prueba, estado, activación y validación de la licencia en el agente |
| `cloud/licensing/` (Go) | Servicio de facturación: checkout, validación de claves, webhook |
| API del agente | `GET /api/license`, `POST /api/checkout`, `POST /api/license/activate`; gating en `/api/scan/start` |

## Estados de licencia

- `trial` — dentro de los 14 días. Funcional.
- `active` — suscripción vigente (`active_until` en el futuro). Funcional.
- `expired` — prueba agotada sin suscripción. Escaneos bloqueados.

## Integración de pagos (Stripe)

El servicio `cloud/licensing` funciona en **dos modos**:

### Modo DEMO (por defecto, sin cuenta de pago)
Emite una clave de licencia activa al instante para probar todo el flujo sin cobros reales. Útil en
desarrollo y demos.

### Modo STRIPE (cobros reales)
Para cobrar de verdad necesitas una cuenta de Stripe (o similar). Pasos:

1. Crea una cuenta en https://stripe.com y un **producto** «NGAV Premium» con un **precio recurrente**
   de 10 USD/mes y **14 días de prueba** (trial).
2. Obtén tu `Secret key` y el `Price ID` (`price_...`).
3. Lanza el servicio con las variables de entorno:
   ```bash
   export STRIPE_SECRET_KEY=sk_live_xxx
   export STRIPE_PRICE_ID=price_xxx
   export NGAV_PUBLIC_URL=https://tu-dominio.com
   go run ./cloud/licensing
   ```
   Entonces `/v1/checkout` crea una **Stripe Checkout Session** (modo suscripción, 14 días de prueba)
   y devuelve la URL de pago real.
4. Configura el **webhook** de Stripe apuntando a `POST /v1/stripe/webhook` para activar/renovar/
   cancelar licencias automáticamente. **Verifica la firma** `Stripe-Signature` (pendiente en el MVP).
5. Apunta el agente al servicio:
   ```bash
   export NGAV_LICENSE_URL=https://tu-dominio.com
   ```

### Alternativas a Stripe
Paddle, Lemon Squeezy o Gumroad (actúan como *merchant of record* y gestionan impuestos/IVA, útil
para vender software a nivel global sin lidiar con la fiscalidad).

## Endurecimiento pendiente para producción (roadmap)

- **Entitlement firmado** (JWT/PASETO) verificado con clave pública embebida, en vez del token simple
  actual, para que la licencia no se pueda falsificar sin acceso al servidor.
- **Verificación de la firma del webhook** de Stripe.
- **Binding a huella de dispositivo** y límite de activaciones concurrentes (anti-compartición).
- **Revocación remota** y periodo de gracia offline.
- **Base de datos** para el estado de licencias (hoy el MVP usa memoria) sincronizada por webhooks.

> Nota legal/UX: comunica claramente el precio, la renovación automática y cómo cancelar antes de
> cobrar. Muchos mercados lo exigen (p. ej. la UE).
