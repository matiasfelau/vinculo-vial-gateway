# CLAUDE.md — vinculo-vial-gateway (Kong, US-01 Registro)

## Resumen del caso de uso
El Gateway es el único punto de entrada público. Para US-01: enruta `POST /api/v1/auth/signup` hacia `vinculo-vial-identity` y actúa como seguridad perimetral validando la atestación de **Google Play Integrity** (`X-App-Attestation`) antes de dejar pasar tráfico a la red interna. No inspecciona el body (viaja cifrado E2E); sólo lo hashea para verificar la ligadura con la atestación. Es también el primer caso de uso que crea este repo desde cero, por lo que además incluye el bootstrap básico de Kong reutilizable por toda la plataforma: Rate Limiting global y Token Offloading (`X-User-Hash`).

## Fuera de alcance
- iOS.

> **Nota de evolución.** El diseño original preveía un mock firmado con PSK
> porque no había acceso a Play Console. Con el acceso ya resuelto, el flujo
> principal es la integración real contra Google; el mock se conserva como
> fuente alternativa (`ATTESTATION_SOURCE=mock`) para CI y desarrollo sin
> dispositivo físico, con la misma estructura de veredicto que la API real.

## Contrato compartido entre componentes (US-01 — fuente única de verdad, idéntico en los 3 repos)

- **Endpoint**: `POST /api/v1/auth/signup` (síncrono).
- **Payload externo (lo que viaja por HTTP, cifrado)**:
  ```json
  { "ephemeral_public_key": "<base64>", "ciphertext": "<base64>" }
  ```
  Encoding estándar de un mensaje HPKE modo BASE (KEM X25519/HKDF-SHA256, AEAD AES-256-GCM).
- **Payload interno (una vez desencriptado en Identity)**:
  ```json
  { "dni": "12345678", "email": "usuario@ejemplo.com", "password": "Password123!" }
  ```
- **Respuestas**: `201 Created` / `400 Bad Request` / `403 Forbidden` / `409 Conflict`.
- **Header `X-App-Attestation`**: token opaco emitido por **Google Play Integrity** en el dispositivo. Lo genera la app, lo canjea y valida el Gateway contra `decodeIntegrityToken`; Identity nunca lo revisa.
  - La app debe pedirlo con `setRequestHash(<SHA-256 del body en hex>)`, atándolo al payload exacto que va a enviar. Si el body se re-serializa después de hashearlo, el Gateway responde `403`.
  - El Gateway exige: app reconocida por Play, dispositivo íntegro (`MEETS_DEVICE_INTEGRITY` o `MEETS_STRONG_INTEGRITY`), package name coincidente, atestación fresca, `requestHash` igual al hash del body recibido, y token no reutilizado.
  - En `ATTESTATION_SOURCE=mock` (sólo CI/desarrollo) el veredicto viaja en un JWT HS256 firmado con `APP_ATTESTATION_PSK`, con **idéntica estructura anidada** a la respuesta de Google.
- **Evento RabbitMQ publicado**: `user.created`, producido por `vinculo-vial-identity`.
  ```json
  { "eventId": "<uuid>", "eventType": "user.created", "timestamp": "<iso8601>", "producer": "vinculo-vial-identity", "actor": null, "payload": { "userId": "<uuid>" } }
  ```
  `actor: null` porque en signup todavía no hay sesión/usuario autenticado actuando.
- **Variables de entorno compartidas conceptualmente** (mismo secreto/par de claves en dos repos, nombre puede variar levemente por convención de cada lenguaje pero el valor debe coincidir):
  - `PLAY_PACKAGE_NAME` — mismo package name en Frontend (Play Console) y Gateway.
  - `ATTESTATION_REQUEST_HASH_ENCODING` — cómo codifica el Frontend el SHA-256 del body (`hex` por defecto). Debe coincidir exactamente o toda atestación falla.
  - `APP_ATTESTATION_PSK` — sólo en modo mock, entre Frontend y Gateway.
  - `IDENTITY_HPKE_PUBLIC_KEY` (Frontend) ↔ `IDENTITY_HPKE_PRIVATE_KEY` (Identity) — mismo par de claves X25519.
- **Header `X-Correlation-Id`**: UUID que genera el Gateway si el cliente no lo trae. Identity debe propagarlo a sus logs y al evento `user.created`.

## Contexto y decisión de diseño
- Kong con **plugin nativo en Lua** (no Go/pluginserver): corre embebido en el mismo worker de OpenResty, sin proceso externo, sin socket IPC, latencia mínima. Se extiende la imagen oficial de Kong copiando los `.lua` — no hay paso de compilación.
- Configuración declarativa DB-less (`kong.yml`).

## Funcionalidades base del Gateway (bootstrap, no específicas de US-01)
- **Rate Limiting global**: plugin nativo `rate-limiting` de Kong, sin `service`/`route` asociado en `kong.yml` → aplica a toda la plataforma desde el día uno.
- **Token Offloading**: plugin nativo `jwt` de Kong (verifica RS256 contra la Public Key de Identity) + plugin custom Lua `token-offloading` que toma el claim `sub` ya validado (`kong.ctx.shared.authenticated_jwt_token` en Kong 3.x) y lo inyecta como header `X-User-Hash`, removiendo `Authorization` antes de reenviar. Se aplica por Route en endpoints que requieren sesión — no en `/auth/signup` (todavía no hay token), pero se deja scaffoldeado. Un `request-transformer` global descarta cualquier `X-User-Hash` entrante, para que no se pueda suplantar identidad desde afuera.
- **Healthcheck**: `GET /status` del **Status API** (`:8100`, sólo lectura), usado en el `healthcheck` de `docker-compose.yml`. La Admin API está apagada: en DB-less no cumple ninguna función y sólo agrega superficie.
- **Logging**: acceso/errores a stdout/stderr, sin PII. `X-Correlation-Id` global para trazar una operación entre componentes.

## Plugin `app-attestation` (Lua nativo)
Intercepta `X-App-Attestation` en la fase `access` y decide si la request llega
a la red interna. Está partido en módulos con una responsabilidad cada uno:

- `sources/google.lua` — canjea el token opaco en `decodeIntegrityToken`.
- `sources/mock.lua` — alternativa para CI: veredicto firmado con PSK.
- `google_oauth.lua` — service account → access token, cacheado en shared dict.
- `verdict.lua` — evalúa el veredicto canónico de Play (función pura).
- `request_hash.lua` — SHA-256 del body para la ligadura con `requestHash`.
- `replay_guard.lua` — consumo de un solo uso de cada atestación.

Separar **fuente** de **política** es lo que permite que la decisión de
seguridad sea una sola y se testee una sola vez, sirva el veredicto Google o el
mock.

Se falla **cerrado**: si Google no responde, si el veredicto no alcanza, si el
hash no coincide o si el token ya se usó, la request no pasa. Toda respuesta de
rechazo es la misma —`403 { "error": "forbidden", "reason": "invalid_attestation" }`—
y el motivo real queda sólo en el log.

## Estructura del componente
```
/vinculo-vial-gateway
  /kong
    kong.conf                         # instancia: DB-less, listeners, logging, shared dicts
    kong.yml                          # config declarativa (plantilla con ${VARIABLES})
    /lib/vv/                          # módulos compartidos: base64url, jws, errores
    /plugins/app-attestation/         # ver desglose arriba
    /plugins/token-offloading/
  /docker/entrypoint.sh               # renderiza kong.yml contra el entorno
  /secrets                            # credenciales montadas — no se versiona
  /spec                               # tests Busted
  /spec/integration/run.sh            # integración contra un stub de Google
  Dockerfile                          # extiende kong:3.7 copiando /kong/plugins
  Dockerfile.test
  docker-compose.yml
  .env.example
```

## Convenciones de código (plugins Lua)
- La lógica decidible va en módulos puros, sin acceso al entorno de request ni al reloj (el `now` se recibe); el `handler.lua` sólo orquesta. Es lo que permite testear con Busted sin levantar Kong.
- Nunca loguear el token de atestación, la PSK ni la clave privada del service account. Ante un error de Google se reporta el status, no el cuerpo.
- Config del plugin vía `schema.lua` + variables de entorno inyectadas a Kong, nunca hardcodeada en el `.lua`.
- Comparaciones de firmas y hashes en tiempo constante (`vv.constant_time`).

## Testing
- **Unitarios** (Busted, sobre el runtime real de OpenResty vía `Dockerfile.test`): política de veredictos, hash del body, fuentes, OAuth del service account, base64url, contrato de error, token offloading.
- **Integración** (`spec/integration/run.sh`): Gateway real contra un stub de las APIs de Google. Cubre el camino HTTP que los unitarios no pueden — firma de la aserción, canje del access token y su caché, `decodeIntegrityToken`, ligadura con el body, anti-replay y no propagación del token al upstream. No requiere credenciales reales.
- Ambas suites corren en CI en cada PR (`.github/workflows/tests.yml`).

## Flujo Git (iterativo por feature)
Rama base `dev`. Una rama por feature, `feature/<slug>`, PR + squash merge a `dev` con tests en verde.

### Branches entregadas
1. `feature/kong-bootstrap` — `kong.conf` + `kong.yml` mínimo (DB-less), listeners, logging.
2. `feature/kong-declarative-routing` — Service `identity-service` + Route `POST /api/v1/auth/signup`.
3. `feature/kong-rate-limiting-global` — plugin nativo `rate-limiting` global, límite por env var.
4. `feature/attestation-lua-plugin` — primera versión del plugin, tests Busted.
5. `feature/kong-plugin-integration` — `kong.yml` referencia al plugin, aplicado a la Route de signup.
6. `feature/token-offloading-lua-plugin` — plugin nativo `jwt` + custom `token-offloading`.
7. `feature/gateway-docker-image` — `Dockerfile`, `docker-compose.yml`, entrypoint.
8. `feature/attestation-error-contract` — contrato único de rechazo, sin filtrar detalle interno.
9. `feature/identity-header-hardening` — anti-suplantación de `X-User-Hash`.
10. `feature/gateway-hardening` — Admin API apagada, IP real del cliente, correlation-id.
11. `feature/ci-busted` — CI en cada PR.
12. `feature/play-integrity-attestation` — atestación real contra Google, ligadura con el body, anti-replay.

## Docker
- No aplica Dockerfile multi-stage con etapa `scratch`: los plugins Lua no compilan, corren interpretados dentro del propio runtime de Kong. El `Dockerfile` es una única etapa que extiende `kong:3.7` copiando `/kong/plugins` y `/kong/lib`, y seteando `KONG_LUA_PACKAGE_PATH`.
- `docker-compose.yml`: un único servicio, Kong (imagen extendida) en modo DB-less. Sin Postgres propio (Kong DB-less no lo requiere) ni RabbitMQ (no aplica a este componente). Monta `./secrets` de sólo lectura para el service account de Google.

## Configuración
`.env.example` documenta todas las variables. Las principales:
- **Atestación**: `ATTESTATION_SOURCE` (`google`|`mock`), `PLAY_PACKAGE_NAME`, `GOOGLE_SERVICE_ACCOUNT_PATH`, `ATTESTATION_DEVICE_VERDICTS`, `ATTESTATION_MAX_AGE_SECONDS`, `ATTESTATION_REQUEST_HASH_ENCODING`, `APP_ATTESTATION_PSK` (sólo mock).
- **Plataforma**: `RATE_LIMIT_PER_MINUTE`, `IDENTITY_SERVICE_URL`, `JWT_PUBLIC_KEY` / `JWT_ISSUER` (Token Offloading), `KONG_TRUSTED_IPS`, puertos de proxy y status.

El service account de Google se **monta como archivo** (`./secrets/`), no se pasa por entorno: la clave privada no tiene por qué estar en el ambiente del proceso ni en la configuración declarativa.

## Comandos
```
docker compose up --build
docker build -f Dockerfile.test -t vinculo-vial-gateway-tests . && docker run --rm vinculo-vial-gateway-tests
bash spec/integration/run.sh
```