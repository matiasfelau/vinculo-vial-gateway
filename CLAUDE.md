# CLAUDE.md — vinculo-vial-gateway (Kong, US-01 Registro)

## Resumen del caso de uso
El Gateway es el único punto de entrada público. Para US-01: enruta `POST /api/v1/auth/signup` hacia `vinculo-vial-identity` y actúa como seguridad perimetral validando el Mock App Attestation (`X-App-Attestation`) antes de dejar pasar tráfico a la red interna. No toca el body (viaja cifrado E2E). Es también el primer caso de uso que crea este repo desde cero, por lo que además incluye el bootstrap básico de Kong reutilizable por toda la plataforma: Rate Limiting global y Token Offloading (`X-User-Hash`).

## Fuera de alcance
- Integración real con Google Play Integrity API (se valida un mock firmado con PSK).
- iOS.

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
- **Header `X-App-Attestation`**: JWT de vida corta, firmado HMAC-SHA256 con `APP_ATTESTATION_PSK`, simulando el veredicto de Play Integrity (claims incluyen algo equivalente a `PLAY_RECOGNIZED`, `MEETS_DEVICE_INTEGRITY`). Lo genera la app, lo valida el Gateway. Identity nunca lo revisa.
- **Evento RabbitMQ publicado**: `user.created`, producido por `vinculo-vial-identity`.
  ```json
  { "eventId": "<uuid>", "eventType": "user.created", "timestamp": "<iso8601>", "producer": "vinculo-vial-identity", "actor": null, "payload": { "userId": "<uuid>" } }
  ```
  `actor: null` porque en signup todavía no hay sesión/usuario autenticado actuando.
- **Variables de entorno compartidas conceptualmente** (mismo secreto/par de claves en dos repos, nombre puede variar levemente por convención de cada lenguaje pero el valor debe coincidir):
  - `APP_ATTESTATION_PSK` — compartida entre Frontend (firma el mock JWT) y Gateway (lo valida).
  - `IDENTITY_HPKE_PUBLIC_KEY` (Frontend) ↔ `IDENTITY_HPKE_PRIVATE_KEY` (Identity) — mismo par de claves X25519.

## Contexto y decisión de diseño
- Kong con **plugin nativo en Lua** (no Go/pluginserver): corre embebido en el mismo worker de OpenResty, sin proceso externo, sin socket IPC, latencia mínima. Se extiende la imagen oficial de Kong copiando los `.lua` — no hay paso de compilación.
- Configuración declarativa DB-less (`kong.yml`).

## Funcionalidades base del Gateway (bootstrap, no específicas de US-01)
- **Rate Limiting global**: plugin nativo `rate-limiting` de Kong, sin `service`/`route` asociado en `kong.yml` → aplica a toda la plataforma desde el día uno.
- **Token Offloading**: plugin nativo `jwt` de Kong (verifica RS256 contra la Public Key de Identity) + plugin custom Lua `token-offloading` que toma el claim `sub` ya validado (`ngx.ctx.authenticated_jwt_token`) y lo inyecta como header `X-User-Hash`, removiendo `Authorization` antes de reenviar. Se aplica por Route en endpoints que requieren sesión — no en `/auth/signup` (todavía no hay token), pero se deja scaffoldeado.
- **Healthcheck**: Route `/status` vía Admin API, usada en el `healthcheck` de `docker-compose.yml`.
- **Logging**: acceso/errores a stdout/stderr, sin PII.

## Plugin `app-attestation` (Lua nativo)
- Intercepta `X-App-Attestation` en la fase `access`.
- Header ausente → `403 Forbidden` inmediato, sin invocar upstream.
- Header presente: valida firma HMAC-SHA256 contra `APP_ATTESTATION_PSK` y expiración (`exp`) del JWT.
- Firma inválida o expirada → `403 Forbidden`.
- Válida → deja pasar sin modificar el body.
- Respuesta de rechazo estandarizada: `{ "error": "forbidden", "reason": "invalid_attestation" }`.

## Estructura del componente
```
/vinculo-vial-gateway
  /kong
    kong.yml                          # config declarativa: Services, Routes, Plugins (DB-less)
    /plugins/app-attestation/
      schema.lua                      # config del plugin (psk, ttl)
      handler.lua                     # lógica de validación HMAC/exp
    /plugins/token-offloading/
      schema.lua
      handler.lua                     # inyección de X-User-Hash desde claims del jwt plugin
  /spec                               # tests Busted de los plugins Lua
  Dockerfile                          # extiende kong:3.7 copiando /kong/plugins
  docker-compose.yml
  .env.example
```

## Convenciones de código (plugins Lua)
- Lógica de validación aislada en `handler.lua`, sin dependencias directas del entorno de request para poder testear con Busted.
- Nunca loguear el token de atestación completo ni la PSK.
- Config del plugin (PSK, TTL) vía `schema.lua` + variables de entorno inyectadas a Kong, nunca hardcodeada en el `.lua`.

## Testing
- Framework: Busted (`spec/app-attestation_spec.lua`, `spec/token-offloading_spec.lua`).
- Casos: firma válida, firma inválida, header ausente, token expirado.
- Sin levantar Kong real — se testea la función de validación aislada.

## Flujo Git (iterativo por feature)
Rama base `dev`. Una rama por feature, `feature/<slug>`, PR + squash merge a `dev` con tests en verde.

### Plan de branches
1. `feature/kong-bootstrap` — `kong.yml` mínimo (DB-less), Admin API, Route de healthcheck, logging.
2. `feature/kong-declarative-routing` — Service `identity-service` + Route `POST /api/v1/auth/signup`.
3. `feature/kong-rate-limiting-global` — plugin nativo `rate-limiting` global, límite por env var.
4. `feature/attestation-lua-plugin` — `schema.lua` + `handler.lua` de `app-attestation`, tests Busted.
5. `feature/kong-plugin-integration` — `kong.yml` referencia al plugin, aplicado a la Route de signup.
6. `feature/token-offloading-lua-plugin` — plugin nativo `jwt` + custom `token-offloading` (inyección `X-User-Hash`, remoción de `Authorization`), tests Busted.
7. `feature/gateway-docker-image` — `Dockerfile` que extiende `kong:3.7` copiando `/kong/plugins`, `docker-compose.yml`.
8. `feature/attestation-error-contract` — estandarizar body/status de rechazo (403), sin filtrar detalle interno.

## Docker
- No aplica Dockerfile multi-stage con etapa `scratch`: los plugins Lua no compilan, corren interpretados dentro del propio runtime de Kong (imagen oficial, base Alpine). El `Dockerfile` es una única etapa que extiende `kong:3.7` copiando `/kong/plugins` y seteando `KONG_LUA_PACKAGE_PATH`.
- `docker-compose.yml`: un único servicio, Kong (imagen extendida) en modo DB-less. Sin Postgres propio (Kong DB-less no lo requiere) ni RabbitMQ (no aplica a este componente).

## Configuración
`.env.example`: `APP_ATTESTATION_PSK`, `ATTESTATION_TOKEN_TTL_SECONDS`, `RATE_LIMIT_PER_MINUTE`, `JWT_PUBLIC_KEY` (Token Offloading), `IDENTITY_SERVICE_URL`, puertos de proxy/admin.

## Comandos
```
docker compose up --build
busted spec/
```