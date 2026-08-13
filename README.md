# vinculo-vial-gateway

API Gateway de la plataforma **Vínculo Vial**, construido sobre **Kong 3.7 en modo
DB-less**. Es el único punto de entrada público: enruta el tráfico hacia los
servicios internos y concentra la seguridad perimetral.

Para US-01 (Registro) expone `POST /api/v1/auth/signup` hacia
`vinculo-vial-identity` y valida el **Mock App Attestation**
(`X-App-Attestation`) antes de permitir tráfico hacia la red interna. El body
nunca se inspecciona ni se modifica: viaja cifrado extremo a extremo (HPKE).

## Estado

| Capacidad | Estado |
|---|---|
| Bootstrap DB-less + logging + Admin API | ✅ |
| Ruteo declarativo a `identity-service` | ✅ |
| Rate limiting global | ✅ |
| Plugin `app-attestation` (Lua) | ✅ |
| Token offloading (`X-User-Hash`) | ✅ |
| Imagen Docker + compose | ✅ |

## Estructura

```
kong/
  kong.conf                    # configuración de la instancia (DB-less, listeners, logging)
  kong.yml                     # configuración declarativa (Services, Routes, Plugins) — plantilla
  plugins/app-attestation/     # plugin Lua: validación del Mock App Attestation
  plugins/token-offloading/    # plugin Lua: X-User-Hash a partir del JWT verificado
docker/entrypoint.sh           # renderiza kong.yml contra el entorno y delega en Kong
spec/                          # tests Busted de los plugins Lua
Dockerfile                     # imagen del Gateway (extiende kong:3.7)
Dockerfile.test                # imagen de test (Kong + Busted sobre resty)
```

## Puesta en marcha

```bash
cp .env.example .env      # completar, sobre todo APP_ATTESTATION_PSK
docker compose up --build
```

- Proxy en `http://localhost:8000` — único punto de entrada público.
- Admin API en `http://127.0.0.1:8001` — sólo desde el host; la usa el
  healthcheck del contenedor (`GET /status`).

El Gateway se conecta a la red Docker `vinculo-vial`, compartida con el resto
de los componentes: `IDENTITY_SERVICE_URL` apunta al nombre de servicio de
`vinculo-vial-identity` dentro de esa red.

El `kong.yml` versionado es una **plantilla**: el entrypoint resuelve los
`${VARIABLE}` contra el entorno en cada arranque, valida el resultado con
`kong config parse` y recién ahí levanta Kong. Si falta una variable requerida,
el contenedor falla de entrada con el nombre de la que falta (nunca su valor).

## Tests

Los plugins usan las mismas APIs que en producción (`ngx.*`, `resty.openssl`),
así que los specs corren sobre el runtime real de OpenResty en lugar de
mockearlo. No se levanta Kong: se testea la lógica de validación aislada.

```bash
docker build -f Dockerfile.test -t vinculo-vial-gateway-tests .
docker run --rm vinculo-vial-gateway-tests            # equivale a `busted spec/`
```

## Contrato del header `X-App-Attestation`

JWT compacto firmado con **HMAC-SHA256** contra `APP_ATTESTATION_PSK`, emitido
por la app y validado sólo por el Gateway (Identity nunca lo revisa). Los
nombres de claim replican los de Play Integrity para que reemplazar el mock por
la API real no cambie el contrato:

```json
{
  "iss": "vinculo-vial-app",
  "aud": "vinculo-vial-gateway",
  "iat": 1735689600,
  "exp": 1735689720,
  "appRecognitionVerdict": "PLAY_RECOGNIZED",
  "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
}
```

Cualquier rechazo devuelve siempre la misma respuesta, sin filtrar el motivo
interno (que queda en los logs):

```
HTTP/1.1 403 Forbidden
{ "error": "forbidden", "reason": "invalid_attestation" }
```

## Convenciones

- Rama base `dev`; una rama `feature/<slug>` por feature, PR + squash merge.
- Los detalles de arquitectura y el contrato compartido entre componentes están
  en [CLAUDE.md](CLAUDE.md).
