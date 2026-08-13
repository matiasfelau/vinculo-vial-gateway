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
  lib/vv/errors.lua            # contrato de error compartido por los plugins
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
- Status API en `http://127.0.0.1:8100` — sólo lectura (`/status`, `/metrics`),
  sólo desde el host; la usa el healthcheck del contenedor.

La **Admin API está apagada**. En DB-less la configuración es inmutable en
runtime, así que no cumple ninguna función operativa; lo único que se le pedía
era el healthcheck, y para eso alcanza el Status API. Apagarla elimina la
superficie en vez de depender de que quien despliegue se acuerde de no publicar
el puerto.

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

## Rate limiting detrás de un proxy

El límite global cuenta **por IP de cliente**. Si el Gateway queda detrás de un
balanceador o un ingress, la IP del peer es la del balanceador: todo el tráfico
caería en un único contador y un solo cliente podría agotar la cuota de la
plataforma entera. En ese caso hay que declarar el proxy en `KONG_TRUSTED_IPS`
(ej. `10.0.0.0/8`).

Con `KONG_TRUSTED_IPS` vacío (el default, Gateway expuesto directamente) Kong
**ignora** el `X-Forwarded-For` entrante, de modo que un cliente no puede
falsear su IP para evadir el límite. Los dos extremos son correctos; lo que
rompe es tener un proxy adelante y no declararlo.

## Trazabilidad

Un `X-Correlation-Id` (UUID) se genera en el Gateway si el cliente no lo trae,
viaja al upstream y se devuelve al cliente. Identity debería propagarlo a sus
logs y al evento `user.created` de RabbitMQ: es lo que permite cruzar una misma
operación entre los logs de los tres repos.

## Headers de identidad

`X-User-Hash` lo escribe **exclusivamente el Gateway**, a partir del `sub` de un
JWT ya verificado: los servicios internos confían en él porque llega por la red
interna. Por eso el header entrante se descarta en **todas** las rutas —
incluida `/auth/signup`, que no tiene `token-offloading`— mediante un
`request-transformer` global. Sin eso, cualquiera podría suplantar a otro
usuario mandando el header desde afuera.

El orden de plugins que lo hace posible:

```
rate-limiting (910) → app-attestation (900) → request-transformer (801, descarta
el header entrante) → token-offloading (790, inyecta el verificado)
```

## Contrato de error

Los rechazos generados por los plugins propios comparten una única forma
(`kong/lib/vv/errors.lua`):

```json
{ "error": "forbidden", "reason": "invalid_attestation" }
```

| Situación | Status | `error` | `reason` |
|---|---|---|---|
| Atestación ausente, mal formada, con firma inválida, expirada o con veredicto rechazado | `403` | `forbidden` | `invalid_attestation` |
| JWT de sesión del que no se puede derivar identidad | `401` | `unauthorized` | `invalid_token` |

El motivo real (`invalid_signature`, `expired_token`, `device_verdict_rejected`,
…) va **sólo al log**: distinguirlos en la respuesta le diría a quien está
sondeando el control exactamente qué validación tocó. Nunca se loguea el token
ni la PSK.

> Los rechazos que produce el propio Kong (`429` de rate limiting, `401` del
> plugin `jwt`, `404` sin Route, `502/503` del upstream) conservan su formato
> nativo `{"message": "..."}`. Unificarlos requeriría reescribir las respuestas
> de error de Kong y queda fuera del alcance de US-01.

## Convenciones

- Rama base `dev`; una rama `feature/<slug>` por feature, PR + squash merge.
- Los detalles de arquitectura y el contrato compartido entre componentes están
  en [CLAUDE.md](CLAUDE.md).
