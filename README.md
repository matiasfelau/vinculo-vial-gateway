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
| Bootstrap DB-less + logging + Status API | ✅ |
| Ruteo declarativo a `identity-service` | ✅ |
| Rate limiting global | ✅ |
| Atestación real contra Google Play Integrity | ✅ |
| Ligadura con el body (`requestHash`) + anti-replay | ✅ |
| Token offloading (`X-User-Hash`) | ✅ |
| Imagen Docker + compose | ✅ |
| CI: 83 tests unitarios + 18 de integración | ✅ |

## Estructura

```
kong/
  kong.conf                       # instancia: DB-less, listeners, logging, shared dicts
  kong.yml                        # declarativo: Services, Routes, Plugins — plantilla
  lib/vv/                         # módulos compartidos (base64url, JWS, errores)
  plugins/app-attestation/
    handler.lua                   # orquesta; toda la decisión vive en los módulos
    schema.lua                    # política y credenciales, nada hardcodeado
    verdict.lua                   # qué veredictos de Play se aceptan
    request_hash.lua              # ligadura de la atestación con el body
    replay_guard.lua              # consumo de un solo uso
    google_oauth.lua              # service account → access token (cacheado)
    sources/google.lua            # decodeIntegrityToken (producción)
    sources/mock.lua              # veredicto firmado con PSK (CI)
  plugins/token-offloading/       # X-User-Hash a partir del JWT ya verificado
docker/entrypoint.sh              # renderiza kong.yml contra el entorno
secrets/                          # credenciales montadas — no se versiona
spec/                             # tests Busted
spec/integration/run.sh           # integración contra un stub de Google
Dockerfile                        # imagen del Gateway (extiende kong:3.7)
Dockerfile.test                   # imagen de test (Kong + Busted sobre resty)
```

La separación entre `verdict.lua` (**qué** se acepta) y `sources/` (**de dónde**
sale el veredicto) es deliberada: la decisión de seguridad es una sola y se
testea una sola vez, sirva el veredicto Google o el mock.

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

El Gateway crea y se conecta a la red Docker `vinculo-vial`, compartida con el
resto de los componentes, y alcanza a Identity en `IDENTITY_SERVICE_URL`
(`http://vinculo-vial-identity:8080` por defecto).

> **Identity tiene que unirse a esa red y anunciarse con el alias
> `vinculo-vial-identity`.** En su compose el servicio se llama `identity`, y
> `vinculo-vial-identity` es el nombre del *proyecto* — que no es un hostname
> resolvible. Sin el alias, Kong devuelve `503` con
> `dns server error: 3 name error` aunque Identity esté perfectamente sano.
> El bloque exacto que va en el compose de Identity está en
> [CLAUDE.md](CLAUDE.md#contrato-compartido-entre-componentes-us-01--fuente-única-de-verdad-idéntico-en-los-3-repos).
>
> Para destrabar sin tocar el compose de Identity, sobre los contenedores ya
> corriendo:
>
> ```bash
> docker network connect --alias vinculo-vial-identity \
>   vinculo-vial vinculo-vial-identity-identity-1
> ```
>
> Es efímero: se pierde en cuanto Compose recree el contenedor.

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

Además hay una suite de **integración** que levanta el Gateway contra un stub de
las dos APIs de Google y ejercita el camino HTTP completo —firma de la aserción
del service account, canje por el access token, `decodeIntegrityToken`,
ligadura con el body y anti-replay— que los tests unitarios no pueden cubrir.
No necesita credenciales reales:

```bash
bash spec/integration/run.sh
```

## Atestación: `X-App-Attestation`

El header transporta el **token opaco de Google Play Integrity** que emite el
dispositivo. El Gateway lo canjea en `decodeIntegrityToken` por el veredicto,
lo evalúa y recién entonces deja pasar la request. Identity nunca lo ve.

### Lo que tiene que hacer la app

```kotlin
// 1. El hash del payload EXACTO que se va a enviar, en hexadecimal.
val body = requestBody.toByteArray()
val requestHash = MessageDigest.getInstance("SHA-256")
    .digest(body)
    .joinToString("") { "%02x".format(it) }

// 2. Pedir el token atándolo a ese hash.
val token = integrityTokenProvider.request(
    StandardIntegrityTokenRequest.builder()
        .setRequestHash(requestHash)
        .build()
).await().token()

// 3. Mandarlo junto con ESE body, sin re-serializarlo.
```

El punto 3 es el que se rompe en la práctica: si el body se vuelve a serializar
después de hashearlo (otro orden de claves, otro espaciado), el hash deja de
coincidir y el Gateway responde `403`. Hay que hashear y enviar **los mismos
bytes**.

El encoding del hash se configura con `ATTESTATION_REQUEST_HASH_ENCODING`
(`hex` por defecto) y tiene que coincidir exactamente con el del Frontend.

### Lo que valida el Gateway

| Control | Rechaza |
|---|---|
| Google resuelve el token | Tokens manipulados, de otra app o vencidos |
| `requestPackageName` / `packageName` | Tokens emitidos para otra aplicación (ver abajo) |
| `appRecognitionVerdict` | APK no reconocido por Play (modificado, repackaged) |
| `deviceRecognitionVerdict` | Dispositivos rooteados, emuladores, comprometidos |
| `certificateSha256Digest` | APK firmado con otro certificado *(opcional)* |
| `appLicensingVerdict` | Copias no licenciadas *(opcional, off por defecto)* |
| `timestampMillis` | Atestaciones fuera de la ventana de frescura |
| `requestHash` vs. body | Una atestación válida reutilizada sobre otro payload |
| Registro anti-replay | El reenvío de una request idéntica |

El body se **hashea, no se inspecciona**: sigue siendo opaco para el Gateway
(viaja cifrado E2E y las claves están en Identity) y se reenvía intacto.

### Identidad de la app

Google publica el package en dos lugares del veredicto y **no siempre puebla
los dos**: la Standard API puede devolver `requestDetails.requestPackageName`
ausente y dejar la identidad sólo en `appIntegrity.packageName`. El criterio es:

- todos los valores presentes tienen que coincidir con `PLAY_PACKAGE_NAME`, y
- tiene que haber al menos uno — si faltan los dos se rechaza
  (`package_name_absent`), porque sin identidad un token de cualquier otra app
  pasaría.

> **Esta comparación es la que detecta un token de otra app; no es redundante.**
> Comprobado en producción: `decodeIntegrityToken` devuelve `200` con un
> veredicto perfectamente válido aunque el package de la URL no sea el de la app
> que generó el token. Google descifra y devuelve el veredicto, y deja en manos
> del servidor verificar para qué app se emitió. Sacar este chequeo dejaría
> pasar atestaciones legítimas de cualquier otra aplicación.

### Veredicto de la app y builds de desarrollo

`appRecognitionVerdict` sólo vale `PLAY_RECOGNIZED` cuando el APK instalado es
**el que distribuyó Google Play**, firmado con la clave registrada en Play
Console. Un build compilado desde Android Studio está firmado con el keystore
de debug, así que Google devuelve `UNRECOGNIZED_VERSION` y el Gateway lo
rechaza — correctamente.

Para probar de punta a punta con el veredicto real, hay que instalar desde
Play. Lo más rápido es **Internal App Sharing** (Play Console → *Internal app
sharing* → subir el APK/AAB → abrir el link desde el dispositivo), que no
requiere pasar por revisión ni publicar nada.

Para iterar sin subir a Play en cada cambio, se puede aceptar el veredicto de
desarrollo:

```bash
ATTESTATION_APP_VERDICTS=["PLAY_RECOGNIZED","UNRECOGNIZED_VERSION"]
```

Eso **desactiva de hecho la verificación de que la app sea la legítima**: un
APK modificado o reempaquetado pasaría. Sirve para desarrollo; nunca para
producción.

> Si el veredicto llega como `UNEVALUATED`, el problema no está en la app:
> significa que Google no llegó a evaluarla, casi siempre porque el dispositivo
> no calificó. Hay que mirar `deviceIntegrity`.

### Diagnóstico

Los rechazos donde "¿qué recibió?" es toda la pregunta —package, veredicto de
dispositivo y `requestHash`— agregan al **log** qué llegó frente a qué se
esperaba:

```
app-attestation: request rechazado (package_mismatch) —
  requestDetails.requestPackageName='ar.felaufernandezbottaro.vinculovial.debug',
  esperado='ar.felaufernandezbottaro.vinculovial'

app-attestation: request rechazado (device_verdict_rejected) —
  recibido=['MEETS_BASIC_INTEGRITY'],
  aceptados=['MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY']
```

Va **sólo al log**, nunca a la respuesta: el cliente sigue recibiendo el mismo
`403 {"error":"forbidden","reason":"invalid_attestation"}` en todos los casos.
Los valores se sanean antes de interpolarse (sin caracteres de control, con
tope de largo) para que no se pueda inyectar una entrada de log falsa.

### Modo mock

Con `ATTESTATION_SOURCE=mock` el veredicto llega en un JWT firmado con
`APP_ATTESTATION_PSK` en lugar de pedírselo a Google, con **la misma estructura
anidada** que devuelve `decodeIntegrityToken`. Existe para CI y para desarrollar
sin dispositivo físico; la política que se evalúa es idéntica, así que el mock
no puede pasar por tener una forma más laxa.

Nunca en producción: quien tenga la PSK fabrica cualquier veredicto.

## Tamaño del payload

El sobre HPKE de signup incluye una selfie comprimida en base64 (~200KB). El
techo efectivo se controla en dos capas, y las dos tienen que estar
coordinadas:

| Capa | Dónde | Qué hace |
|---|---|---|
| Piso global de nginx | `nginx_http_client_max_body_size` en `kong.conf` (no templado por entorno) | Corta con un `413` propio de nginx antes de que la request llegue a ningún plugin de Kong |
| Techo por Route | plugin `request-size-limiting` en `kong.yml`, `SIGNUP_MAX_BODY_MB` | Corta con la respuesta estándar de Kong, sólo en `/auth/signup` |

El plugin corre en prioridad 951 — antes que `rate-limiting` (910) y
`app-attestation` (900), así que un body de más de `SIGNUP_MAX_BODY_MB` se
rechaza sin gastar cuota de rate limit ni una llamada a Google.

Es **por Route y no global** a propósito: Kong corre todas las instancias de un
mismo plugin que apliquen a una request, así que un `request-size-limiting`
global sumado a éste limitaría todo por el menor de los dos — el mismo motivo
por el que `rate-limiting` es sólo global y `app-attestation` es sólo por
Route (ver más abajo).

Si `SIGNUP_MAX_BODY_MB` sube por encima del piso de nginx, ese piso corta
primero y el plugin nunca llega a correr — hay que subir los dos juntos. El
buffer de nginx (`nginx_http_client_body_buffer_size`) también tiene que
quedar igual o mayor al piso: si el body no entra en el buffer, nginx lo
vuelca a un archivo temporal donde `app-attestation` ya no lo puede leer para
calcular el `requestHash`.

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
