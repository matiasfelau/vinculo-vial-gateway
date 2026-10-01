# vinculo-vial-gateway

API Gateway de la plataforma **Vínculo Vial**, construido sobre **Kong 3.7 en modo
DB-less**. Es el único punto de entrada público: enruta el tráfico hacia los
servicios internos y concentra la seguridad perimetral.

Expone `POST /api/v1/auth/signup` (US-01, Registro), `POST /api/v1/auth/signin`
(US-02, Login), `POST /api/v1/auth/refresh` + `POST /api/v1/auth/logout`
(US-03, Gestión de Sesión) hacia `vinculo-vial-identity`, `POST
/api/v1/vehicles` (US-04, Vinculación de Vehículo) hacia
`vinculo-vial-vehicle`, `POST /api/v1/alerts` (US-05, Escaneo de Patente y
Alerta Anónima) + `GET /api/v1/alerts/inbox` (US-07, Buzón de Alertas) hacia
`vinculo-vial-alert`, y `POST` + `DELETE /api/v1/notifications/tokens` (US-06,
Registro y Baja de Tokens FCM) hacia `vinculo-vial-notification`. Valida **App
Attestation** (`X-App-Attestation`, contra Google Play Integrity) en signup,
signin y refresh antes de permitir tráfico hacia la red interna — **logout es
la única excepción deliberada** (ver más abajo). El resto de las Routes usa un
perímetro distinto: **Token Offloading** real — Kong verifica el Access Token
(JWT RS256) y traduce el claim `sub` al header `X-User-Id`, para que el
upstream nunca vea ni necesite validar el JWT. Ninguna tiene `app-attestation`
(decisión cerrada del contrato desde US-05, por velocidad) y las que escriben
datos se apoyan en cambio en **rate limiting por usuario** sobre `X-User-Id`
— 5/min y 10/hora en `/alerts`, 10/día en el alta de `/notifications/tokens`,
como control de seguridad y no como cortesía operativa; 20/min en
`/alerts/inbox`, más permisivo por tratarse de lectura idempotente. La baja de
`/notifications/tokens` **no** lleva rate limiting, deliberadamente (ver más
abajo). El body de signup/signin/vehicles/alerts viaja cifrado extremo a
extremo (HPKE) y el Gateway nunca lo inspecciona ni lo modifica; el de
refresh/logout es un Refresh Token opaco sin cifrado propio, cuya
confidencialidad la aporta HTTPS; el del alta de `/notifications/tokens` es
un token FCM en texto plano, sin cifrado propio; `/alerts/inbox` y la baja de
`/notifications/tokens` no tienen body relevante.

## Estado

| Capacidad | Estado |
|---|---|
| Bootstrap DB-less + logging + Status API | ✅ |
| Ruteo declarativo a `identity-service` (`/auth/signup`, `/auth/signin`, `/auth/refresh`, `/auth/logout`) | ✅ |
| Ruteo declarativo a `vehicle-service` (`/vehicles`, US-04) | ✅ |
| Ruteo declarativo a `alert-service` (`/alerts`, US-05) | ✅ |
| Ruteo declarativo a `alert-service` (`/alerts/inbox`, US-07) | ✅ |
| Ruteo declarativo a `notification-service` (`POST /notifications/tokens`, US-06) | ✅ |
| Ruteo declarativo a `notification-service` (`DELETE /notifications/tokens`, US-06) | ✅ |
| Rate limiting global | ✅ |
| Rate limiting por usuario en `/alerts` (5/min, 10/hora sobre `X-User-Id`) | ✅ |
| Rate limiting por usuario en `/alerts/inbox` (20/min sobre `X-User-Id`) | ✅ |
| Rate limiting por usuario en el alta de `/notifications/tokens` (10/día sobre `X-User-Id`) | ✅ |
| La baja de `/notifications/tokens` sin rate limiting (deliberado, ver más abajo) | ✅ |
| Atestación real contra Google Play Integrity | ✅ |
| Ligadura con el body (`requestHash`) + anti-replay | ✅ |
| `/auth/logout` exento de atestación (deliberado, ver más abajo) | ✅ |
| `/alerts`, `/alerts/inbox` y `/notifications/tokens` exentos de atestación (decisión cerrada del contrato desde US-05, ver más abajo) | ✅ |
| Token offloading (`X-User-Hash` en el scaffold, `X-User-Id` en `/vehicles`, `/alerts`, `/alerts/inbox` y `/notifications/tokens`) | ✅ |
| `/internal/*` sin Route en Kong (verificado con un 404 explícito, Vehicle, Alert y Notification) | ✅ |
| Imagen Docker + compose | ✅ |
| CI: 94 tests unitarios + 93 de integración | ✅ |

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
  plugins/token-offloading/       # X-User-Hash/X-User-Id a partir del JWT ya verificado, PRIORITY=1000
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
# Una sola vez por host, antes del primer `docker compose up` de CUALQUIER
# componente de la plataforma (ver "Nomenclatura Docker" más abajo):
docker network create vinculo-vial

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

El Gateway se conecta a la red Docker **externa** `vinculo-vial` — no la crea
él: es la red puente que comparte toda la plataforma, provista una única vez
fuera de cualquier compose individual (ver el bootstrap de arriba). Ahí
alcanza a Identity en `IDENTITY_SERVICE_URL`
(`http://vinculo-vial-identity:8080` por defecto).

> **Cada componente de la plataforma tiene que declarar esa misma red como
> `external: true` y unirse a ella con un `container_name` de la forma
> `vinculo-vial-<servicio>`** (ver "Nomenclatura Docker", más abajo). Con eso
> alcanza: Docker resuelve el `container_name` como hostname en cualquier red
> puente compartida, sin necesidad de un alias manual. El bloque que va en el
> compose de cada componente:
>
> ```yaml
> networks:
>   vinculo-vial:
>     external: true
>
> services:
>   identity:                        # el nombre del servicio en SU compose
>     container_name: vinculo-vial-identity
>     networks:
>       default:                     # para hablar con su propia base de datos
>       vinculo-vial:
> ```
>
> **Si un componente todavía no migró** y sólo se anuncia con el nombre corto
> de su servicio (p. ej. `identity`), Kong devuelve `503` con
> `dns server error: 3 name error` aunque esté perfectamente sano. Para
> destrabar sin tocar su compose, sobre el contenedor ya corriendo:
>
> ```bash
> docker network connect --alias vinculo-vial-identity \
>   vinculo-vial <nombre-real-del-contenedor>
> ```
>
> Es efímero: se pierde en cuanto Compose recree ese contenedor. Es un
> parche, no el estado final — la solución real es que ese componente migre
> a `container_name: vinculo-vial-<servicio>`.

El `kong.yml` versionado es una **plantilla**: el entrypoint resuelve los
`${VARIABLE}` contra el entorno en cada arranque, valida el resultado con
`kong config parse` y recién ahí levanta Kong. Si falta una variable requerida,
el contenedor falla de entrada con el nombre de la que falta (nunca su valor).

### Nomenclatura Docker (convención de plataforma)

Convención obligatoria para la infraestructura Docker de los cuatro
componentes, para eliminar la resolución de DNS inconsistente entre
microservicios:

| Regla | En este repo |
|---|---|
| Contenedor principal: `vinculo-vial-<servicio>` | Ya cumplía: `container_name: vinculo-vial-gateway` |
| Contenedores secundarios (DB/broker): `vinculo-vial-<nombre>-db` / `vinculo-vial-<tecnología>` | No aplica: el Gateway es DB-less, sin contenedores propios además del suyo |
| Red global `vinculo-vial`, `external: true` | Corregido en este cambio: antes la creaba este compose (ver más abajo) |
| Red interna `<servicio>-internal` para el tráfico con su DB | No aplica: no hay DB propia que aislar |
| Volúmenes persistentes: `vinculo-vial-<nombre>-data` | No aplica: no hay volúmenes con nombre, sólo el bind mount de `./secrets` |

El único ajuste real fue la red: antes de este cambio, `docker-compose.yml`
**creaba** `vinculo-vial` (sin `external: true`), lo que dependía de que el
Gateway fuera el primer componente en levantarse y dejaba a los demás
adivinando quién era el dueño de la red. Ahora ningún compose la crea: se
provisiona una única vez por host (ver "Puesta en marcha") y todo componente
—Gateway incluido— se conecta a ella como recurso externo.

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

## Gestión de sesión: `/auth/refresh` y `/auth/logout`

Ambos endpoints reciben `{ "refresh_token": "<string opaco>" }`, de un solo
uso — sin el sobre HPKE de signup/signin, porque la confidencialidad la aporta
HTTPS y no hace falta cifrado adicional para un token opaco. El Gateway no
participa de la emisión ni de la revocación: sólo enruta y, en `/refresh`,
perimetra con `app-attestation`.

| Ruta | `X-App-Attestation` | Motivo |
|---|---|---|
| `POST /auth/refresh` | Obligatorio | Emite un par de tokens nuevo (rotado); mismo perímetro que signup/signin |
| `POST /auth/logout` | **No se exige** | Ver justificación abajo |

### Por qué `/logout` queda exento de atestación

Es una decisión deliberada, no un descuido. Cerrar sesión es una acción de
seguridad del **usuario**: si el dispositivo perdiera su capacidad de atestar
(o el mock, o a futuro Play Integrity real, fallara), exigir el header dejaría
al usuario atrapado sin poder revocar su propia sesión — exactamente lo
contrario de lo que se busca ante un robo de dispositivo. El riesgo residual
es bajo: quien ya posee el Refresh Token sólo puede invalidarlo, lo cual no le
da acceso a nada.

Por eso `/auth/logout` responde `200` siempre, incluso si el token no existía
o ya estaba revocado — es Identity quien implementa esa anti-enumeración; el
Gateway simplemente no le agrega una barrera de atestación por delante.

### `app-attestation` es siempre por Route, nunca por Service

Si el plugin se declarara a nivel del Service `identity-service`, se
heredaría automáticamente en **todas** sus Routes — incluida `/auth/logout`,
que por contrato tiene que quedar exenta, y Kong no ofrece manera de
desactivar un plugin heredado del Service en una Route puntual. Por eso es
regla del repo: cualquier Route nueva declara explícitamente los plugins que
necesita; declararlos a nivel de Service queda prohibido.

## Vinculación de Vehículo: `/vehicles` (US-04)

Primer endpoint con **Token Offloading real**: en vez de un perímetro de
atestación (como signup/signin/refresh), `/vehicles` exige sesión. El plugin
nativo `jwt` verifica la firma RS256 del Access Token contra `JWT_PUBLIC_KEY`
(la misma clave pública de Identity que ya se usa en el scaffold de
`/users/me`) y `token-offloading` traduce el claim `sub` —ya validado— al
header `X-User-Id` antes de reenviar a `vinculo-vial-vehicle`. El body es un
sobre HPKE con **cifrado diferenciado**: `dni_enc` sólo lo puede abrir
Identity, `pat_enc` sólo Vehicle — el Gateway no lo inspecciona ni lo
modifica, igual que en signup/signin.

| Ruta | Perímetro | Motivo |
|---|---|---|
| `POST /vehicles` | `jwt` + `token-offloading` | Requiere sesión activa; Vehicle nunca ve el JWT |

### Anti-spoofing de `X-User-Id`

Igual que con `X-User-Hash`, el header de identidad lo escribe
**exclusivamente el Gateway**: el propio `token-offloading` hace
`clear_header("X-User-Id")` **antes** de derivar el valor del JWT y escribir
el suyo — ver `kong/plugins/token-offloading/handler.lua`. Si esto no
ocurriera antes de escribir el header (o no ocurriera en absoluto), un
cliente podría mandar su propio `X-User-Id` y, según cómo Kong resuelva
headers duplicados, Vehicle podría terminar vinculando un vehículo a la
cuenta de otro usuario. Es la única capa en esta Route (ver
[Headers de identidad](#headers-de-identidad) para el porqué no hay, además,
un `request-transformer` corriendo acá).

### `/internal/verify-ownership` no existe en Kong

Vehicle llama a `POST /internal/verify-ownership` en Identity directo por red
interna — nunca a través del Gateway. No hay, ni va a haber, ninguna Route que
matchee `/internal/*`: una petición a ese path a través del proxy devuelve
`404` de Kong (sin Route que la atienda), sin llegar nunca a Identity.
Verificado explícitamente en la suite de integración.

**Alcance de esta protección**: la ausencia de Route en Kong bloquea el
acceso *desde afuera de la plataforma*, pero no aísla el endpoint *dentro* de
la red Docker — cualquier contenedor de esa red puede llamar a Identity
directamente. El aislamiento real (puerto interno separado y/o un secreto
servicio a servicio) es responsabilidad de Identity, documentado en su propio
`CLAUDE.md`. El Gateway sólo cubre la mitad perimetral del problema.

## Escaneo de Patente: `/alerts` (US-05)

Mismo perímetro base que `/vehicles`: `jwt` verifica el Access Token y
`token-offloading` traduce el `sub` a `X-User-Id` antes de reenviar a
`vinculo-vial-alert`. La diferencia es que esta Route **no lleva
`app-attestation`** — decisión cerrada del contrato de US-05, por
velocidad — y en su lugar suma `rate-limiting` **por usuario**, mucho más
estricto que el límite global por IP:

| Ruta | Perímetro | Límite por usuario |
|---|---|---|
| `POST /alerts` | `jwt` + `token-offloading` + `rate-limiting` | 5/min, 10/hora sobre `X-User-Id` |

### Por qué el rate limiting acá es un control de seguridad, no una cortesía

Sin `app-attestation`, cualquiera con un Access Token válido puede llamar a
este endpoint: no hay una segunda señal (dispositivo/app legítima) que
filtre tráfico automatizado. El `rate-limiting` por `X-User-Id` es la
**única** defensa contra un uso abusivo de la alerta anónima (spam, barrido
de patentes ajenas disfrazado de alertas). Por eso el límite es
significativamente más bajo que el global por IP, y por qué el orden de
plugins que lo sostiene es crítico:

```
jwt (1450) → token-offloading (1000) → rate-limiting (910, limit_by: header)
```

Si `token-offloading` corriera después de `rate-limiting` (como corría antes
de la corrección de prioridad — ver [Headers de identidad](#headers-de-identidad)),
`X-User-Id` todavía no existiría cuando `rate-limiting` intenta leerlo, y el
límite por usuario degradaría en silencio a otro criterio, dejando el
anti-abuso sin efecto real.

### `/internal/resolve-owner` no existe en Kong

Mismo esquema que Vehicle: Alert llama a `POST /internal/resolve-owner` en
Vehicle directo por red interna — Vehicle responde con `{"owner_ids": [...]}`
(un array, la relación es 1 patente → N dueños) y Alert nunca abre el
criptograma `pat_enc` que reenvía, porque no posee la clave privada de
Vehicle. No hay, ni va a haber, ninguna Route que matchee `/internal/*`: una
petición a ese path a través del proxy devuelve `404` de Kong. Verificado
explícitamente en la suite de integración. El mismo alcance limitado que en
Vehicle aplica acá: Kong bloquea el acceso desde afuera de la plataforma,
pero no aísla el endpoint dentro de la red Docker.

## Buzón de Alertas: `/alerts/inbox` (US-07)

Endpoint de **lectura**, sobre el mismo Service `alert-service` de US-05. Mismo
perímetro base que `/alerts`: `jwt` verifica el Access Token y
`token-offloading` traduce el `sub` a `X-User-Id`. Tampoco lleva
`app-attestation` — mismo motivo que `/alerts` — pero el `rate-limiting` que
lo reemplaza es deliberadamente más permisivo:

| Ruta | Perímetro | Límite por usuario |
|---|---|---|
| `GET /alerts/inbox` | `jwt` + `token-offloading` + `rate-limiting` | 20/min sobre `X-User-Id` |

### Por qué 20/min y no 5/min como `/alerts`

`/alerts` es una operación de escritura sin `app-attestation` por delante, así
que su `rate-limiting` es la única defensa contra abuso automatizado — de ahí
el límite estricto. `/alerts/inbox` es de lectura, idempotente y sin efectos:
sólo devuelve datos que ya pertenecen al usuario autenticado, no es un oráculo
de descubrimiento sobre datos ajenos. Una app puede necesitar refrescarlo con
frecuencia legítima, así que el límite es más holgado — sigue dependiendo de
la misma `PRIORITY = 1000` de `token-offloading` que `/alerts` (ver
[Headers de identidad](#headers-de-identidad)): si ese plugin corriera después
de `rate-limiting`, el límite por usuario degradaría en silencio a otro
criterio, igual que en `/alerts`.

### Paginación por cursor

Acepta `limit` (opcional, default 20, tope 100) y `cursor` (opaco, ausente en
la primera página) como query params, que el Gateway reenvía sin tocar —
`strip_path: false`, igual que el resto de las Routes del repo. El recorte del
`limit` al tope y la validación del `cursor` son responsabilidad de Alert, no
del Gateway: **Never Trust the Client se aplica en el servicio dueño del
dato**, no en el borde, y está prohibido sumar acá lógica de negocio de
paginación.

### Precedencia frente a `POST /alerts`

Ambas Routes comparten el prefijo `/api/v1/alerts`, pero Kong resuelve por
método además de por path: `alerts-route` declara `methods: [POST]` de forma
explícita, así que un `GET` nunca puede matchearla, sin importar la
especificidad del path. Verificado en la suite de integración con una
secuencia de 20 requests exitosos a `/alerts/inbox` seguidos de un 21° que
recibe `429` — si el `GET` hubiera caído por error en `alerts-route`, esa
secuencia habría fallado mucho antes del vigésimo request, contra el límite de
5/min de esa Route.

### Zero-PII

El DTO de salida (`id`, `alert_type`, `created_at`) es responsabilidad
exclusiva de Alert; el Gateway no inspecciona el body de la respuesta, sólo la
perimetra. La regla de anonimato del emisor —nunca `issuer_id`, `owner_id` ni
la patente hacia el cliente— vive en el contrato compartido, no en este repo.

## Registro y Baja de Tokens FCM: `/notifications/tokens` (US-06)

Dos Routes sobre el mismo Service `notification-service`, separadas por
método porque cada una necesita un perímetro distinto:

| Ruta | Perímetro | Límite por usuario |
|---|---|---|
| `POST /notifications/tokens` | `jwt` + `token-offloading` + `rate-limiting` | 10/día sobre `X-User-Id` |
| `DELETE /notifications/tokens` | `jwt` + `token-offloading` | Sin límite |

Mismo perímetro base que `/vehicles` y `/alerts`: `jwt` verifica el Access
Token y `token-offloading` traduce el `sub` a `X-User-Id`. Tampoco lleva
`app-attestation` — mismo motivo que `/alerts` y `/alerts/inbox`. El body del
alta es un token FCM en texto plano (`{"fcm_token": "..."}`), sin el sobre
HPKE de signup/vehicles/alerts: no es un dato sensible en ese sentido, así que
el Gateway lo reenvía intacto sin más tratamiento que el perímetro de sesión.

### Por qué son dos Routes y no una

Una única Route con `methods: [POST, DELETE]` heredaría el mismo
`rate-limiting` en ambos métodos, y eso es exactamente lo que no puede pasar:
un límite alcanzado en la baja dejaría al dispositivo **recibiendo
notificaciones que ya no le corresponden** — una fuga de privacidad, no una
molestia. Mismo criterio que eximir `/auth/logout` de `app-attestation`: hay
operaciones de baja/revocación que no se pueden dejar bloqueadas por una
cuota. Separar la Route por método es la única forma de que el
`rate-limiting` de una no se filtre a la otra.

### Por qué 10/día y no un límite por minuto

Un token FCM rota con poca frecuencia: reinstalación de la app, restauración
de un backup, limpieza de datos. Diez altas diarias por usuario es holgado
para cualquier uso legítimo y acota el abuso de escritura sobre un endpoint
sin `app-attestation` por delante. Depende de la misma `PRIORITY = 1000` de
`token-offloading` que `/alerts` y `/alerts/inbox` (ver
[Headers de identidad](#headers-de-identidad)): si ese plugin corriera
después de `rate-limiting`, el límite por usuario degradaría en silencio a
otro criterio.

### `/internal/*` no existe en Kong

Mismo criterio que Vehicle y Alert: no hay, ni va a haber, ninguna Route que
matchee `/internal/*`. Verificado explícitamente en la suite de integración.

## Tamaño del payload

El sobre HPKE de signup incluye una selfie comprimida en base64 (~200KB); el de
signin sólo lleva credenciales. Cada Route tiene su propio techo, coherente con
lo que realmente transporta. El techo efectivo se controla en dos capas, y las
dos tienen que estar coordinadas:

| Capa | Dónde | Qué hace |
|---|---|---|
| Piso global de nginx | `nginx_http_client_max_body_size` en `kong.conf` (no templado por entorno) | Corta con un `413` propio de nginx antes de que la request llegue a ningún plugin de Kong |
| Techo por Route | plugin `request-size-limiting` en `kong.yml`, `SIGNUP_MAX_BODY_MB` en `/auth/signup`, `SIGNIN_MAX_BODY_KB` en `/auth/signin` | Corta con la respuesta estándar de Kong, sólo en su propia Route |

El plugin corre en prioridad 951 — antes que `rate-limiting` (910) y
`app-attestation` (900), así que un body por encima del techo de su Route se
rechaza sin gastar cuota de rate limit ni una llamada a Google.

Es **por Route y no global** a propósito: Kong corre todas las instancias de un
mismo plugin que apliquen a una request, así que un `request-size-limiting`
global sumado a éste limitaría todo por el menor de los dos — el mismo motivo
por el que `rate-limiting` es sólo global y `app-attestation` es sólo por
Route (ver más abajo).

Si alguno de los dos techos sube por encima del piso de nginx, ese piso corta
primero y el plugin nunca llega a correr — hay que subir los dos juntos. El
buffer de nginx (`nginx_http_client_body_buffer_size`) también tiene que
quedar igual o mayor al mayor de los dos techos: si el body no entra en el
buffer, nginx lo vuelca a un archivo temporal donde `app-attestation` ya no lo
puede leer para calcular el `requestHash`.

`/auth/refresh` y `/auth/logout` no tienen un techo propio de
`request-size-limiting`: el body es sólo un Refresh Token opaco, órdenes de
magnitud más chico que el margen que ya deja el piso global de nginx, así que
un techo dedicado no agrega protección real — a diferencia de signup/signin,
donde el body sí puede acercarse al piso global.

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

`X-User-Hash` (scaffold de `/users/me`) y `X-User-Id` (`/vehicles`, US-04, y el
resto de las Routes con sesión) los escribe **exclusivamente el Gateway**, a
partir del `sub` de un JWT ya verificado: los servicios internos confían en
ellos porque llegan por la red interna. Sin eso, cualquiera podría suplantar a
otro usuario mandando el header desde afuera. La protección se aplica en dos
capas distintas, según si la Route tiene `token-offloading` o no:

- **Con `token-offloading`** (`/users/me`, `/vehicles`): el propio plugin
  hace `clear_header` del header antes de escribir el suyo, en un único
  `access()` atómico — no hace falta ni conviene sumar otro plugin encima.
- **Sin `token-offloading`** (`/auth/signup`, `/auth/signin`,
  `/auth/refresh`, `/auth/logout`): cada una de esas cuatro Routes declara su
  propia instancia de `request-transformer` que descarta ambos headers
  entrantes.

Antes había una única instancia de `request-transformer` **global**, que
cubría las cuatro rutas sin `token-offloading` con una sola declaración. Se
reemplazó por cuatro instancias por Route porque su prioridad nativa (801)
queda fija entre `rate-limiting` (910) y `token-offloading` — y con
`token-offloading` corriendo a partir de US-05 en una prioridad mayor a la de
`rate-limiting` (ver más abajo), un `request-transformer` global le habría
borrado el header recién escrito antes de reenviarlo al upstream. Declararlo
sólo en las rutas que de verdad lo necesitan evita el conflicto sin perder
cobertura.

El orden de plugins relevante en cada caso:

```
Rutas con token-offloading (/users/me, /vehicles y, desde US-05/US-06/US-07,
/alerts, /alerts/inbox y /notifications/tokens):
  jwt (1450) → token-offloading (1000) → rate-limiting (910, todas salvo DELETE /notifications/tokens)

Rutas sin token-offloading (signup, signin, refresh, logout):
  rate-limiting (910) → app-attestation (900, salvo logout) → request-transformer (801, por Route)
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
| Google/Play Integrity inalcanzable, o sin respuesta dentro del presupuesto del par de llamadas | `503` | `service_unavailable` | `dependency_unavailable` |
| Google/Play Integrity respondió `5xx`, o un `200` con un cuerpo fuera de contrato | `502` | `bad_gateway` | `dependency_error` |

El motivo real (`invalid_signature`, `expired_token`, `device_verdict_rejected`,
…) va **sólo al log**: distinguirlos en la respuesta le diría a quien está
sondeando el control exactamente qué validación tocó. Nunca se loguea el token
ni la PSK.

Las dos últimas filas son deliberadamente distintas de `invalid_attestation`:
una dependencia caída o que responde fuera de contrato no es un veredicto
negativo sobre el dispositivo del cliente, y tratarla como tal le haría creer
que el problema es suyo (no reintentable) cuando en realidad es transitorio y
ajeno a él. La distinción es posible porque `app-attestation` es código propio
que puede clasificar la falla antes de responder; no existe un mecanismo
equivalente para interceptar la respuesta nativa de Kong (ver nota siguiente).

> Los rechazos que produce el propio Kong (`429` de rate limiting, `401` del
> plugin `jwt`, `404` sin Route) conservan su formato nativo
> `{"message": "..."}`. Unificarlos requeriría reescribir las respuestas de
> error de Kong y queda fuera de alcance.
>
> Un upstream interno (`identity-service`, `vehicle-service`, `alert-service`,
> `notification-service`) que no responde dentro de su `read_timeout` recibe
> `504` de Kong — no `503` — porque el proxy nativo de Kong, a diferencia del
> cliente HTTP propio que usa `app-attestation` contra Google, no ofrece un
> punto donde reclasificar ese código antes de responder. Es una excepción
> deliberada y documentada al criterio general de la plataforma (503 =
> dependencia propia no disponible), no una inconsistencia pendiente.

## Presupuesto de latencia

Cada request que atraviesa el Gateway tiene un techo de 12000ms en el peor
caso: `2 × connect_timeout + read_timeout` (el `2 ×` es por el reintento de
`retries: 1` ante un fallo de conexión; `write_timeout` no participa porque un
upstream sano en la misma red no se estanca escribiendo, sólo conectando o
leyendo — verificado en la suite de integración, ver "Resiliencia (K2)").

| Service | `connect_timeout` | `read_timeout` | `write_timeout` | Peor caso |
|---|---|---|---|---|
| `identity-service` | 1000 | 6000 | 15000 | 8000 |
| `vehicle-service` | 1000 | 9000 | 9000 | 11000 |
| `alert-service` | 1000 | 9000 | 9000 | 11000 |
| `notification-service` | 1000 | 9000 | 9000 | 11000 |

`identity-service` queda más ajustado porque sus Routes (`/auth/signup`,
`/auth/signin`, `/auth/refresh`) además cargan `app-attestation`, que reparte
el resto del presupuesto (hasta 4000ms) contra Google: `8000 + 4000 = 12000`.
Las otras tres Routes no tienen esa dependencia y usan el presupuesto
completo. El `write_timeout` de `identity-service` queda sin acotar porque el
body de signup lleva una selfie y necesita margen para subir, no para que
Identity responda — no entra en la cuenta del peor caso por el motivo de
arriba.

Dentro de `app-attestation`, el canje de OAuth y el POST a
`decodeIntegrityToken` comparten un presupuesto agregado de 4000ms
(`ATTESTATION_DEPENDENCY_TIMEOUT_MS`), no 4000ms cada uno: lo que consume el
primero se descuenta del segundo. Con el access token en caché (el caso
común, dura una hora) el primero ni ocurre, así que el segundo dispone del
agregado completo. Cada llamada además respeta un techo individual de 3000ms
(`ATTESTATION_DEPENDENCY_CALL_TIMEOUT_MS`), para que ninguna de las dos pueda
sola agotar el presupuesto del par.

## Convenciones

- Rama base `dev`; una rama `feature/<slug>` por feature, PR + squash merge a `dev`, PR de release de `dev` a `main`.
