#!/usr/bin/env bash
#
# Test de integración del plugin `app-attestation` contra un stub de Google.
#
# Levanta tres contenedores —el Gateway, un stub de las APIs de Google y un
# upstream de eco— y ejercita el camino completo: firma de la aserción del
# service account, canje por un access token, POST a decodeIntegrityToken,
# evaluación del veredicto, ligadura con el hash del body y anti-replay.
#
# Es lo único que verifica de punta a punta el camino HTTP a Google, que los
# tests unitarios no pueden cubrir. No necesita credenciales reales.
set -euo pipefail

readonly NETWORK=vv-integration
readonly GATEWAY=vv-it-gateway
readonly STUB=vv-it-google
readonly UPSTREAM=vv-it-upstream
readonly PACKAGE_NAME=ar.felaufernandezbottaro.vinculovial
readonly JWT_ISSUER=vinculo-vial-identity

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# En Git Bash las rutas son POSIX (`/c/...`) y el demonio de Docker, que corre
# en Windows, no las entiende. En Linux no hay nada que convertir.
to_host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s' "$1"
  fi
}

failures=0

cleanup() {
  docker rm -f "${GATEWAY}" "${STUB}" "${UPSTREAM}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── Aserciones ───────────────────────────────────────────────────────────────

pass() {
  printf '  \033[32mok\033[0m   %s\n' "$1"
}

fail() {
  printf '  \033[31mFALLA\033[0m %s\n        %s\n' "$1" "$2"
  failures=$((failures + 1))
}

check() {
  local description="$1" expected="$2" actual="$3"

  if [[ "${expected}" == "${actual}" ]]; then
    pass "${description}"
  else
    fail "${description}" "esperado: ${expected}
        obtenido: ${actual}"
  fi
}

check_contains() {
  local description="$1" needle="$2" haystack="$3"

  if [[ "${haystack}" == *"${needle}"* ]]; then
    pass "${description}"
  else
    fail "${description}" "no contiene: ${needle}
        en: ${haystack}"
  fi
}

check_not_contains() {
  local description="$1" needle="$2" haystack="$3"

  if [[ "${haystack}" != *"${needle}"* ]]; then
    pass "${description}"
  else
    fail "${description}" "no debería contener: ${needle}"
  fi
}

# Manda un signup al Gateway y devuelve el status HTTP.
signup_status() {
  local attestation="$1" body="${2:-}"

  docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/signup \
    -H "X-App-Attestation: ${attestation}" \
    -H 'Content-Type: application/json' \
    --data-binary "${body}"
}

# Igual que signup_status, pero contra /auth/signin (US-02). El plugin
# `app-attestation` es la misma instancia/lógica en ambas Routes: lo que este
# helper ejercita es el ruteo y la config propia de la Route de signin
# (el techo de tamaño), no la política de atestación en sí — esa ya está
# cubierta en detalle contra signup, más arriba.
signin_status() {
  local attestation="$1" body="${2:-}"

  docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/signin \
    -H "X-App-Attestation: ${attestation}" \
    -H 'Content-Type: application/json' \
    --data-binary "${body}"
}

# Igual patrón contra /auth/refresh (US-03). A diferencia de signup/signin, el
# body no es un sobre HPKE sino `{"refresh_token": "<opaco>"}`, pero la
# ligadura con `app-attestation` funciona idéntico: el hash es del body crudo,
# sea cual sea su forma.
refresh_status() {
  local attestation="$1" body="${2:-}"

  docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/refresh \
    -H "X-App-Attestation: ${attestation}" \
    -H 'Content-Type: application/json' \
    --data-binary "${body}"
}

# SHA-256 del body en hexadecimal: lo mismo que calcula el Gateway y lo que el
# Frontend le pasa a `setRequestHash()`.
body_hash() {
  docker exec "${GATEWAY}" sh -c "printf '%s' '$1' | sha256sum | cut -d' ' -f1"
}

# Manda un POST a /api/v1/vehicles con el Bearer token dado (vacío = sin
# header Authorization) y devuelve el status HTTP. US-04: a diferencia de
# signup/signin/refresh, esta Route no exige `app-attestation` — la exige
# `jwt` + `token-offloading`.
vehicles_status() {
  local token="$1" body="${2:-\{\}}"

  if [[ -z "${token}" ]]; then
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST http://127.0.0.1:8000/api/v1/vehicles \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  else
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST http://127.0.0.1:8000/api/v1/vehicles \
      -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  fi
}

# Manda un POST a /api/v1/alerts con el Bearer token dado (vacío = sin header
# Authorization) y devuelve el status HTTP. US-05: mismo par jwt +
# token-offloading que vehicles_status, más rate-limiting por X-User-Id (ese
# tercer plugin se verifica en su propia suite, no acá).
alerts_status() {
  local token="$1" body="${2:-\{\}}"

  if [[ -z "${token}" ]]; then
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST http://127.0.0.1:8000/api/v1/alerts \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  else
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST http://127.0.0.1:8000/api/v1/alerts \
      -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  fi
}

# Manda un GET a /api/v1/alerts/inbox con el Bearer token dado (vacío = sin
# header Authorization), query params opcionales, y devuelve el status HTTP.
# US-07: mismo par jwt + token-offloading que alerts_status, más
# rate-limiting a 20/min por X-User-Id (más permisivo que el de alerts_status
# porque es lectura idempotente); el rate-limiting exhaustivo se verifica en
# su propia sección, no acá.
alerts_inbox_status() {
  local token="$1" query="${2:-}"

  if [[ -z "${token}" ]]; then
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X GET "http://127.0.0.1:8000/api/v1/alerts/inbox${query}"
  else
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X GET "http://127.0.0.1:8000/api/v1/alerts/inbox${query}" \
      -H "Authorization: Bearer ${token}"
  fi
}

# Firma un JWT RS256 compacto con la clave privada efímera de este run, usando
# el mismo módulo (`vv.jws`) que el plugin usa para firmar la aserción del
# service account de Google — no una reimplementación paralela del firmado.
sign_jwt() {
  local claims_json="$1"

  docker run --rm \
    -v "$(to_host_path "${jwt_dir}"):/keys:ro" \
    -v "$(to_host_path "${REPO_ROOT}/kong/lib"):/opt/kong:ro" \
    -e "VV_CLAIMS=${claims_json}" \
    --entrypoint resty kong:3.7 -I /opt/kong -e '
      local cjson = require "cjson.safe"
      local jws = require "vv.jws"

      local file = assert(io.open("/keys/private.pem"))
      local private_key = file:read("*a")
      file:close()

      local claims = assert(cjson.decode(os.getenv("VV_CLAIMS")))
      io.write(assert(jws.sign_rs256(claims, private_key)))
    '
}

# ── Preparación ──────────────────────────────────────────────────────────────

echo "==> Construyendo la imagen del Gateway"
docker build -q -t vinculo-vial-gateway:integration "$(to_host_path "${REPO_ROOT}")" >/dev/null

cleanup
docker network create "${NETWORK}" >/dev/null

echo "==> Levantando el stub de Google y el upstream"
docker run -d --name "${STUB}" --network "${NETWORK}" \
  -v "$(to_host_path "${SCRIPT_DIR}/fake-google/nginx.conf"):/conf/nginx.conf:ro" \
  --entrypoint sh kong:3.7 \
  -c 'mkdir -p /tmp/stub/logs && exec /usr/local/openresty/bin/openresty -c /conf/nginx.conf -p /tmp/stub -g "daemon off;"' \
  >/dev/null

docker run -d --name "${UPSTREAM}" --network "${NETWORK}" \
  -e HTTP_PORT=8080 mendhak/http-https-echo:31 >/dev/null

# Service account de juguete: clave RSA nueva en cada corrida, con el
# `token_uri` apuntando al stub. Nada de esto se versiona.
echo "==> Generando un service account de prueba"
sa_dir="$(mktemp -d)"

# Los contenedores de Kong corren como el usuario `kong`, no como root. En
# Linux el bind mount respeta los permisos del host, y `mktemp -d` crea el
# directorio en modo 700: sin esto, el contenedor no puede ni entrar.
# (En Docker Desktop los permisos se ignoran, así que el problema sólo aparece
# en CI.)
chmod 755 "${sa_dir}"

docker run --rm --entrypoint sh kong:3.7 -c '
  openssl genrsa 2048 2>/dev/null
' > "${sa_dir}/private.pem"
chmod 644 "${sa_dir}/private.pem"

# El contenedor sólo lee y escribe a stdout: el archivo lo crea el shell del
# host, y queda con su usuario y sus permisos. Si lo escribiera el contenedor,
# quedaría de root y el host no podría ni ajustarle los permisos después.
docker run --rm -v "$(to_host_path "${sa_dir}"):/sa:ro" --entrypoint resty kong:3.7 -e '
  local cjson = require "cjson.safe"
  local file = assert(io.open("/sa/private.pem"))
  local private_key = file:read("*a")
  file:close()

  io.write(cjson.encode({
    type = "service_account",
    project_id = "vinculo-vial-test",
    private_key_id = "stub-key-id",
    private_key = private_key,
    client_email = "gateway@vinculo-vial-test.iam.gserviceaccount.com",
    token_uri = "http://vv-it-google:8080/token",
  }))
' > "${sa_dir}/google-service-account.json"
chmod 644 "${sa_dir}/google-service-account.json"

# Par RSA efímero para firmar los Access Token de sesión (US-04): la clave
# pública sobreescribe JWT_PUBLIC_KEY del Gateway, la privada firma los JWT de
# prueba con `sign_jwt`. Nuevo en cada corrida, igual que el service account.
echo "==> Generando un par RSA de prueba para JWT_PUBLIC_KEY"
jwt_dir="$(mktemp -d)"
chmod 755 "${jwt_dir}"

docker run --rm --entrypoint sh kong:3.7 -c '
  openssl genrsa 2048 2>/dev/null
' > "${jwt_dir}/private.pem"
chmod 644 "${jwt_dir}/private.pem"

docker run --rm -v "$(to_host_path "${jwt_dir}"):/keys:ro" --entrypoint sh kong:3.7 -c '
  openssl rsa -in /keys/private.pem -pubout 2>/dev/null
' > "${jwt_dir}/public.pem"

# Mismo formato que documenta .env.example: saltos de línea escapados como
# `\n` literal, para insertarse en un escalar YAML entrecomillado.
jwt_public_key_escaped="$(awk 'BEGIN{ORS="\\n"} 1' "${jwt_dir}/public.pem")"

echo "==> Levantando el Gateway"
docker run -d --name "${GATEWAY}" --network "${NETWORK}" \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -v "$(to_host_path "${sa_dir}/google-service-account.json"):/etc/vinculo-vial/google-service-account.json:ro" \
  -e "IDENTITY_SERVICE_URL=http://${UPSTREAM}:8080" \
  -e "VEHICLE_SERVICE_URL=http://${UPSTREAM}:8080" \
  -e "ALERT_SERVICE_URL=http://${UPSTREAM}:8080" \
  -e "PLAY_INTEGRITY_URL=http://${STUB}:8080" \
  -e "PLAY_PACKAGE_NAME=${PACKAGE_NAME}" \
  -e ATTESTATION_SOURCE=google \
  -e ATTESTATION_SSL_VERIFY=false \
  -e "JWT_PUBLIC_KEY=${jwt_public_key_escaped}" \
  -e "JWT_ISSUER=${JWT_ISSUER}" \
  vinculo-vial-gateway:integration >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${GATEWAY}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${GATEWAY}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
  echo "El Gateway no llegó a estar healthy:"
  docker logs "${GATEWAY}"
  exit 1
fi

# ── Casos ────────────────────────────────────────────────────────────────────

echo
echo "Camino feliz"

body='{"ephemeral_public_key":"AAAA","ciphertext":"BBBB"}'
hash="$(body_hash "${body}")"

check "atestación válida ligada al body llega al upstream" \
  200 "$(signup_status "${hash}" "${body}")"

echo
echo "Ligadura con el body (requestHash)"

# Mismo token de atestación, otro body: es el ataque que la ligadura frena.
check "una atestación válida no sirve para otro body" \
  403 "$(signup_status "${hash}" '{"ephemeral_public_key":"AAAA","ciphertext":"MANIPULADO"}')"

body2='{"ephemeral_public_key":"CCCC","ciphertext":"DDDD"}'
check "un body distinto con su propio hash sí pasa" \
  200 "$(signup_status "$(body_hash "${body2}")" "${body2}")"

echo
echo "Identidad de la app"

# Reproduce el rechazo que apareció en la primera prueba contra Google real:
# la Standard API puede devolver el veredicto sin
# `requestDetails.requestPackageName`, dejando la identidad sólo en
# `appIntegrity.packageName`. Exigir el primero rechazaba atestaciones válidas.
body_nopkg='{"ephemeral_public_key":"QQQQ","ciphertext":"RRRR"}'
check "un veredicto sin requestPackageName se acepta si appIntegrity coincide" \
  200 "$(signup_status "NOPKG:$(body_hash "${body_nopkg}")" "${body_nopkg}")"

# Comprobado contra Google real: `decodeIntegrityToken` devuelve 200 con un
# veredicto válido aunque el token lo haya generado otra app. Este chequeo del
# Gateway es el ÚNICO control que lo detecta — sin él, una atestación legítima
# de cualquier otra aplicación pasaría.
body_otherpkg='{"ephemeral_public_key":"SSSS","ciphertext":"TTTT"}'
check "un veredicto válido de OTRA app se rechaza" \
  403 "$(signup_status "OTHERPKG:$(body_hash "${body_otherpkg}")" "${body_otherpkg}")"

echo
echo "Anti-replay"

body3='{"ephemeral_public_key":"EEEE","ciphertext":"FFFF"}'
hash3="$(body_hash "${body3}")"
check "la primera presentación del token pasa" \
  200 "$(signup_status "${hash3}" "${body3}")"
check "reenviar exactamente la misma request se rechaza" \
  403 "$(signup_status "${hash3}" "${body3}")"

echo
echo "Veredicto del dispositivo"

body4='{"ephemeral_public_key":"GGGG","ciphertext":"HHHH"}'
hash4="$(body_hash "${body4}")"
check "un dispositivo que sólo pasa controles básicos se rechaza" \
  403 "$(signup_status "${hash4}|MEETS_BASIC_INTEGRITY" "${body4}")"

body5='{"ephemeral_public_key":"IIII","ciphertext":"JJJJ"}'
hash5="$(body_hash "${body5}")"
check "un emulador se rechaza" \
  403 "$(signup_status "${hash5}|MEETS_VIRTUAL_INTEGRITY" "${body5}")"

body6='{"ephemeral_public_key":"KKKK","ciphertext":"LLLL"}'
hash6="$(body_hash "${body6}")"
check "un dispositivo comprometido (sin veredictos) se rechaza" \
  403 "$(signup_status "${hash6}|NONE" "${body6}")"

body7='{"ephemeral_public_key":"MMMM","ciphertext":"NNNN"}'
hash7="$(body_hash "${body7}")"
check "integridad reforzada por hardware se acepta" \
  200 "$(signup_status "${hash7}|MEETS_DEVICE_INTEGRITY,MEETS_STRONG_INTEGRITY" "${body7}")"

echo
echo "Errores de Google"

check "un token que Google rechaza se traduce en 403" \
  403 "$(signup_status "REJECT" '{}')"
check "un error 5xx de Google falla cerrado" \
  403 "$(signup_status "BOOM" '{}')"

echo
echo "Tamaño del payload"

# El plugin `request-size-limiting` corre en prioridad 951: más alto que
# `app-attestation` (900). Un body por encima de SIGNUP_MAX_BODY_MB tiene que
# rechazarse SIN llegar a llamar a Google, aunque la atestación ni siquiera
# sea válida — si el orden estuviera invertido, cada intento de subir un
# archivo enorme le costaría una llamada real a la Play Integrity API.
google_calls_before="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"

# El body en sí no importa (se rechaza antes de leerlo entero); sólo el
# tamaño. Se arma en un archivo dentro del contenedor para no chocar con el
# límite de longitud de argumentos del shell del host.
docker exec "${GATEWAY}" sh -c \
  "head -c 6291456 /dev/urandom > /tmp/oversized.bin"

oversized_status="$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
  -X POST http://127.0.0.1:8000/api/v1/auth/signup \
  -H 'X-App-Attestation: no-hace-falta-que-sea-valido' \
  -H 'Content-Type: application/octet-stream' \
  -H 'Expect:' \
  --data-binary @/tmp/oversized.bin)"

check "un body de 6MB (> SIGNUP_MAX_BODY_MB) se rechaza" 413 "${oversized_status}"

google_calls_after="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"
check "el rechazo por tamaño no llega a llamar a Google" \
  "${google_calls_before}" "${google_calls_after}"

echo
echo "Header de atestación"

check "sin header, 403 sin siquiera llamar a Google" \
  403 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/signup -d '{}')"

echo
echo "Contrato de la respuesta y del upstream"

# El orden de las claves del JSON no está garantizado, así que se verifica el
# contenido y no la serialización exacta.
rejection="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/signup \
  -H 'X-App-Attestation: REJECT' -d '{}')"

check_contains "el rechazo declara el error del contrato" \
  '"error":"forbidden"' "${rejection}"
check_contains "el rechazo declara el motivo público del contrato" \
  '"reason":"invalid_attestation"' "${rejection}"
# El motivo real de éste era `playintegrity_token_rejected`: al cliente no le
# llega nada que le diga qué control tocó.
check_not_contains "el rechazo no filtra el motivo interno" \
  "playintegrity" "${rejection}"

body8='{"ephemeral_public_key":"OOOO","ciphertext":"PPPP"}'
upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/signup \
  -H "X-App-Attestation: $(body_hash "${body8}")" \
  -H 'Content-Type: application/json' \
  --data-binary "${body8}")"

check_not_contains "el token de atestación no se propaga al upstream" \
  "x-app-attestation" "$(printf '%s' "${upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_contains "el body llega intacto al upstream" \
  "PPPP" "${upstream_view}"

echo
echo "Caché del access token"

# Un solo canje de token para todas las requests anteriores: si no cacheara,
# habría uno por request.
token_requests="$(docker logs "${STUB}" 2>&1 | grep -c 'POST /token' || true)"
check "el access token se pide una sola vez, no por request" \
  1 "${token_requests}"

echo
echo "Login (US-02)"

# La política de atestación en sí (ligadura, replay, veredictos, errores de
# Google) ya está cubierta en detalle contra signup: es la misma instancia de
# plugin. Acá sólo se verifica lo específico de esta Route: que el header
# siga siendo obligatorio, que una atestación válida efectivamente pase, el
# contrato de la respuesta, y el techo de tamaño propio (mucho más chico que
# el de signup, porque el body no lleva una selfie).

check "sin header, 403 sin siquiera llamar a Google" \
  403 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/signin -d '{}')"

signin_body='{"ephemeral_public_key":"ZZZZ","ciphertext":"ZZZZ"}'
signin_hash="$(body_hash "${signin_body}")"

check "atestación válida ligada al body llega al upstream" \
  200 "$(signin_status "${signin_hash}" "${signin_body}")"

# Body propio para este chequeo: el anti-replay ya probado más arriba
# rechazaría un segundo uso del mismo token de la request anterior.
signin_body2='{"ephemeral_public_key":"YYYY","ciphertext":"WWWW"}'
signin_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/signin \
  -H "X-App-Attestation: $(body_hash "${signin_body2}")" \
  -H 'Content-Type: application/json' \
  --data-binary "${signin_body2}")"

check_contains "el body llega intacto al upstream" \
  "WWWW" "${signin_upstream_view}"
check_not_contains "el token de atestación no se propaga al upstream" \
  "x-app-attestation" "$(printf '%s' "${signin_upstream_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Tamaño del payload de login"

signin_google_calls_before="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"

# Un byte por encima de SIGNIN_MAX_BODY_KB (64KB). El contenido no importa: se
# rechaza antes de leerlo entero.
docker exec "${GATEWAY}" sh -c \
  "head -c 65537 /dev/urandom > /tmp/oversized-signin.bin"

signin_oversized_status="$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
  -X POST http://127.0.0.1:8000/api/v1/auth/signin \
  -H 'X-App-Attestation: no-hace-falta-que-sea-valido' \
  -H 'Content-Type: application/octet-stream' \
  -H 'Expect:' \
  --data-binary @/tmp/oversized-signin.bin)"

check "un body de 64KB+1 (> SIGNIN_MAX_BODY_KB) se rechaza" 413 "${signin_oversized_status}"

signin_google_calls_after="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"
check "el rechazo por tamaño no llega a llamar a Google" \
  "${signin_google_calls_before}" "${signin_google_calls_after}"

echo
echo "Refresh (US-03)"

# La política de atestación en sí (ligadura, replay, veredictos, errores de
# Google) ya está cubierta en detalle contra signup: es la misma instancia de
# plugin. Acá sólo se verifica el contrato específico de esta Route — que el
# header siga siendo obligatorio y que una atestación válida efectivamente
# pase — y el contrato de la respuesta.

check "sin header, 403 sin siquiera llamar a Google" \
  403 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/refresh -d '{}')"

refresh_body='{"refresh_token":"opaque-refresh-a"}'
refresh_hash="$(body_hash "${refresh_body}")"

check "atestación válida ligada al body llega al upstream" \
  200 "$(refresh_status "${refresh_hash}" "${refresh_body}")"

check "una atestación rechazada por Google se traduce en 403" \
  403 "$(refresh_status "REJECT" '{"refresh_token":"no-importa"}')"

# Body propio para este chequeo: el anti-replay ya probado más arriba
# rechazaría un segundo uso del mismo token de la request anterior.
refresh_body2='{"refresh_token":"opaque-refresh-b"}'
refresh_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/refresh \
  -H "X-App-Attestation: $(body_hash "${refresh_body2}")" \
  -H 'Content-Type: application/json' \
  --data-binary "${refresh_body2}")"

check_contains "el body llega intacto al upstream" \
  "opaque-refresh-b" "${refresh_upstream_view}"
check_not_contains "el token de atestación no se propaga al upstream" \
  "x-app-attestation" "$(printf '%s' "${refresh_upstream_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Logout (US-03): exención deliberada de atestación"

# A diferencia de TODAS las demás rutas, logout tiene que pasar SIN header: si
# exigiera atestación, un usuario con el dispositivo comprometido (o el mock
# caído) quedaría sin poder cerrar su propia sesión — justo lo contrario de lo
# que se busca ante un robo de dispositivo. Se manda un `X-User-Hash` de
# prueba para confirmar que el `request-transformer` global lo descarta acá
# también, igual que en el resto de las rutas.

check "sin header de atestación pasa igual (no 403)" \
  200 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/logout \
    -H 'Content-Type: application/json' \
    -d '{"refresh_token":"cualquier-token"}')"

logout_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/logout \
  -H 'Content-Type: application/json' \
  -H 'X-User-Hash: intento-de-suplantacion' \
  -d '{"refresh_token":"otro-token-distinto"}')"

check_contains "el body llega intacto al upstream" \
  "otro-token-distinto" "${logout_upstream_view}"
check_not_contains "X-User-Hash entrante se descarta también en logout" \
  "intento-de-suplantacion" "$(printf '%s' "${logout_upstream_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Vinculación de Vehículo (US-04): JWT y Token Offloading"

readonly USER_SUB="b7e6c1d4-4a2f-4e9b-9c3a-6f1d2e8a9c11"
now="$(date +%s)"

vehicles_body='{"dni_enc":"cripto-para-identity","pat_enc":"cripto-para-vehicle"}'

check "sin Authorization, 401 sin necesidad de un JWT" \
  401 "$(vehicles_status "" "${vehicles_body}")"

check "un Bearer que no es un JWT compacto se rechaza con 401" \
  401 "$(vehicles_status "no-es-un-jwt" "${vehicles_body}")"

expired_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${USER_SUB}\",\"exp\":$((now - 300))}")"
check "un JWT expirado se rechaza con 401" \
  401 "$(vehicles_status "${expired_token}" "${vehicles_body}")"

wrong_issuer_token="$(sign_jwt "{\"iss\":\"otro-emisor\",\"sub\":\"${USER_SUB}\",\"exp\":$((now + 300))}")"
check "un JWT firmado con un iss que no tiene consumer registrado se rechaza con 401" \
  401 "$(vehicles_status "${wrong_issuer_token}" "${vehicles_body}")"

valid_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${USER_SUB}\",\"exp\":$((now + 300))}")"
check "un JWT válido, firmado y sin vencer, pasa" \
  200 "$(vehicles_status "${valid_token}" "${vehicles_body}")"

vehicles_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/vehicles \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'Content-Type: application/json' \
  --data-binary "${vehicles_body}")"

check_contains "Vehicle recibe X-User-Id con el sub del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${vehicles_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el Authorization no se propaga al upstream (token offloading)" \
  "authorization" "$(printf '%s' "${vehicles_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_contains "el body (sobre HPKE) llega intacto al upstream" \
  "cripto-para-vehicle" "${vehicles_upstream_view}"

spoofed_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/vehicles \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'X-User-Id: usuario-suplantado' \
  -H 'Content-Type: application/json' \
  --data-binary "${vehicles_body}")"

check_contains "un X-User-Id forjado por el cliente se reemplaza por el del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${spoofed_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el X-User-Id forjado no llega al upstream" \
  "usuario-suplantado" "$(printf '%s' "${spoofed_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Vinculación de Vehículo (US-04): /internal/* no existe en Kong"

# `/internal/verify-ownership` (Vehicle → Identity) es tráfico interno
# directo: no hay ninguna Route en kong.yml que matchee `/internal/*`, así
# que a través del proxy tiene que dar 404 de Kong, sin llegar a ningún
# upstream (ni Vehicle, que no existe en este harness, ni Identity).
check "/internal/verify-ownership no tiene Route: 404" \
  404 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/internal/verify-ownership \
    -H 'Content-Type: application/json' \
    -d '{"owner_id":"x","dni_enc":"y"}')"

echo
echo "Escaneo de Patente (US-05): JWT y Token Offloading en /alerts"

# Mismo usuario que en la sección de Vehículo: los contadores de
# rate-limiting son por Route, así que reusar el sub no cruza cupos entre
# /vehicles y /alerts. Cada bloque manda a lo sumo 2 requests con JWT
# válido, muy por debajo del límite de 5/min — la verificación exhaustiva
# del rate-limiting (sexto request -> 429, cupos independientes por
# usuario) es una suite aparte.
alerts_body='{"alert_type":"exceso_de_velocidad","pat_enc":"cripto-para-vehicle"}'

check "sin Authorization, 401 sin necesidad de un JWT" \
  401 "$(alerts_status "" "${alerts_body}")"

alerts_expired_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${USER_SUB}\",\"exp\":$((now - 300))}")"
check "un JWT expirado se rechaza con 401" \
  401 "$(alerts_status "${alerts_expired_token}" "${alerts_body}")"

check "un JWT válido, firmado y sin vencer, pasa" \
  200 "$(alerts_status "${valid_token}" "${alerts_body}")"

alerts_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/alerts \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'Content-Type: application/json' \
  --data-binary "${alerts_body}")"

check_contains "Alert recibe X-User-Id con el sub del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${alerts_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el Authorization no se propaga al upstream (token offloading)" \
  "authorization" "$(printf '%s' "${alerts_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_contains "el body (alert_type + sobre HPKE) llega intacto al upstream" \
  "exceso_de_velocidad" "${alerts_upstream_view}"
check_contains "el criptograma de la patente llega intacto al upstream" \
  "cripto-para-vehicle" "${alerts_upstream_view}"

alerts_spoofed_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/alerts \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'X-User-Id: usuario-suplantado' \
  -H 'Content-Type: application/json' \
  --data-binary "${alerts_body}")"

check_contains "un X-User-Id forjado por el cliente se reemplaza por el del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${alerts_spoofed_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el X-User-Id forjado no llega al upstream" \
  "usuario-suplantado" "$(printf '%s' "${alerts_spoofed_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Escaneo de Patente (US-05): /internal/* no existe en Kong"

# `/internal/resolve-owner` (Alert → Vehicle) es tráfico interno directo:
# no hay ninguna Route en kong.yml que matchee `/internal/*`, así que a
# través del proxy tiene que dar 404 de Kong.
check "/internal/resolve-owner no tiene Route: 404" \
  404 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/internal/resolve-owner \
    -H 'Content-Type: application/json' \
    -d '{"pat_enc":"cripto-para-vehicle"}')"

echo
echo "Buzón de Alertas (US-07): JWT y Token Offloading en /alerts/inbox"

# Mismo usuario que en las secciones anteriores: el rate-limiting de esta
# Route es una instancia de plugin propia (Route distinta), así que reusar
# el sub no cruza cupos con /alerts ni con /vehicles. La verificación
# exhaustiva del límite de 20/min es una sección aparte, más abajo.
check "sin Authorization, 401 sin necesidad de un JWT" \
  401 "$(alerts_inbox_status "")"

inbox_expired_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${USER_SUB}\",\"exp\":$((now - 300))}")"
check "un JWT expirado se rechaza con 401" \
  401 "$(alerts_inbox_status "${inbox_expired_token}")"

check "un JWT válido, firmado y sin vencer, pasa" \
  200 "$(alerts_inbox_status "${valid_token}")"

inbox_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X GET http://127.0.0.1:8000/api/v1/alerts/inbox \
  -H "Authorization: Bearer ${valid_token}")"

check_contains "Alert recibe X-User-Id con el sub del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${inbox_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el Authorization no se propaga al upstream (token offloading)" \
  "authorization" "$(printf '%s' "${inbox_upstream_view}" | tr '[:upper:]' '[:lower:]')"

inbox_spoofed_view="$(docker exec "${GATEWAY}" curl -s \
  -X GET http://127.0.0.1:8000/api/v1/alerts/inbox \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'X-User-Id: usuario-suplantado')"

check_contains "un X-User-Id forjado por el cliente se reemplaza por el del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${inbox_spoofed_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el X-User-Id forjado no llega al upstream" \
  "usuario-suplantado" "$(printf '%s' "${inbox_spoofed_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Buzón de Alertas (US-07): rate limiting a 20/min, independiente del de /alerts"

# Prueba, de paso, la precedencia de rutas: si un GET a /alerts/inbox
# cayera por error en `alerts-route` (POST /alerts, 5/min), esta ráfaga
# habría dejado pasar sólo 5 requests, no 20. Sub propio para no arrastrar
# el cupo ya consumido en la sección anterior.
#
# Las 21 requests se disparan en paralelo (no en secuencia) a propósito: el
# contador de `rate-limiting` con policy=local usa una ventana fija alineada
# al reloj de pared (no relativa a la primera request), así que una ráfaga
# secuencial de 21 llamadas —cada una con el overhead de un `docker exec`—
# corre el riesgo real de cruzar el límite del minuto a mitad de camino y
# reiniciar el contador, dejando pasar la request 21 por pura casualidad de
# timing. En paralelo, las 21 llegan dentro de la misma ventana.
inbox_rl_user="9f1c2d3e-4b5a-4c6d-8e9f-0a1b2c3d4e5f"
inbox_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${inbox_rl_user}\",\"exp\":$((now + 300))}")"

rl_tmp="$(mktemp -d)"
for i in $(seq 1 21); do
  ( alerts_inbox_status "${inbox_rl_token}" > "${rl_tmp}/${i}" ) &
done
wait

rl_ok=0
rl_limited=0
for i in $(seq 1 21); do
  case "$(cat "${rl_tmp}/${i}")" in
    200) rl_ok=$((rl_ok + 1)) ;;
    429) rl_limited=$((rl_limited + 1)) ;;
  esac
done
rm -rf "${rl_tmp}"

check "de 21 requests en el mismo minuto, exactamente 20 pasan" 20 "${rl_ok}"
check "y exactamente 1 se rechaza con 429" 1 "${rl_limited}"

inbox_other_user="1a2b3c4d-5e6f-4789-9a0b-1c2d3e4f5a6b"
inbox_other_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${inbox_other_user}\",\"exp\":$((now + 300))}")"

check "un usuario distinto no comparte cupo con el que ya alcanzó el límite" \
  200 "$(alerts_inbox_status "${inbox_other_token}")"

echo
if (( failures > 0 )); then
  printf '\033[31m%d caso(s) fallaron\033[0m\n' "${failures}"
  echo
  echo "Logs del Gateway:"
  docker logs "${GATEWAY}" 2>&1 | grep -i "app-attestation" | tail -20
  exit 1
fi

printf '\033[32mTodos los casos de integración pasaron\033[0m\n'
