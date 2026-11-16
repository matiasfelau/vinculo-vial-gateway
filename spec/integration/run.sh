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
# Segundo Gateway y upstream dedicados a la sección de resiliencia (K2):
# aislados del Gateway principal para no interferir con el resto de la
# suite — ver esa sección, al final de "Casos".
readonly GATEWAY_SLOW=vv-it-gateway-slow
readonly SLOW_UPSTREAM=vv-it-slow-upstream
# Tercer Gateway y upstream controlable, para la sección de resiliencia del
# balanceo y del presupuesto de las llamadas a Google (ver "Resiliencia (Ola 5)").
readonly GATEWAY_RESILIENCE=vv-it-gateway-resilience
readonly FLAKY_UPSTREAM=vv-it-flaky-upstream
# Cuarto Gateway (sin sondeo activo de targets sanos, para que sólo el
# healthcheck pasivo pueda sacar un target del balanceo) y un upstream que
# arranca con el puerto cerrado, para la recuperación de targets marcados por
# el pasivo.
readonly GATEWAY_PASSIVE=vv-it-gateway-passive
readonly LATE_UPSTREAM=vv-it-late-upstream
# Quinto Gateway, con `KONG_TRUSTED_IPS` declarado, para simular el despliegue
# detrás de Nginx Proxy Manager (ver "Rutas de US-09: detrás de un proxy").
readonly GATEWAY_PROXY=vv-it-gateway-proxy
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
  docker rm -f "${GATEWAY}" "${STUB}" "${UPSTREAM}" \
    "${GATEWAY_SLOW}" "${SLOW_UPSTREAM}" "${GATEWAY_RESILIENCE}" "${FLAKY_UPSTREAM}" \
    "${GATEWAY_PASSIVE}" "${LATE_UPSTREAM}" "${GATEWAY_PROXY}" >/dev/null 2>&1 || true
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
  local token="$1" body="${2:-{}}"

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
  local token="$1" body="${2:-{}}"

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

# Manda un POST a /api/v1/notifications/tokens con el Bearer token dado
# (vacío = sin header Authorization) y devuelve el status HTTP. US-06: mismo
# par jwt + token-offloading que alerts_status, más rate-limiting a 10/día
# por X-User-Id (ese tercer plugin se verifica en su propia sección, no acá).
notifications_post_status() {
  local token="$1" body="${2:-{}}"

  if [[ -z "${token}" ]]; then
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST http://127.0.0.1:8000/api/v1/notifications/tokens \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  else
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST http://127.0.0.1:8000/api/v1/notifications/tokens \
      -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  fi
}

# Manda un DELETE a /api/v1/notifications/tokens con el Bearer token dado
# (vacío = sin header Authorization) y devuelve el status HTTP. US-06: mismo
# par jwt + token-offloading que notifications_post_status, pero SIN
# rate-limiting — esa ausencia se verifica en su propia sección, no acá.
notifications_delete_status() {
  local token="$1" body="${2:-{}}"

  if [[ -z "${token}" ]]; then
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X DELETE http://127.0.0.1:8000/api/v1/notifications/tokens \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  else
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X DELETE http://127.0.0.1:8000/api/v1/notifications/tokens \
      -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' \
      --data-binary "${body}"
  fi
}

# Manda `METHOD path` con el Bearer token dado y devuelve el status HTTP. US-08:
# el upstream de eco responde 200 a cualquier path, así que un 404 sólo puede
# ser de Kong (ninguna Route matcheó): es lo que distingue "ruteado" de "no
# ruteado" en la matriz de ruteo.
route_status() {
  local method="$1" path="$2" token="$3"

  if [[ "${method}" == "GET" ]]; then
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X GET "http://127.0.0.1:8000${path}" \
      -H "Authorization: Bearer ${token}"
  else
    docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X "${method}" "http://127.0.0.1:8000${path}" \
      -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' \
      --data-binary '{}'
  fi
}

# Igual que `route_status`, pero devuelve los headers de la respuesta en
# minúsculas. Sirve para identificar QUÉ Route atendió la request: cada una
# declara un `rate-limiting` propio y Kong expone su límite en
# `X-RateLimit-Limit-*` (`hide_client_headers: false`).
route_headers() {
  local method="$1" path="$2" token="$3"

  if [[ "${method}" == "GET" ]]; then
    docker exec "${GATEWAY}" curl -s -D - -o /dev/null \
      -X GET "http://127.0.0.1:8000${path}" \
      -H "Authorization: Bearer ${token}" | tr '[:upper:]' '[:lower:]'
  else
    docker exec "${GATEWAY}" curl -s -D - -o /dev/null \
      -X "${method}" "http://127.0.0.1:8000${path}" \
      -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' \
      --data-binary '{}' | tr '[:upper:]' '[:lower:]'
  fi
}

# Manda un body de `bytes` bytes aleatorios (octet-stream) y devuelve el status
# HTTP. El archivo se arma y se referencia dentro del contenedor, con un único
# `sh -c`, para no chocar con el límite de argumentos del shell del host ni con
# la conversión de rutas de Git Bash sobre `@/tmp/...`. El `; true` evita que
# `set -e` aborte la suite si curl corta la subida ante un 413 temprano.
sized_status() {
  local method="$1" path="$2" token="$3" bytes="$4"

  docker exec "${GATEWAY}" sh -c "
    head -c ${bytes} /dev/urandom > /tmp/sized.bin
    curl -s -o /dev/null -w '%{http_code}' -X ${method} 'http://127.0.0.1:8000${path}' \
      -H 'Authorization: Bearer ${token}' \
      -H 'Content-Type: application/octet-stream' -H 'Expect:' \
      --data-binary @/tmp/sized.bin
    true"
}

# Igual que `sized_status`, pero como el multipart de `POST /api/v1/alerts`
# (US-08): una parte `metadata` JSON y una parte `general` de `bytes` bytes. El
# Gateway no inspecciona ni valida el contenido: sólo cuenta el tamaño.
multipart_status() {
  local token="$1" bytes="$2"

  docker exec "${GATEWAY}" sh -c "
    printf '%s' '{\"attempt_id\":\"0f1e2d3c-4b5a-4968-8776-655443322110\",\"alert_type\":\"CRASHED\"}' > /tmp/meta.json
    head -c ${bytes} /dev/urandom > /tmp/part.bin
    curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/api/v1/alerts \
      -H 'Authorization: Bearer ${token}' -H 'Expect:' \
      -F 'metadata=@/tmp/meta.json;type=application/json' \
      -F 'general=@/tmp/part.bin;type=application/octet-stream'
    true"
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

# :31 devolvía 500 de forma intermitente en requests POST con body, una vez
# que la suite creció lo suficiente para exponerlo (no reproducible con pocas
# requests) — corregido en versiones más recientes de la imagen.
docker run -d --name "${UPSTREAM}" --network "${NETWORK}" \
  -e HTTP_PORT=8080 mendhak/http-https-echo:41 >/dev/null

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
  -e "NOTIFICATION_SERVICE_URL=http://${UPSTREAM}:8080" \
  -e "BENEFITS_SERVICE_URL=http://${UPSTREAM}:8080" \
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
# Un 5xx de Google no es un veredicto negativo: es la dependencia caída.
# Tratarlo como invalid_attestation le haría creer al cliente que SU
# dispositivo es el problema, cuando en realidad es transitorio y ajeno a él.
check "un error 5xx de Google se traduce en 502, no en un veredicto negativo" \
  502 "$(signup_status "BOOM" '{}')"

boom_rejection="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/signup \
  -H 'X-App-Attestation: BOOM' -d '{}')"

check_contains "la falla de dependencia declara el error del contrato" \
  '"error":"bad_gateway"' "${boom_rejection}"
check_contains "la falla de dependencia declara el motivo público del contrato" \
  '"reason":"dependency_error"' "${boom_rejection}"
check_not_contains "la falla de dependencia no filtra el motivo interno" \
  "playintegrity" "${boom_rejection}"

# Google rechaza NUESTRO access token: defecto propio de configuración, no
# un veredicto sobre el dispositivo del cliente ni Google caído. Expulsar al
# cliente con un 403 acá es el bug que este caso fija como regresión.
check "credenciales propias inválidas frente a Google se traducen en 500" \
  500 "$(signup_status "UNAUTHORIZED" '{}')"

unauthorized_rejection="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/auth/signup \
  -H 'X-App-Attestation: UNAUTHORIZED' -d '{}')"

check_contains "el defecto propio declara el error del contrato" \
  '"error":"internal_error"' "${unauthorized_rejection}"
check_contains "el defecto propio declara el motivo público del contrato" \
  '"reason":"gateway_fault"' "${unauthorized_rejection}"
check_not_contains "el defecto propio no filtra el motivo interno" \
  "playintegrity" "${unauthorized_rejection}"

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
echo "Ruteo exacto (US-08): alerts-route y vehicles-route no capturan subrecursos"

# Usuario dedicado: el cupo de `alerts-route` (5/min) es por X-User-Id, y USER_SUB
# ya consumió parte del suyo más arriba.
exact_user="6d7e8f90-a1b2-4c3d-8e4f-5a6b7c8d9e0f"
exact_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${exact_user}\",\"exp\":$((now + 300))}")"
exact_uuid="0f1e2d3c-4b5a-4968-8776-655443322110"

check "POST /api/v1/alerts sigue ruteando a alerts-route" \
  200 "$(route_status POST /api/v1/alerts "${exact_token}")"
check_contains "POST /api/v1/alerts lo atiende alerts-route (5/min, 10/h)" \
  "x-ratelimit-limit-hour: 10" "$(route_headers POST /api/v1/alerts "${exact_token}")"

check "POST /api/v1/alerts/ (barra final) ya no matchea alerts-route" \
  404 "$(route_status POST /api/v1/alerts/ "${exact_token}")"
check "POST /api/v1/alerts/{subrecurso} inexistente no cae en alerts-route" \
  404 "$(route_status POST /api/v1/alerts/inexistente "${exact_token}")"
check "POST /api/v1/alerts/{uuid} no cae en alerts-route" \
  404 "$(route_status POST "/api/v1/alerts/${exact_uuid}" "${exact_token}")"

check "GET /api/v1/alerts/inbox sigue ruteando a alerts-inbox-route" \
  200 "$(route_status GET /api/v1/alerts/inbox "${exact_token}")"

check "POST /api/v1/vehicles sigue ruteando a vehicles-route" \
  200 "$(route_status POST /api/v1/vehicles "${exact_token}")"
check "POST /api/v1/vehicles/ (barra final) ya no matchea vehicles-route" \
  404 "$(route_status POST /api/v1/vehicles/ "${exact_token}")"
check "POST /api/v1/vehicles/check (eliminado en US-08) ya no tiene Route" \
  404 "$(route_status POST /api/v1/vehicles/check "${exact_token}")"

echo
echo "Rutas de US-08: matriz de ruteo"

# Cada Route nueva declara un `rate-limiting` propio, y Kong expone su límite
# en `X-RateLimit-Limit-*`: es lo que identifica QUÉ Route atendió.
u8_user="3a4b5c6d-7e8f-4a9b-8c0d-1e2f3a4b5c6d"
u8_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u8_user}\",\"exp\":$((now + 300))}")"
u8_uuid="0f1e2d3c-4b5a-4968-8776-655443322110"
u8_evidence="/api/v1/alerts/${u8_uuid}/evidence"
u8_feedback="/api/v1/alerts/${u8_uuid}/feedback"
u8_report="/api/v1/alerts/${u8_uuid}/report"

attempts_headers="$(route_headers POST /api/v1/alerts/attempts "${u8_token}")"
check_contains "POST /api/v1/alerts/attempts → alerts-attempts-route (10/min)" \
  "x-ratelimit-limit-minute: 10" "${attempts_headers}"
check_contains "POST /api/v1/alerts/attempts → alerts-attempts-route (30/h)" \
  "x-ratelimit-limit-hour: 30" "${attempts_headers}"

check "GET /api/v1/alerts/{uuid}/evidence/PLATE/0 → alerts-evidence-route" \
  200 "$(route_status GET "${u8_evidence}/PLATE/0" "${u8_token}")"
for role in GENERAL PLATE DETAIL CONTEXT; do
  check "GET .../evidence/${role}/2 rutea" \
    200 "$(route_status GET "${u8_evidence}/${role}/2" "${u8_token}")"
done
check "GET .../evidence/FOO/0 (rol fuera del catálogo) → 404" \
  404 "$(route_status GET "${u8_evidence}/FOO/0" "${u8_token}")"
check "GET .../evidence/plate/0 (rol en minúsculas) → 404" \
  404 "$(route_status GET "${u8_evidence}/plate/0" "${u8_token}")"
check "GET .../evidence/PLATE/10 (índice de dos dígitos) → 404" \
  404 "$(route_status GET "${u8_evidence}/PLATE/10" "${u8_token}")"
check "GET .../evidence/PLATE/0/extra → 404" \
  404 "$(route_status GET "${u8_evidence}/PLATE/0/extra" "${u8_token}")"
check "GET /api/v1/alerts/{id corto}/evidence/PLATE/0 → 404" \
  404 "$(route_status GET /api/v1/alerts/1234/evidence/PLATE/0 "${u8_token}")"
check "POST .../evidence/PLATE/0 (método incorrecto) → 404" \
  404 "$(route_status POST "${u8_evidence}/PLATE/0" "${u8_token}")"

check_contains "PUT .../feedback → alerts-feedback-route (30/min)" \
  "x-ratelimit-limit-minute: 30" "$(route_headers PUT "${u8_feedback}" "${u8_token}")"
check "POST .../feedback (método incorrecto) → 404" \
  404 "$(route_status POST "${u8_feedback}" "${u8_token}")"
check "PUT /api/v1/alerts/{id corto}/feedback → 404" \
  404 "$(route_status PUT /api/v1/alerts/1234/feedback "${u8_token}")"

report_headers="$(route_headers POST "${u8_report}" "${u8_token}")"
check_contains "POST .../report → alerts-report-route (5/min)" \
  "x-ratelimit-limit-minute: 5" "${report_headers}"
check_contains "POST .../report → alerts-report-route (20/h)" \
  "x-ratelimit-limit-hour: 20" "${report_headers}"
check "PUT .../report (método incorrecto) → 404" \
  404 "$(route_status PUT "${u8_report}" "${u8_token}")"
check "POST .../report/ (barra final) → 404" \
  404 "$(route_status POST "${u8_report}/" "${u8_token}")"

check "POST /api/v1/alerts sigue en alerts-route" \
  200 "$(route_status POST /api/v1/alerts "${u8_token}")"
check "GET /api/v1/alerts/inbox sigue en alerts-inbox-route" \
  200 "$(route_status GET /api/v1/alerts/inbox "${u8_token}")"
check "POST /api/v1/vehicles sigue en vehicles-route" \
  200 "$(route_status POST /api/v1/vehicles "${u8_token}")"
check "POST /api/v1/vehicles/check → 404" \
  404 "$(route_status POST /api/v1/vehicles/check "${u8_token}")"

echo
echo "Rutas de US-08: seguridad (JWT y Token Offloading)"

u8_expired="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u8_user}\",\"exp\":$((now - 300))}")"
for target in "POST /api/v1/alerts/attempts" "GET ${u8_evidence}/PLATE/0" \
  "PUT ${u8_feedback}" "POST ${u8_report}"; do
  method="${target%% *}"; path="${target#* }"

  check "sin Authorization, 401: ${method} ${path##*/}" \
    401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X "${method}" "http://127.0.0.1:8000${path}" \
      -H 'Content-Type: application/json' -d '{}')"
  check "JWT expirado, 401: ${method} ${path##*/}" \
    401 "$(route_status "${method}" "${path}" "${u8_expired}")"

  spoofed_view="$(docker exec "${GATEWAY}" curl -s \
    -X "${method}" "http://127.0.0.1:8000${path}" \
    -H "Authorization: Bearer ${u8_token}" \
    -H 'X-User-Id: usuario-suplantado' \
    -H 'Content-Type: application/json' -d '{}' | tr '[:upper:]' '[:lower:]')"
  check_contains "X-User-Id del JWT llega al upstream: ${method} ${path##*/}" \
    "\"x-user-id\": \"${u8_user}\"" "${spoofed_view}"
  check_not_contains "el X-User-Id forjado se descarta: ${method} ${path##*/}" \
    "usuario-suplantado" "${spoofed_view}"
  check_not_contains "el Authorization no se propaga: ${method} ${path##*/}" \
    "authorization" "${spoofed_view}"
done

echo
echo "Rutas de US-08: límites de tamaño"

u8_size_user="5c6d7e8f-9a0b-4c1d-8e2f-3a4b5c6d7e8f"
u8_size_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u8_size_user}\",\"exp\":$((now + 300))}")"

# `alerts-route`: 5 MB = 5242880 bytes. 5,1 MB (5347738) se rechaza; 4,8 MB
# (5033165) pasa. El 413 de Kong no gasta cupo de rate limit.
check "multipart de 5,1 MB → 413" \
  413 "$(multipart_status "${u8_size_token}" 5347738)"
check "multipart de 4,8 MB pasa" \
  200 "$(multipart_status "${u8_size_token}" 5033165)"

check "attempts de 9000 bytes (> 8 KB) → 413" \
  413 "$(sized_status POST /api/v1/alerts/attempts "${u8_size_token}" 9000)"
check "attempts de 7000 bytes (≤ 8 KB) pasa" \
  200 "$(sized_status POST /api/v1/alerts/attempts "${u8_size_token}" 7000)"
check "feedback de 1500 bytes (> 1 KB) → 413" \
  413 "$(sized_status PUT "${u8_feedback}" "${u8_size_token}" 1500)"
check "feedback de 900 bytes (≤ 1 KB) pasa" \
  200 "$(sized_status PUT "${u8_feedback}" "${u8_size_token}" 900)"
check "report de 1500 bytes (> 1 KB) → 413" \
  413 "$(sized_status POST "${u8_report}" "${u8_size_token}" 1500)"
check "report de 900 bytes (≤ 1 KB) pasa" \
  200 "$(sized_status POST "${u8_report}" "${u8_size_token}" 900)"

echo
echo "Rutas de US-08: rate limiting por X-User-Id"

# Mismo guard de reloj que el de /alerts/inbox: el contador `local` usa una
# ventana fija alineada al minuto de reloj; si la ráfaga la cruzara, se
# reiniciaría y enmascararía el corte esperado.
u8_rl_seconds="$(date +%S)"; u8_rl_seconds=$((10#${u8_rl_seconds}))
if (( u8_rl_seconds > 30 )); then
  u8_rl_sleep=$((60 - u8_rl_seconds))
  echo "  (esperando ${u8_rl_sleep}s al próximo minuto de reloj, para no cruzar la ventana del rate-limiting a mitad de la ráfaga)"
  sleep "${u8_rl_sleep}"
fi

u8_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d\",\"exp\":$((now + 300))}")"
u8_rl_other="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"8b9c0d1e-2f3a-4b4c-9d5e-6f7a8b9c0d1e\",\"exp\":$((now + 300))}")"

for _ in $(seq 1 9); do
  route_status POST /api/v1/alerts/attempts "${u8_rl_token}" >/dev/null
done
check "el attempt 10 del minuto todavía pasa" \
  200 "$(route_status POST /api/v1/alerts/attempts "${u8_rl_token}")"
check "el attempt 11 del minuto → 429" \
  429 "$(route_status POST /api/v1/alerts/attempts "${u8_rl_token}")"
check "otro usuario no comparte el contador de attempts" \
  200 "$(route_status POST /api/v1/alerts/attempts "${u8_rl_other}")"

for _ in $(seq 1 4); do
  route_status POST "${u8_report}" "${u8_rl_token}" >/dev/null
done
check "el report 5 del minuto todavía pasa" \
  200 "$(route_status POST "${u8_report}" "${u8_rl_token}")"
check "el report 6 del minuto → 429" \
  429 "$(route_status POST "${u8_report}" "${u8_rl_token}")"
check "otro usuario no comparte el contador de report" \
  200 "$(route_status POST "${u8_report}" "${u8_rl_other}")"

echo
echo "Rutas de US-09: matriz de ruteo (alerts-sent-route y alerts-seen-route)"

# El upstream de eco responde 200 a todo (incluido el PUT .../seen, que en
# Alert devuelve 204): acá sólo se verifica QUÉ Route atiende cada request, no
# el status del servicio real.
u9_user="2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
u9_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u9_user}\",\"exp\":$((now + 300))}")"
u9_expired="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u9_user}\",\"exp\":$((now - 300))}")"
u9_uuid="0f1e2d3c-4b5a-4968-8776-655443322110"
u9_sent="/api/v1/alerts/sent"
u9_seen="/api/v1/alerts/${u9_uuid}/seen"

check "GET /api/v1/alerts/sent → alerts-sent-route" \
  200 "$(route_status GET "${u9_sent}" "${u9_token}")"
check_contains "GET /api/v1/alerts/sent lo atiende alerts-sent-route (20/min)" \
  "x-ratelimit-limit-minute: 20" "$(route_headers GET "${u9_sent}" "${u9_token}")"
check "GET /api/v1/alerts/sent con limit y cursor rutea igual" \
  200 "$(route_status GET "${u9_sent}?limit=50&cursor=abc" "${u9_token}")"
check "POST /api/v1/alerts/sent (método incorrecto) → 404" \
  404 "$(route_status POST "${u9_sent}" "${u9_token}")"
check "GET /api/v1/alerts/sent/ (barra final) → 404" \
  404 "$(route_status GET "${u9_sent}/" "${u9_token}")"
check "GET /api/v1/alerts/sentinel (mismo prefijo) → 404" \
  404 "$(route_status GET /api/v1/alerts/sentinel "${u9_token}")"
check "GET /api/v1/alerts/sent/{uuid} → 404" \
  404 "$(route_status GET "${u9_sent}/${u9_uuid}" "${u9_token}")"

u9_seen_headers="$(route_headers PUT "${u9_seen}" "${u9_token}")"
check "PUT /api/v1/alerts/{uuid}/seen → alerts-seen-route" \
  200 "$(route_status PUT "${u9_seen}" "${u9_token}")"
check_contains "PUT .../seen lo atiende alerts-seen-route (30/min)" \
  "x-ratelimit-limit-minute: 30" "${u9_seen_headers}"
check "POST .../seen (método incorrecto) → 404" \
  404 "$(route_status POST "${u9_seen}" "${u9_token}")"
check "GET .../seen (método incorrecto) → 404" \
  404 "$(route_status GET "${u9_seen}" "${u9_token}")"
check "PUT /api/v1/alerts/{id corto}/seen → 404" \
  404 "$(route_status PUT /api/v1/alerts/1234/seen "${u9_token}")"
check "PUT .../seen/ (barra final) → 404" \
  404 "$(route_status PUT "${u9_seen}/" "${u9_token}")"
check "PUT .../seen/extra → 404" \
  404 "$(route_status PUT "${u9_seen}/extra" "${u9_token}")"

# Ninguna Route existente captura los paths nuevos, ni al revés: cada una sigue
# atendiendo lo suyo.
check_contains "POST /api/v1/alerts sigue en alerts-route (5/min, 10/h)" \
  "x-ratelimit-limit-hour: 10" "$(route_headers POST /api/v1/alerts "${u9_token}")"
check_contains "GET /api/v1/alerts/inbox sigue en alerts-inbox-route (20/min, sin hora)" \
  "x-ratelimit-limit-minute: 20" "$(route_headers GET /api/v1/alerts/inbox "${u9_token}")"
check "POST /api/v1/alerts/attempts sigue en alerts-attempts-route" \
  200 "$(route_status POST /api/v1/alerts/attempts "${u9_token}")"
check "PUT .../feedback sigue en alerts-feedback-route" \
  200 "$(route_status PUT "/api/v1/alerts/${u9_uuid}/feedback" "${u9_token}")"
check "POST .../report sigue en alerts-report-route" \
  200 "$(route_status POST "/api/v1/alerts/${u9_uuid}/report" "${u9_token}")"

echo
echo "Rutas de US-09: seguridad (JWT y Token Offloading)"

for target in "GET ${u9_sent}" "PUT ${u9_seen}"; do
  method="${target%% *}"; path="${target#* }"

  check "sin Authorization, 401: ${method} ${path##*/}" \
    401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X "${method}" "http://127.0.0.1:8000${path}")"
  check "JWT expirado, 401: ${method} ${path##*/}" \
    401 "$(route_status "${method}" "${path}" "${u9_expired}")"

  u9_spoofed_view="$(docker exec "${GATEWAY}" curl -s \
    -X "${method}" "http://127.0.0.1:8000${path}" \
    -H "Authorization: Bearer ${u9_token}" \
    -H 'X-User-Id: usuario-suplantado' | tr '[:upper:]' '[:lower:]')"
  check_contains "X-User-Id del JWT llega al upstream: ${method} ${path##*/}" \
    "\"x-user-id\": \"${u9_user}\"" "${u9_spoofed_view}"
  check_not_contains "el X-User-Id forjado se descarta: ${method} ${path##*/}" \
    "usuario-suplantado" "${u9_spoofed_view}"
  check_not_contains "el Authorization no se propaga: ${method} ${path##*/}" \
    "authorization" "${u9_spoofed_view}"
done

echo
echo "Rutas de US-09: rate limiting por X-User-Id (sent 20/min, seen 30/min)"

# Mismo guard de reloj que el de /alerts/inbox: la ventana fija del contador
# `local` se alinea al minuto de reloj y, si la ráfaga la cruzara, se
# reiniciaría y enmascararía el corte esperado. Cada ráfaga espera por su
# cuenta (`$1` = segundos máximos que puede pasar del minuto de reloj al
# arrancar), porque juntas no entran en un mismo minuto.
u9_wait_clock_minute() {
  local now_seconds
  now_seconds="$(date +%S)"; now_seconds=$((10#${now_seconds}))
  if (( now_seconds > $1 )); then
    echo "  (esperando $((60 - now_seconds))s al próximo minuto de reloj, para no cruzar la ventana del rate-limiting a mitad de la ráfaga)"
    sleep $((60 - now_seconds))
  fi
}

u9_wait_clock_minute 25

u9_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"4d5e6f7a-8b9c-4d0e-9f1a-2b3c4d5e6f7a\",\"exp\":$((now + 300))}")"
u9_rl_other="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b\",\"exp\":$((now + 300))}")"

# Si un GET a /alerts/sent cayera en `alerts-route` (5/min), esta ráfaga habría
# fallado mucho antes del vigésimo.
for _ in $(seq 1 19); do
  route_status GET "${u9_sent}" "${u9_rl_token}" >/dev/null
done
check "el request 20 de sent en el minuto todavía pasa" \
  200 "$(route_status GET "${u9_sent}" "${u9_rl_token}")"
check "el request 21 de sent en el minuto → 429" \
  429 "$(route_status GET "${u9_sent}" "${u9_rl_token}")"
check "otro usuario no comparte el contador de sent" \
  200 "$(route_status GET "${u9_sent}" "${u9_rl_other}")"

u9_wait_clock_minute 15
for _ in $(seq 1 29); do
  route_status PUT "${u9_seen}" "${u9_rl_token}" >/dev/null
done
check "el request 30 de seen en el minuto todavía pasa" \
  200 "$(route_status PUT "${u9_seen}" "${u9_rl_token}")"
check "el request 31 de seen en el minuto → 429" \
  429 "$(route_status PUT "${u9_seen}" "${u9_rl_token}")"
check "otro usuario no comparte el contador de seen" \
  200 "$(route_status PUT "${u9_seen}" "${u9_rl_other}")"

echo
echo "Rutas de US-09: detrás de un proxy (KONG_TRUSTED_IPS)"

# Nginx Proxy Manager termina el TLS delante de Kong y reenvía la IP real en
# `X-Forwarded-For`. El proxy se simula con el propio curl dentro del
# contenedor: su peer es 127.0.0.1, que es lo que se declara de confianza.
# Con la lista vacía (el Gateway principal) el header del cliente se ignora.
echo "==> Levantando un Gateway con KONG_TRUSTED_IPS"
docker run -d --name "${GATEWAY_PROXY}" --network "${NETWORK}"   --env-file "$(to_host_path "${REPO_ROOT}/.env.example")"   -v "$(to_host_path "${sa_dir}/google-service-account.json"):/etc/vinculo-vial/google-service-account.json:ro"   -e "IDENTITY_SERVICE_URL=http://${UPSTREAM}:8080"   -e "VEHICLE_SERVICE_URL=http://${UPSTREAM}:8080"   -e "ALERT_SERVICE_URL=http://${UPSTREAM}:8080"   -e "NOTIFICATION_SERVICE_URL=http://${UPSTREAM}:8080"   -e "BENEFITS_SERVICE_URL=http://${UPSTREAM}:8080"   -e "PLAY_INTEGRITY_URL=http://${STUB}:8080"   -e "PLAY_PACKAGE_NAME=${PACKAGE_NAME}"   -e ATTESTATION_SOURCE=google   -e ATTESTATION_SSL_VERIFY=false   -e "JWT_PUBLIC_KEY=${jwt_public_key_escaped}"   -e "JWT_ISSUER=${JWT_ISSUER}"   -e "KONG_TRUSTED_IPS=127.0.0.1/32"   vinculo-vial-gateway:integration >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${GATEWAY_PROXY}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${GATEWAY_PROXY}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
  echo "El Gateway con KONG_TRUSTED_IPS no llegó a estar healthy:"
  docker logs "${GATEWAY_PROXY}"
  exit 1
fi

u9_proxy_headers=(-H "Authorization: Bearer ${u9_token}" -H 'X-Forwarded-For: 203.0.113.7')
u9_proxy_view="$(docker exec "${GATEWAY_PROXY}" curl -s   -X GET "http://127.0.0.1:8000${u9_sent}" "${u9_proxy_headers[@]}" | tr '[:upper:]' '[:lower:]')"
check_contains "con proxy de confianza, Kong toma la IP real del X-Forwarded-For (sent)"   "\"x-real-ip\": \"203.0.113.7\"" "${u9_proxy_view}"
check_contains "con proxy de confianza, X-User-Id sigue llegando del JWT (sent)"   "\"x-user-id\": \"${u9_user}\"" "${u9_proxy_view}"
check "con proxy de confianza, PUT .../seen sigue ruteando"   200 "$(docker exec "${GATEWAY_PROXY}" curl -s -o /dev/null -w '%{http_code}'     -X PUT "http://127.0.0.1:8000${u9_seen}" "${u9_proxy_headers[@]}")"
check "con proxy de confianza, sin JWT sigue siendo 401"   401 "$(docker exec "${GATEWAY_PROXY}" curl -s -o /dev/null -w '%{http_code}'     -X GET "http://127.0.0.1:8000${u9_sent}" -H 'X-Forwarded-For: 203.0.113.7')"

u9_direct_view="$(docker exec "${GATEWAY}" curl -s   -X GET "http://127.0.0.1:8000${u9_sent}" "${u9_proxy_headers[@]}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "sin proxy de confianza, el X-Forwarded-For del cliente se ignora"   "\"x-real-ip\": \"203.0.113.7\"" "${u9_direct_view}"

echo
echo "Baja de cuenta (US-11): matriz de ruteo (users-me-delete-route)"

# El cupo de la baja es de 3/min por usuario, y cada request ruteado a la Route
# lo consume (un 404 de Kong, un 401 o un 413 no: cortan antes de
# `rate-limiting`). Por eso cada grupo de requests válidos usa su propio
# usuario, en lugar de reutilizar uno y chocar con el 429.
u11_me="/api/v1/users/me"
u11_user="3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"
u11_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u11_user}\",\"exp\":$((now + 300))}")"
u11_expired="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u11_user}\",\"exp\":$((now - 300))}")"
u11_status_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"6f7a8b9c-0d1e-4f2a-8b3c-4d5e6f7a8b9c\",\"exp\":$((now + 300))}")"
u11_size_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d\",\"exp\":$((now + 300))}")"

# Un solo request devuelve a la vez el status y los headers de la Route que lo
# atendió: cada Route declara su propio `rate-limiting`, y Kong expone su
# límite en `X-RateLimit-Limit-*`.
u11_headers="$(route_headers DELETE "${u11_me}" "${u11_token}")"
check_contains "DELETE /api/v1/users/me → users-me-delete-route" \
  "http/1.1 200" "${u11_headers}"
check_contains "DELETE /api/v1/users/me lo atiende users-me-delete-route (3/min)" \
  "x-ratelimit-limit-minute: 3" "${u11_headers}"
check_contains "DELETE /api/v1/users/me lo atiende users-me-delete-route (10/h)" \
  "x-ratelimit-limit-hour: 10" "${u11_headers}"

# Los demás métodos sobre el mismo path no tienen Route: sólo el GET del
# scaffold `identity-profile`, que sigue como estaba.
check "PUT /api/v1/users/me (método sin Route) → 404" \
  404 "$(route_status PUT "${u11_me}" "${u11_token}")"
check "POST /api/v1/users/me (método sin Route) → 404" \
  404 "$(route_status POST "${u11_me}" "${u11_token}")"
check "PATCH /api/v1/users/me (método sin Route) → 404" \
  404 "$(route_status PATCH "${u11_me}" "${u11_token}")"

# Path exacto: la Route no captura subrecursos ni paths con el mismo prefijo.
check "DELETE /api/v1/users/me/ (barra final) → 404" \
  404 "$(route_status DELETE "${u11_me}/" "${u11_token}")"
check "DELETE /api/v1/users/me/extra → 404" \
  404 "$(route_status DELETE "${u11_me}/extra" "${u11_token}")"
check "DELETE /api/v1/users/mex (mismo prefijo) → 404" \
  404 "$(route_status DELETE /api/v1/users/mex "${u11_token}")"

# Ninguna Route existente captura el path nuevo, ni al revés.
u11_profile_view="$(docker exec "${GATEWAY}" curl -s \
  -X GET "http://127.0.0.1:8000${u11_me}" \
  -H "Authorization: Bearer ${u11_token}" | tr '[:upper:]' '[:lower:]')"
check_contains "GET /api/v1/users/me sigue en identity-profile (X-User-Hash)" \
  "\"x-user-hash\":" "${u11_profile_view}"
check_not_contains "GET /api/v1/users/me no pasa por users-me-delete-route (sin X-User-Id)" \
  "\"x-user-id\":" "${u11_profile_view}"
check "DELETE /api/v1/notifications/tokens sigue en notification-tokens-delete-route" \
  200 "$(route_status DELETE /api/v1/notifications/tokens "${u11_token}")"

echo
echo "Baja de cuenta (US-11): seguridad (JWT y Token Offloading)"

check "sin Authorization, 401: DELETE /users/me" \
  401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:8000${u11_me}" \
    -H 'Content-Type: application/json' --data-binary '{"password":"x"}')"
check "JWT expirado, 401: DELETE /users/me" \
  401 "$(route_status DELETE "${u11_me}" "${u11_expired}")"
check "JWT mal formado, 401: DELETE /users/me" \
  401 "$(route_status DELETE "${u11_me}" "no-es-un-jwt")"

u11_spoofed_view="$(docker exec "${GATEWAY}" curl -s \
  -X DELETE "http://127.0.0.1:8000${u11_me}" \
  -H "Authorization: Bearer ${u11_token}" \
  -H 'X-User-Id: usuario-suplantado' \
  -H 'Content-Type: application/json' \
  --data-binary '{"password":"contrasena-de-prueba"}' | tr '[:upper:]' '[:lower:]')"
check_contains "X-User-Id del JWT llega al upstream: DELETE /users/me" \
  "\"x-user-id\": \"${u11_user}\"" "${u11_spoofed_view}"
check_not_contains "el X-User-Id forjado se descarta: DELETE /users/me" \
  "usuario-suplantado" "${u11_spoofed_view}"
check_not_contains "el Authorization no se propaga: DELETE /users/me" \
  "authorization" "${u11_spoofed_view}"
check_contains "el body con la contraseña se reenvía sin tocar: DELETE /users/me" \
  "contrasena-de-prueba" "${u11_spoofed_view}"

echo
echo "Baja de cuenta (US-11): las respuestas de Identity se propagan"

# El upstream de eco devuelve el status que pide `x-set-response-status-code`.
# El Gateway no transforma las respuestas de esta Route: un 204 o un 401 de
# Identity (`INVALID_PASSWORD`) llegan al cliente tal cual.
check "el 204 de Identity se propaga" \
  204 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:8000${u11_me}" \
    -H "Authorization: Bearer ${u11_status_token}" \
    -H 'Content-Type: application/json' \
    -H 'x-set-response-status-code: 204' \
    --data-binary '{"password":"x"}')"
check "el 401 INVALID_PASSWORD de Identity se propaga" \
  401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:8000${u11_me}" \
    -H "Authorization: Bearer ${u11_status_token}" \
    -H 'Content-Type: application/json' \
    -H 'x-set-response-status-code: 401' \
    --data-binary '{"password":"x"}')"

echo
echo "Baja de cuenta (US-11): límite de tamaño (1 KB)"

# El 413 de Kong corta antes de `rate-limiting` y no gasta cupo.
check "baja de 1500 bytes (> 1 KB) → 413" \
  413 "$(sized_status DELETE "${u11_me}" "${u11_size_token}" 1500)"
check "baja de 900 bytes (≤ 1 KB) pasa" \
  200 "$(sized_status DELETE "${u11_me}" "${u11_size_token}" 900)"

echo
echo "Baja de cuenta (US-11): rate limiting por X-User-Id (3/min)"

# Mismo guard de reloj que el de US-09: la ventana fija del contador `local` se
# alinea al minuto de reloj y, si la ráfaga la cruzara, se reiniciaría y
# enmascararía el corte esperado.
u9_wait_clock_minute 40

u11_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"8b9c0d1e-2f3a-4b4c-8d5e-6f7a8b9c0d1e\",\"exp\":$((now + 300))}")"
u11_rl_other="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"9c0d1e2f-3a4b-4c5d-9e6f-7a8b9c0d1e2f\",\"exp\":$((now + 300))}")"

for _ in $(seq 1 2); do
  route_status DELETE "${u11_me}" "${u11_rl_token}" >/dev/null
done
check "la baja 3 del minuto todavía pasa" \
  200 "$(route_status DELETE "${u11_me}" "${u11_rl_token}")"
check "la baja 4 del minuto → 429" \
  429 "$(route_status DELETE "${u11_me}" "${u11_rl_token}")"
check "otro usuario no comparte el contador de la baja" \
  200 "$(route_status DELETE "${u11_me}" "${u11_rl_other}")"

echo
echo "Email y recuperación de contraseña (US-13): rutas públicas"

# Cinco Routes sin `jwt`, con el perímetro de signup/signin (descarte de
# `X-User-Hash`/`X-User-Id`, `app-attestation`, techo de body y rate limit por
# IP). Cada Route de 3/min atiende como máximo 3 requests de esta sección por
# ventana: por eso cada request cumple varios chequeos a la vez y la sección
# arranca con un guard de reloj.
u13_routes=(
  "/api/v1/auth/email-verifications|3|10"
  "/api/v1/auth/email-verifications/confirm|10|30"
  "/api/v1/auth/password-resets|3|10"
  "/api/v1/auth/password-resets/confirm|10|30"
  "/api/v1/auth/password-resets/complete|3|10"
)

# POST con una atestación válida ligada a un body propio (el anti-replay
# rechazaría un body repetido). Devuelve status y headers en minúsculas, y
# después el eco del upstream. Los argumentos extra van directo a curl.
u13_post_full() {
  local path="$1"; shift
  local body="{\"ephemeral_public_key\":\"U13$(date +%s%N)${RANDOM}\",\"ciphertext\":\"CCCC\"}"

  docker exec "${GATEWAY}" curl -s -D - -X POST "http://127.0.0.1:8000${path}" \
    -H "X-App-Attestation: $(body_hash "${body}")" \
    -H 'Content-Type: application/json' "$@" \
    --data-binary "${body}" | tr '[:upper:]' '[:lower:]'
}

u13_post() {
  local path="$1" body="{\"ephemeral_public_key\":\"U13$(date +%s%N)${RANDOM}\",\"ciphertext\":\"CCCC\"}"

  docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST "http://127.0.0.1:8000${path}" \
    -H "X-App-Attestation: $(body_hash "${body}")" \
    -H 'Content-Type: application/json' \
    --data-binary "${body}"
}

# Body de `bytes` bytes con una atestación que no hace falta que sea válida: lo
# que se mide es si el techo de la Route lo corta (413) o lo deja llegar a la
# atestación (403).
u13_sized_status() {
  local path="$1" bytes="$2"

  docker exec "${GATEWAY}" sh -c "
    head -c ${bytes} /dev/urandom > /tmp/u13.bin
    curl -s -o /dev/null -w '%{http_code}' -X POST 'http://127.0.0.1:8000${path}' \
      -H 'X-App-Attestation: no-hace-falta-que-sea-valido' \
      -H 'Content-Type: application/octet-stream' -H 'Expect:' \
      --data-binary @/tmp/u13.bin
    true"
}

u9_wait_clock_minute 30

for u13_entry in "${u13_routes[@]}"; do
  IFS='|' read -r u13_path u13_minute u13_hour <<< "${u13_entry}"

  # Un solo request: ruteo, cupo propio, atestación válida, descarte de los
  # headers de identidad forjados y body intacto.
  u13_view="$(u13_post_full "${u13_path}" \
    -H 'X-User-Id: usuario-suplantado' -H 'X-User-Hash: hash-suplantado')"

  check_contains "POST ${u13_path} con atestación válida llega al upstream" \
    "http/1.1 200" "${u13_view}"
  check_contains "POST ${u13_path} lo atiende su propia Route (${u13_minute}/min)" \
    "x-ratelimit-limit-minute: ${u13_minute}" "${u13_view}"
  check_contains "POST ${u13_path} lo atiende su propia Route (${u13_hour}/h)" \
    "x-ratelimit-limit-hour: ${u13_hour}" "${u13_view}"
  check_not_contains "el X-User-Id forjado se descarta: ${u13_path}" \
    "usuario-suplantado" "${u13_view}"
  check_not_contains "el X-User-Hash forjado se descarta: ${u13_path}" \
    "hash-suplantado" "${u13_view}"
  check_not_contains "el token de atestación no se propaga: ${u13_path}" \
    "x-app-attestation" "${u13_view}"
  check_contains "el body llega intacto al upstream: ${u13_path}" \
    "cccc" "${u13_view}"
done

echo
echo "Email y recuperación de contraseña (US-13): atestación obligatoria"

u13_google_before="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"
for u13_entry in "${u13_routes[@]}"; do
  IFS='|' read -r u13_path _ _ <<< "${u13_entry}"
  check "sin header de atestación, 403: ${u13_path}" \
    403 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X POST "http://127.0.0.1:8000${u13_path}" -d '{}')"
done
u13_google_after="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"
check "el rechazo sin header no llama a Google" \
  "${u13_google_before}" "${u13_google_after}"

echo
echo "Email y recuperación de contraseña (US-13): path exacto"

# Un path de prefijo capturaría el subrecurso con el cupo y el techo del padre.
for u13_path in \
  /api/v1/auth/email-verifications/ \
  /api/v1/auth/email-verifications/extra \
  /api/v1/auth/email-verifications/confirm/ \
  /api/v1/auth/email-verifications/confirm/extra \
  /api/v1/auth/password-resets/ \
  /api/v1/auth/password-resets/extra \
  /api/v1/auth/password-resets/confirm/ \
  /api/v1/auth/password-resets/complete/ \
  /api/v1/auth/password-resetsx; do
  check "POST ${u13_path} (path sin Route) → 404" 404 "$(u13_post "${u13_path}")"
done

for u13_entry in "${u13_routes[@]}"; do
  IFS='|' read -r u13_path _ _ <<< "${u13_entry}"
  check "GET ${u13_path} (método sin Route) → 404" \
    404 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X GET "http://127.0.0.1:8000${u13_path}")"
done

echo
echo "Email y recuperación de contraseña (US-13): límite de tamaño"

# 413 de Kong: corta antes de `rate-limiting` y de `app-attestation`.
# SIGNIN_MAX_BODY_KB = 64 KB en las cuatro rutas de códigos; la selfie de
# `complete` usa SIGNUP_MAX_BODY_MB = 5 MB.
for u13_path in \
  /api/v1/auth/email-verifications \
  /api/v1/auth/email-verifications/confirm \
  /api/v1/auth/password-resets \
  /api/v1/auth/password-resets/confirm; do
  check "un body de 64KB+1 se rechaza: ${u13_path}" \
    413 "$(u13_sized_status "${u13_path}" 65537)"
done
check "un body de 64KB+1 no se rechaza en complete (techo de signup, llega a la atestación)" \
  403 "$(u13_sized_status /api/v1/auth/password-resets/complete 65537)"
check "un body de 6MB (> SIGNUP_MAX_BODY_MB) se rechaza en complete" \
  413 "$(u13_sized_status /api/v1/auth/password-resets/complete 6291456)"

echo
echo "Email y recuperación de contraseña (US-13): rate limiting por IP"

# Ráfaga de `count` requests con atestación válida y body propio, corrida
# dentro del contenedor en un solo `docker exec`: así entra holgada en la ventana
# del minuto. Devuelve los status en orden, separados por espacios.
u13_burst() {
  docker exec -i "${GATEWAY}" sh -s -- "$1" "$2" <<'SH'
path="$1"; count="$2"; i=0
while [ "${i}" -lt "${count}" ]; do
  i=$((i + 1))
  suffix="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  body="{\"ephemeral_public_key\":\"U13-${suffix}\",\"ciphertext\":\"CCCC\"}"
  hash="$(printf '%s' "${body}" | sha256sum | cut -d' ' -f1)"
  curl -s -o /dev/null -w '%{http_code} ' -X POST "http://127.0.0.1:8000${path}" \
    -H "X-App-Attestation: ${hash}" -H 'Content-Type: application/json' \
    --data-binary "${body}"
done
SH
}

# Ventana limpia: los contadores `local` se alinean al minuto de reloj. Cada
# Route tiene su contador, así que las cinco ráfagas conviven en la misma
# ventana sin pisarse.
u9_wait_clock_minute 0

check "email-verifications: 3 pasan y la 4 → 429 (3/min)" \
  "200 200 200 429 " "$(u13_burst /api/v1/auth/email-verifications 4)"
check "email-verifications/confirm: 10 pasan y la 11 → 429 (10/min)" \
  "200 200 200 200 200 200 200 200 200 200 429 " \
  "$(u13_burst /api/v1/auth/email-verifications/confirm 11)"
check "password-resets: 3 pasan y la 4 → 429 (3/min)" \
  "200 200 200 429 " "$(u13_burst /api/v1/auth/password-resets 4)"
check "password-resets/confirm: 10 pasan y la 11 → 429 (10/min)" \
  "200 200 200 200 200 200 200 200 200 200 429 " \
  "$(u13_burst /api/v1/auth/password-resets/confirm 11)"
check "password-resets/complete: 3 pasan y la 4 → 429 (3/min)" \
  "200 200 200 429 " "$(u13_burst /api/v1/auth/password-resets/complete 4)"

# Con el cupo agotado, el 429 corta antes de `app-attestation` (la prioridad de
# `rate-limiting` es mayor): no gasta una llamada a Google.
u13_google_before="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"
u13_limited="$(u13_post_full /api/v1/auth/email-verifications)"
u13_google_after="$(docker logs "${STUB}" 2>&1 | grep -c 'decodeIntegrityToken' || true)"
check_contains "con el cupo agotado, el request siguiente → 429" \
  "http/1.1 429" "${u13_limited}"
check_contains "el 429 informa cuándo reintentar" "retry-after" "${u13_limited}"
check "el 429 corta antes de la atestación: no llama a Google" \
  "${u13_google_before}" "${u13_google_after}"

echo
echo "Vinculación por dominio (US-14): matriz de ruteo (conteo, unlink y unlink-all)"

# Cada Route de US-14 declara su propio `rate-limiting` y Kong expone su límite
# en `X-RateLimit-Limit-*`: es lo que identifica QUÉ Route atendió el request.
# Sólo los requests ruteados gastan cupo (un 404 de Kong, un 401 o un 413 cortan
# antes), así que cada grupo usa su propio usuario.
u14_vehicles="/api/v1/vehicles"
u14_unlink="/api/v1/vehicles/unlink"
u14_token_for() {
  sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"$1\",\"exp\":$((now + 300))}"
}
u14_get_user="a1b2c3d4-0001-4a5b-8c6d-7e8f9a0b1c2d"
u14_unlink_user="a1b2c3d4-0002-4a5b-8c6d-7e8f9a0b1c2d"
u14_all_user="a1b2c3d4-0003-4a5b-8c6d-7e8f9a0b1c2d"
u14_get_token="$(u14_token_for "${u14_get_user}")"
u14_unlink_token="$(u14_token_for "${u14_unlink_user}")"
u14_all_token="$(u14_token_for "${u14_all_user}")"

u14_get_headers="$(route_headers GET "${u14_vehicles}" "${u14_get_token}")"
check_contains "GET /api/v1/vehicles → vehicles-count-route" \
  "http/1.1 200" "${u14_get_headers}"
check_contains "GET /api/v1/vehicles lo atiende vehicles-count-route (30/min)" \
  "x-ratelimit-limit-minute: 30" "${u14_get_headers}"
check_not_contains "GET /api/v1/vehicles no tiene tope por hora" \
  "x-ratelimit-limit-hour" "${u14_get_headers}"

u14_unlink_headers="$(route_headers POST "${u14_unlink}" "${u14_unlink_token}")"
check_contains "POST /api/v1/vehicles/unlink → vehicles-unlink-route" \
  "http/1.1 200" "${u14_unlink_headers}"
check_contains "POST /api/v1/vehicles/unlink lo atiende vehicles-unlink-route (10/min)" \
  "x-ratelimit-limit-minute: 10" "${u14_unlink_headers}"
check_contains "POST /api/v1/vehicles/unlink lo atiende vehicles-unlink-route (30/h)" \
  "x-ratelimit-limit-hour: 30" "${u14_unlink_headers}"

u14_all_headers="$(route_headers DELETE "${u14_vehicles}" "${u14_all_token}")"
check_contains "DELETE /api/v1/vehicles → vehicles-unlink-all-route" \
  "http/1.1 200" "${u14_all_headers}"
check_contains "DELETE /api/v1/vehicles lo atiende vehicles-unlink-all-route (3/min)" \
  "x-ratelimit-limit-minute: 3" "${u14_all_headers}"
check_contains "DELETE /api/v1/vehicles lo atiende vehicles-unlink-all-route (10/h)" \
  "x-ratelimit-limit-hour: 10" "${u14_all_headers}"

# El alta vigente no se toca: sigue en `vehicles-route`, que no declara
# `rate-limiting` propio, así que ve el perímetro por IP (60/min), no los
# límites de las Routes nuevas.
u14_post_user="a1b2c3d4-0004-4a5b-8c6d-7e8f9a0b1c2d"
u14_post_headers="$(route_headers POST "${u14_vehicles}" "$(u14_token_for "${u14_post_user}")")"
check_contains "POST /api/v1/vehicles sigue en vehicles-route (200)" \
  "http/1.1 200" "${u14_post_headers}"
check_contains "POST /api/v1/vehicles sigue sin rate-limiting propio (perímetro por IP)" \
  "x-ratelimit-limit-minute: 60" "${u14_post_headers}"

# Los demás métodos no tienen Route en ninguno de los dos paths.
u14_probe="$(u14_token_for "a1b2c3d4-0005-4a5b-8c6d-7e8f9a0b1c2d")"
check "PUT /api/v1/vehicles (método sin Route) → 404" \
  404 "$(route_status PUT "${u14_vehicles}" "${u14_probe}")"
check "PATCH /api/v1/vehicles (método sin Route) → 404" \
  404 "$(route_status PATCH "${u14_vehicles}" "${u14_probe}")"
check "GET /api/v1/vehicles/unlink (método sin Route) → 404" \
  404 "$(route_status GET "${u14_unlink}" "${u14_probe}")"
check "DELETE /api/v1/vehicles/unlink (método sin Route) → 404" \
  404 "$(route_status DELETE "${u14_unlink}" "${u14_probe}")"
check "PUT /api/v1/vehicles/unlink (método sin Route) → 404" \
  404 "$(route_status PUT "${u14_unlink}" "${u14_probe}")"

echo
echo "Vinculación por dominio (US-14): path exacto"

# Regex anclada con `$`: ninguna Route captura barras finales, subrecursos ni
# paths que sólo comparten prefijo.
check "GET /api/v1/vehicles/ (barra final) → 404" \
  404 "$(route_status GET "${u14_vehicles}/" "${u14_probe}")"
check "GET /api/v1/vehicles/extra → 404" \
  404 "$(route_status GET "${u14_vehicles}/extra" "${u14_probe}")"
check "GET /api/v1/vehicles/check (eliminado en US-08) → 404" \
  404 "$(route_status GET "${u14_vehicles}/check" "${u14_probe}")"
check "GET /api/v1/vehiclesx (mismo prefijo) → 404" \
  404 "$(route_status GET /api/v1/vehiclesx "${u14_probe}")"
check "DELETE /api/v1/vehicles/ (barra final) → 404" \
  404 "$(route_status DELETE "${u14_vehicles}/" "${u14_probe}")"
check "DELETE /api/v1/vehicles/extra → 404" \
  404 "$(route_status DELETE "${u14_vehicles}/extra" "${u14_probe}")"
check "DELETE /api/v1/vehicles/check → 404" \
  404 "$(route_status DELETE "${u14_vehicles}/check" "${u14_probe}")"
check "POST /api/v1/vehicles/unlink/ (barra final) → 404" \
  404 "$(route_status POST "${u14_unlink}/" "${u14_probe}")"
check "POST /api/v1/vehicles/unlink/extra → 404" \
  404 "$(route_status POST "${u14_unlink}/extra" "${u14_probe}")"
check "POST /api/v1/vehicles/unlinkx (mismo prefijo) → 404" \
  404 "$(route_status POST "${u14_unlink}x" "${u14_probe}")"
check "POST /api/v1/vehicles/unlink/{uuid} → 404" \
  404 "$(route_status POST "${u14_unlink}/0f1e2d3c-4b5a-4968-8776-655443322110" "${u14_probe}")"

echo
echo "Vinculación por dominio (US-14): seguridad (JWT y Token Offloading)"

# Cada Route exige un JWT válido: sin Authorization, mal formado, vencido o con
# un `iss` sin consumer registrado se corta con 401 antes de llegar a Vehicle.
u14_expired="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u14_probe}\",\"exp\":$((now - 300))}")"
u14_wrong_iss="$(sign_jwt "{\"iss\":\"otro-emisor\",\"sub\":\"${u14_get_user}\",\"exp\":$((now + 300))}")"
u14_unlink_body='{"payload_enc":"cripto-para-vehicle"}'

check "sin Authorization, 401: GET /vehicles" \
  401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X GET "http://127.0.0.1:8000${u14_vehicles}")"
check "sin Authorization, 401: POST /vehicles/unlink" \
  401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST "http://127.0.0.1:8000${u14_unlink}" \
    -H 'Content-Type: application/json' --data-binary "${u14_unlink_body}")"
check "sin Authorization, 401: DELETE /vehicles" \
  401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:8000${u14_vehicles}")"

check "JWT mal formado, 401: GET /vehicles" \
  401 "$(route_status GET "${u14_vehicles}" "no-es-un-jwt")"
check "JWT mal formado, 401: POST /vehicles/unlink" \
  401 "$(route_status POST "${u14_unlink}" "no-es-un-jwt")"
check "JWT mal formado, 401: DELETE /vehicles" \
  401 "$(route_status DELETE "${u14_vehicles}" "no-es-un-jwt")"

check "JWT expirado, 401: GET /vehicles" \
  401 "$(route_status GET "${u14_vehicles}" "${u14_expired}")"
check "JWT expirado, 401: POST /vehicles/unlink" \
  401 "$(route_status POST "${u14_unlink}" "${u14_expired}")"
check "JWT expirado, 401: DELETE /vehicles" \
  401 "$(route_status DELETE "${u14_vehicles}" "${u14_expired}")"

check "JWT con un iss sin consumer registrado, 401: GET /vehicles" \
  401 "$(route_status GET "${u14_vehicles}" "${u14_wrong_iss}")"
check "JWT con un iss sin consumer registrado, 401: POST /vehicles/unlink" \
  401 "$(route_status POST "${u14_unlink}" "${u14_wrong_iss}")"
check "JWT con un iss sin consumer registrado, 401: DELETE /vehicles" \
  401 "$(route_status DELETE "${u14_vehicles}" "${u14_wrong_iss}")"

# Con un JWT válido, Vehicle recibe `X-User-Id` con el `sub` y no recibe el
# `Authorization`. Un `X-User-Id` forjado por el cliente se descarta: es la
# única protección contra vincular o desvincular a nombre de otro usuario.
u14_get_view="$(docker exec "${GATEWAY}" curl -s \
  -X GET "http://127.0.0.1:8000${u14_vehicles}" \
  -H "Authorization: Bearer ${u14_get_token}" \
  -H 'X-User-Id: usuario-suplantado' | tr '[:upper:]' '[:lower:]')"
check_contains "X-User-Id del JWT llega al upstream: GET /vehicles" \
  "\"x-user-id\": \"${u14_get_user}\"" "${u14_get_view}"
check_not_contains "el X-User-Id forjado se descarta: GET /vehicles" \
  "usuario-suplantado" "${u14_get_view}"
check_not_contains "el Authorization no se propaga: GET /vehicles" \
  "authorization" "${u14_get_view}"

u14_unlink_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST "http://127.0.0.1:8000${u14_unlink}" \
  -H "Authorization: Bearer ${u14_unlink_token}" \
  -H 'X-User-Id: usuario-suplantado' \
  -H 'Content-Type: application/json' \
  --data-binary "${u14_unlink_body}")"
check_contains "X-User-Id del JWT llega al upstream: POST /vehicles/unlink" \
  "\"x-user-id\": \"${u14_unlink_user}\"" "$(printf '%s' "${u14_unlink_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el X-User-Id forjado se descarta: POST /vehicles/unlink" \
  "usuario-suplantado" "${u14_unlink_view}"
check_not_contains "el Authorization no se propaga: POST /vehicles/unlink" \
  "authorization" "$(printf '%s' "${u14_unlink_view}" | tr '[:upper:]' '[:lower:]')"
check_contains "el sobre HPKE de unlink se reenvía sin tocar" \
  "cripto-para-vehicle" "${u14_unlink_view}"

u14_all_view="$(docker exec "${GATEWAY}" curl -s \
  -X DELETE "http://127.0.0.1:8000${u14_vehicles}" \
  -H "Authorization: Bearer ${u14_all_token}" \
  -H 'X-User-Id: usuario-suplantado' | tr '[:upper:]' '[:lower:]')"
check_contains "X-User-Id del JWT llega al upstream: DELETE /vehicles" \
  "\"x-user-id\": \"${u14_all_user}\"" "${u14_all_view}"
check_not_contains "el X-User-Id forjado se descarta: DELETE /vehicles" \
  "usuario-suplantado" "${u14_all_view}"
check_not_contains "el Authorization no se propaga: DELETE /vehicles" \
  "authorization" "${u14_all_view}"

# El Gateway no loguea bodies: el sobre de `unlink` (que cifra una patente) no
# puede aparecer en sus logs.
u14_marker_user="a1b2c3d4-0006-4a5b-8c6d-7e8f9a0b1c2d"
docker exec "${GATEWAY}" curl -s -o /dev/null \
  -X POST "http://127.0.0.1:8000${u14_unlink}" \
  -H "Authorization: Bearer $(u14_token_for "${u14_marker_user}")" \
  -H 'Content-Type: application/json' \
  --data-binary '{"payload_enc":"marcador-de-patente-cifrada"}'
check_not_contains "el sobre de unlink no aparece en los logs del Gateway" \
  "marcador-de-patente-cifrada" "$(docker logs "${GATEWAY}" 2>&1)"

echo
echo "Vinculación por dominio (US-14): las respuestas de Vehicle se propagan"

# El upstream de eco devuelve el status que pide `x-set-response-status-code`.
# El Gateway no transforma las respuestas de estas Routes: el 204 de la
# desvinculación total y los códigos de error de Vehicle llegan tal cual.
u14_status_user="a1b2c3d4-0007-4a5b-8c6d-7e8f9a0b1c2d"
u14_status_token="$(u14_token_for "${u14_status_user}")"
u14_forced_status() {
  local method="$1" path="$2" code="$3"

  docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X "${method}" "http://127.0.0.1:8000${path}" \
    -H "Authorization: Bearer ${u14_status_token}" \
    -H 'Content-Type: application/json' \
    -H "x-set-response-status-code: ${code}" \
    --data-binary '{}'
}
check "el 204 de DELETE /vehicles se propaga" \
  204 "$(u14_forced_status DELETE "${u14_vehicles}" 204)"
check "el 404 VEHICLE_NOT_FOUND de unlink se propaga" \
  404 "$(u14_forced_status POST "${u14_unlink}" 404)"
check "el 400 INVALID_PLATE de unlink se propaga" \
  400 "$(u14_forced_status POST "${u14_unlink}" 400)"
check "el 503 DEPENDENCY_UNAVAILABLE de GET /vehicles se propaga" \
  503 "$(u14_forced_status GET "${u14_vehicles}" 503)"

echo
echo "Vinculación por dominio (US-14): rate limiting por X-User-Id"

# Mismo guard de reloj que el de US-09 y US-11: la ventana fija del contador
# `local` se alinea al minuto de reloj y, si la ráfaga la cruzara, se
# reiniciaría y enmascararía el corte esperado.
u9_wait_clock_minute 35

u14_rl_get="$(u14_token_for "a1b2c3d4-0101-4a5b-8c6d-7e8f9a0b1c2d")"
u14_rl_other="$(u14_token_for "a1b2c3d4-0102-4a5b-8c6d-7e8f9a0b1c2d")"

# Si un GET cayera en una Route de 10/min o de 3/min, esta ráfaga habría
# fallado mucho antes del trigésimo.
for _ in $(seq 1 29); do
  route_status GET "${u14_vehicles}" "${u14_rl_get}" >/dev/null
done
check "el request 30 de GET /vehicles en el minuto todavía pasa" \
  200 "$(route_status GET "${u14_vehicles}" "${u14_rl_get}")"
check "el request 31 de GET /vehicles en el minuto → 429" \
  429 "$(route_status GET "${u14_vehicles}" "${u14_rl_get}")"
check "otro usuario no comparte el contador de GET /vehicles" \
  200 "$(route_status GET "${u14_vehicles}" "${u14_rl_other}")"

u9_wait_clock_minute 45

u14_rl_unlink="$(u14_token_for "a1b2c3d4-0103-4a5b-8c6d-7e8f9a0b1c2d")"
for _ in $(seq 1 9); do
  route_status POST "${u14_unlink}" "${u14_rl_unlink}" >/dev/null
done
check "el request 10 de unlink en el minuto todavía pasa" \
  200 "$(route_status POST "${u14_unlink}" "${u14_rl_unlink}")"
check "el request 11 de unlink en el minuto → 429" \
  429 "$(route_status POST "${u14_unlink}" "${u14_rl_unlink}")"
check "otro usuario no comparte el contador de unlink" \
  200 "$(route_status POST "${u14_unlink}" "${u14_rl_other}")"

u14_rl_all="$(u14_token_for "a1b2c3d4-0104-4a5b-8c6d-7e8f9a0b1c2d")"
for _ in $(seq 1 2); do
  route_status DELETE "${u14_vehicles}" "${u14_rl_all}" >/dev/null
done
check "el request 3 de DELETE /vehicles en el minuto todavía pasa" \
  200 "$(route_status DELETE "${u14_vehicles}" "${u14_rl_all}")"
check "el request 4 de DELETE /vehicles en el minuto → 429" \
  429 "$(route_status DELETE "${u14_vehicles}" "${u14_rl_all}")"
check "otro usuario no comparte el contador de DELETE /vehicles" \
  200 "$(route_status DELETE "${u14_vehicles}" "${u14_rl_other}")"

# Los tres contadores son independientes entre sí: agotar uno no corta a los
# otros, aunque compartan path y usuario.
check "con DELETE agotado, el mismo usuario sigue pudiendo hacer GET" \
  200 "$(route_status GET "${u14_vehicles}" "${u14_rl_all}")"
check "con DELETE agotado, el mismo usuario sigue pudiendo hacer unlink" \
  200 "$(route_status POST "${u14_unlink}" "${u14_rl_all}")"

echo
echo "Beneficios (US-18): matriz de ruteo (lista, banner y claim)"

# Cada Route de US-18 declara su propio `rate-limiting` y Kong expone su límite
# en `X-RateLimit-Limit-*`: es lo que identifica QUÉ Route atendió el request.
# Sólo los requests ruteados gastan cupo (un 404 de Kong o un 401 cortan antes),
# así que cada grupo usa su propio usuario.
u18_list="/api/v1/benefits"
u18_id="0f1e2d3c-4b5a-4968-8776-655443322110"
u18_banner="/api/v1/benefits/${u18_id}/banner"
u18_claim="/api/v1/benefits/${u18_id}/claim"
u18_token_for() {
  sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"$1\",\"exp\":$((now + 300))}"
}
u18_list_user="b1c2d3e4-0001-4a5b-8c6d-7e8f9a0b1c2d"
u18_banner_user="b1c2d3e4-0002-4a5b-8c6d-7e8f9a0b1c2d"
u18_claim_user="b1c2d3e4-0003-4a5b-8c6d-7e8f9a0b1c2d"
u18_list_token="$(u18_token_for "${u18_list_user}")"
u18_banner_token="$(u18_token_for "${u18_banner_user}")"
u18_claim_token="$(u18_token_for "${u18_claim_user}")"

u18_list_headers="$(route_headers GET "${u18_list}" "${u18_list_token}")"
check_contains "GET /api/v1/benefits → benefits-list-route" \
  "http/1.1 200" "${u18_list_headers}"
check_contains "GET /api/v1/benefits lo atiende benefits-list-route (60/min)" \
  "x-ratelimit-limit-minute: 60" "${u18_list_headers}"
check_not_contains "GET /api/v1/benefits no tiene tope por hora" \
  "x-ratelimit-limit-hour" "${u18_list_headers}"

u18_banner_headers="$(route_headers GET "${u18_banner}" "${u18_banner_token}")"
check_contains "GET /api/v1/benefits/{id}/banner → benefits-banner-route" \
  "http/1.1 200" "${u18_banner_headers}"
check_contains "GET /api/v1/benefits/{id}/banner lo atiende benefits-banner-route (120/min)" \
  "x-ratelimit-limit-minute: 120" "${u18_banner_headers}"
check_not_contains "GET /api/v1/benefits/{id}/banner no tiene tope por hora" \
  "x-ratelimit-limit-hour" "${u18_banner_headers}"

u18_claim_headers="$(route_headers POST "${u18_claim}" "${u18_claim_token}")"
check_contains "POST /api/v1/benefits/{id}/claim → benefits-claim-route" \
  "http/1.1 200" "${u18_claim_headers}"
check_contains "POST /api/v1/benefits/{id}/claim lo atiende benefits-claim-route (10/min)" \
  "x-ratelimit-limit-minute: 10" "${u18_claim_headers}"
check_contains "POST /api/v1/benefits/{id}/claim lo atiende benefits-claim-route (30/h)" \
  "x-ratelimit-limit-hour: 30" "${u18_claim_headers}"

# El id es un UUID en minúsculas o mayúsculas.
check "el {id} en mayúsculas también se rutea: banner" \
  200 "$(route_status GET "/api/v1/benefits/0F1E2D3C-4B5A-4968-8776-655443322110/banner" "$(u18_token_for "b1c2d3e4-0004-4a5b-8c6d-7e8f9a0b1c2d")")"

# Los demás métodos no tienen Route en ninguno de los tres paths.
u18_probe="$(u18_token_for "b1c2d3e4-0005-4a5b-8c6d-7e8f9a0b1c2d")"
for method in POST PUT PATCH DELETE; do
  check "${method} /api/v1/benefits (método sin Route) → 404" \
    404 "$(route_status "${method}" "${u18_list}" "${u18_probe}")"
done
for method in POST PUT PATCH DELETE; do
  check "${method} /api/v1/benefits/{id}/banner (método sin Route) → 404" \
    404 "$(route_status "${method}" "${u18_banner}" "${u18_probe}")"
done
for method in GET PUT PATCH DELETE; do
  check "${method} /api/v1/benefits/{id}/claim (método sin Route) → 404" \
    404 "$(route_status "${method}" "${u18_claim}" "${u18_probe}")"
done

echo
echo "Beneficios (US-18): path exacto"

# Regex anclada con `$`: ninguna Route captura barras finales, subrecursos,
# ids que no son un UUID ni paths que sólo comparten prefijo.
check "GET /api/v1/benefits/ (barra final) → 404" \
  404 "$(route_status GET "${u18_list}/" "${u18_probe}")"
check "GET /api/v1/benefits/extra → 404" \
  404 "$(route_status GET "${u18_list}/extra" "${u18_probe}")"
check "GET /api/v1/benefits/{id} (sin subrecurso) → 404" \
  404 "$(route_status GET "${u18_list}/${u18_id}" "${u18_probe}")"
check "GET /api/v1/benefitsx (mismo prefijo) → 404" \
  404 "$(route_status GET /api/v1/benefitsx "${u18_probe}")"
check "GET /api/v1/benefits/{id}/banner/ (barra final) → 404" \
  404 "$(route_status GET "${u18_banner}/" "${u18_probe}")"
check "GET /api/v1/benefits/{id}/banner/extra → 404" \
  404 "$(route_status GET "${u18_banner}/extra" "${u18_probe}")"
check "GET /api/v1/benefits/{id}/bannerx (mismo prefijo) → 404" \
  404 "$(route_status GET "${u18_banner}x" "${u18_probe}")"
check "GET /api/v1/benefits/{id}/x/banner → 404" \
  404 "$(route_status GET "/api/v1/benefits/${u18_id}/x/banner" "${u18_probe}")"
check "GET /api/v1/benefits/no-es-un-uuid/banner → 404" \
  404 "$(route_status GET /api/v1/benefits/no-es-un-uuid/banner "${u18_probe}")"
check "POST /api/v1/benefits/{id}/claim/ (barra final) → 404" \
  404 "$(route_status POST "${u18_claim}/" "${u18_probe}")"
check "POST /api/v1/benefits/{id}/claim/extra → 404" \
  404 "$(route_status POST "${u18_claim}/extra" "${u18_probe}")"
check "POST /api/v1/benefits/{id}/claimx (mismo prefijo) → 404" \
  404 "$(route_status POST "${u18_claim}x" "${u18_probe}")"
check "POST /api/v1/benefits/no-es-un-uuid/claim → 404" \
  404 "$(route_status POST /api/v1/benefits/no-es-un-uuid/claim "${u18_probe}")"
check "POST /api/v1/benefits/claim (sin id) → 404" \
  404 "$(route_status POST /api/v1/benefits/claim "${u18_probe}")"

echo
echo "Beneficios (US-18): /admin/* no se alcanza por Kong"

# El router de administración de Benefits (puerto propio, `X-Admin-Api-Key`) no
# tiene Route: el 404 es de Kong, aun con un JWT válido y aun con la clave.
for method in GET POST; do
  check "${method} /admin/v1/campaigns → 404 de Kong" \
    404 "$(route_status "${method}" /admin/v1/campaigns "${u18_probe}")"
done
check "PATCH /admin/v1/campaigns/{id} → 404 de Kong" \
  404 "$(route_status PATCH "/admin/v1/campaigns/${u18_id}" "${u18_probe}")"
check "PUT /admin/v1/campaigns/{id}/banner → 404 de Kong" \
  404 "$(route_status PUT "/admin/v1/campaigns/${u18_id}/banner" "${u18_probe}")"
check "POST /admin/v1/campaigns/{id}/codes → 404 de Kong" \
  404 "$(route_status POST "/admin/v1/campaigns/${u18_id}/codes" "${u18_probe}")"
check "POST /admin/v1/campaigns/{id}/redemptions → 404 de Kong" \
  404 "$(route_status POST "/admin/v1/campaigns/${u18_id}/redemptions" "${u18_probe}")"
check "GET /admin/v1/campaigns/{id}/stats → 404 de Kong" \
  404 "$(route_status GET "/admin/v1/campaigns/${u18_id}/stats" "${u18_probe}")"
check "GET /admin/v1/campaigns con X-Admin-Api-Key → 404 de Kong" \
  404 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X GET http://127.0.0.1:8000/admin/v1/campaigns \
    -H 'X-Admin-Api-Key: una-clave-de-administracion-de-32-caracteres')"
check "GET /api/v1/benefits/admin/v1/campaigns → 404" \
  404 "$(route_status GET /api/v1/benefits/admin/v1/campaigns "${u18_probe}")"
check "GET /internal/benefits → 404 de Kong" \
  404 "$(route_status GET /internal/benefits "${u18_probe}")"

echo
echo "Beneficios (US-18): seguridad (JWT y Token Offloading)"

# Cada Route exige un JWT válido: sin Authorization, mal formado, vencido o con
# un `iss` sin consumer registrado se corta con 401 antes de llegar a Benefits.
u18_expired="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${u18_probe}\",\"exp\":$((now - 300))}")"
u18_wrong_iss="$(sign_jwt "{\"iss\":\"otro-emisor\",\"sub\":\"${u18_list_user}\",\"exp\":$((now + 300))}")"

u18_ph="{id}"
u18_paths=("GET ${u18_list}" "GET ${u18_banner}" "POST ${u18_claim}")
for entry in "${u18_paths[@]}"; do
  method="${entry%% *}"
  path="${entry#* }"
  label="${method} ${path/${u18_id}/${u18_ph}}"

  check "sin Authorization, 401: ${label}" \
    401 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
      -X "${method}" "http://127.0.0.1:8000${path}")"
  check "JWT mal formado, 401: ${label}" \
    401 "$(route_status "${method}" "${path}" "no-es-un-jwt")"
  check "JWT expirado, 401: ${label}" \
    401 "$(route_status "${method}" "${path}" "${u18_expired}")"
  check "JWT con un iss sin consumer registrado, 401: ${label}" \
    401 "$(route_status "${method}" "${path}" "${u18_wrong_iss}")"
done

# Un JWT sin `sub` no deja derivar la identidad: se corta en el perímetro.
u18_no_sub="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"exp\":$((now + 300))}")"
check "JWT sin sub, 401: POST /benefits/{id}/claim" \
  401 "$(route_status POST "${u18_claim}" "${u18_no_sub}")"

# Con un JWT válido, Benefits recibe `X-User-Id` con el `sub` y no recibe el
# `Authorization`. Un `X-User-Id` o un `X-User-Hash` forjado por el cliente no
# llega: es la única protección contra pedir el código a nombre de otro.
u18_view() {
  local method="$1" path="$2" token="$3"

  docker exec "${GATEWAY}" curl -s \
    -X "${method}" "http://127.0.0.1:8000${path}" \
    -H "Authorization: Bearer ${token}" \
    -H 'X-User-Id: usuario-suplantado' \
    -H 'X-User-Hash: hash-suplantado' \
    -H 'Content-Type: application/json' \
    --data-binary '{}' | tr '[:upper:]' '[:lower:]'
}
u18_check_view() {
  local label="$1" user="$2" view="$3"

  check_contains "X-User-Id del JWT llega al upstream: ${label}" \
    "\"x-user-id\": \"${user}\"" "${view}"
  check_not_contains "el X-User-Id forjado se descarta: ${label}" \
    "usuario-suplantado" "${view}"
  check_not_contains "el X-User-Hash forjado se descarta: ${label}" \
    "hash-suplantado" "${view}"
  check_not_contains "el Authorization no se propaga: ${label}" \
    "authorization" "${view}"
}
u18_check_view "GET /benefits" "${u18_list_user}" \
  "$(u18_view GET "${u18_list}" "${u18_list_token}")"
u18_check_view "GET /benefits/{id}/banner" "${u18_banner_user}" \
  "$(u18_view GET "${u18_banner}" "${u18_banner_token}")"
u18_check_view "POST /benefits/{id}/claim" "${u18_claim_user}" \
  "$(u18_view POST "${u18_claim}" "${u18_claim_token}")"

# El path con el id llega intacto al upstream (`strip_path: false`).
check_contains "el path del banner llega intacto a Benefits" \
  "${u18_banner}" "$(u18_view GET "${u18_banner}" "${u18_banner_token}")"

# El Gateway no loguea bodies ni headers de sesión: el JWT no puede aparecer en
# sus logs.
check_not_contains "el JWT del usuario no aparece en los logs del Gateway" \
  "${u18_claim_token}" "$(docker logs "${GATEWAY}" 2>&1)"

echo
echo "Beneficios (US-18): las respuestas de Benefits se propagan"

# El upstream de eco devuelve el status que pide `x-set-response-status-code`.
# El Gateway no transforma las respuestas de estas Routes: el 304 del banner,
# el 409 `NO_CODES_LEFT` y el 404 `BENEFIT_NOT_FOUND` llegan tal cual.
u18_status_token="$(u18_token_for "b1c2d3e4-0007-4a5b-8c6d-7e8f9a0b1c2d")"
u18_forced_status() {
  local method="$1" path="$2" code="$3"

  docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X "${method}" "http://127.0.0.1:8000${path}" \
    -H "Authorization: Bearer ${u18_status_token}" \
    -H 'Content-Type: application/json' \
    -H "x-set-response-status-code: ${code}" \
    --data-binary '{}'
}
check "el 304 del banner se propaga" \
  304 "$(u18_forced_status GET "${u18_banner}" 304)"
check "el 404 BENEFIT_NOT_FOUND del banner se propaga" \
  404 "$(u18_forced_status GET "${u18_banner}" 404)"
check "el 404 BENEFIT_NOT_FOUND de claim se propaga" \
  404 "$(u18_forced_status POST "${u18_claim}" 404)"
check "el 409 NO_CODES_LEFT de claim se propaga" \
  409 "$(u18_forced_status POST "${u18_claim}" 409)"
check "el 503 DEPENDENCY_UNAVAILABLE de la lista se propaga" \
  503 "$(u18_forced_status GET "${u18_list}" 503)"

echo
echo "Beneficios (US-18): rate limiting por X-User-Id"

# Mismo guard de reloj que el de US-09, US-11 y US-14: la ventana fija del
# contador `local` se alinea al minuto de reloj y, si la ráfaga la cruzara, se
# reiniciaría y enmascararía el corte esperado.
#
# `u18_burst` hace `count` requests en una sola ejecución dentro del
# contenedor y devuelve el status de la última: la ráfaga de 120 del banner no
# entra en un minuto si cada request es un `docker exec` propio.
u18_burst() {
  local method="$1" path="$2" token="$3" count="$4"

  docker exec "${GATEWAY}" sh -c "
    last=
    i=0
    while [ \$i -lt ${count} ]; do
      last=\$(curl -s -o /dev/null -w '%{http_code}' -X ${method} 'http://127.0.0.1:8000${path}' \
        -H 'Authorization: Bearer ${token}' -H 'Content-Type: application/json' --data-binary '{}')
      i=\$((i + 1))
    done
    printf '%s' \"\$last\""
}

u9_wait_clock_minute 35

u18_rl_list="$(u18_token_for "b1c2d3e4-0101-4a5b-8c6d-7e8f9a0b1c2d")"
u18_rl_other="$(u18_token_for "b1c2d3e4-0102-4a5b-8c6d-7e8f9a0b1c2d")"

# Si la lista cayera en una Route de 10/min, esta ráfaga habría fallado mucho
# antes del sexagésimo.
check "el request 60 de GET /benefits en el minuto todavía pasa" \
  200 "$(u18_burst GET "${u18_list}" "${u18_rl_list}" 60)"
check "el request 61 de GET /benefits en el minuto → 429" \
  429 "$(route_status GET "${u18_list}" "${u18_rl_list}")"
check "otro usuario no comparte el contador de GET /benefits" \
  200 "$(route_status GET "${u18_list}" "${u18_rl_other}")"

u9_wait_clock_minute 30

u18_rl_banner="$(u18_token_for "b1c2d3e4-0103-4a5b-8c6d-7e8f9a0b1c2d")"
# Si el banner cayera en la Route de la lista (60/min), la ráfaga habría
# fallado en el request 61.
check "el request 120 del banner en el minuto todavía pasa" \
  200 "$(u18_burst GET "${u18_banner}" "${u18_rl_banner}" 120)"
check "el request 121 del banner en el minuto → 429" \
  429 "$(route_status GET "${u18_banner}" "${u18_rl_banner}")"
check "otro usuario no comparte el contador del banner" \
  200 "$(route_status GET "${u18_banner}" "${u18_rl_other}")"
# El cupo es por Route: agotar el banner no corta la lista del mismo usuario.
check "con el banner agotado, el mismo usuario sigue pudiendo pedir la lista" \
  200 "$(route_status GET "${u18_list}" "${u18_rl_banner}")"

u9_wait_clock_minute 45

u18_rl_claim="$(u18_token_for "b1c2d3e4-0104-4a5b-8c6d-7e8f9a0b1c2d")"
check "el request 10 de claim en el minuto todavía pasa" \
  200 "$(u18_burst POST "${u18_claim}" "${u18_rl_claim}" 10)"
check "el request 11 de claim en el minuto → 429" \
  429 "$(route_status POST "${u18_claim}" "${u18_rl_claim}")"
check "otro usuario no comparte el contador de claim" \
  200 "$(route_status POST "${u18_claim}" "${u18_rl_other}")"
# El cupo de claim es por usuario, no por campaña: otro id lo consume igual.
check "el cupo de claim es por usuario: otro {id} también da 429" \
  429 "$(route_status POST "/api/v1/benefits/1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d/claim" "${u18_rl_claim}")"
check "con claim agotado, el mismo usuario sigue pudiendo pedir la lista" \
  200 "$(route_status GET "${u18_list}" "${u18_rl_claim}")"

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

# El contador de `rate-limiting` con policy=local usa una ventana fija
# alineada al reloj de pared (no relativa a la primera request de esta
# ráfaga): si arrancara sobre el filo de un minuto, la ventana podría rotar
# a mitad de camino y reiniciar el contador, enmascarando el corte esperado
# en la request 21 (probado empíricamente: tanto en secuencia como en
# paralelo, sin esta espera, la ráfaga es flaky exactamente por esto). Se
# espera a tener margen suficiente en el minuto de reloj actual antes de
# arrancar, para que las ~21 requests —todas por `docker exec`, no
# instantáneas— completen sin cruzarlo.
rl_seconds_now="$(date +%S)"; rl_seconds_now=$((10#${rl_seconds_now}))
if (( rl_seconds_now > 30 )); then
  rl_sleep_for=$((60 - rl_seconds_now))
  echo "  (esperando ${rl_sleep_for}s al próximo minuto de reloj, para no cruzar la ventana del rate-limiting a mitad de la ráfaga)"
  sleep "${rl_sleep_for}"
fi

inbox_rl_user="9f1c2d3e-4b5a-4c6d-8e9f-0a1b2c3d4e5f"
inbox_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${inbox_rl_user}\",\"exp\":$((now + 300))}")"

# Prueba, de paso, la precedencia de rutas: si un GET a /alerts/inbox
# cayera por error en `alerts-route` (POST /alerts, 5/min), esta secuencia
# de 20 requests exitosos habría fallado mucho antes del vigésimo.
for _ in $(seq 1 19); do
  alerts_inbox_status "${inbox_rl_token}" >/dev/null
done

check "el request 20 en el minuto todavía pasa" \
  200 "$(alerts_inbox_status "${inbox_rl_token}")"

check "el request 21 en el minuto se rechaza con 429" \
  429 "$(alerts_inbox_status "${inbox_rl_token}")"

inbox_other_user="1a2b3c4d-5e6f-4789-9a0b-1c2d3e4f5a6b"
inbox_other_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${inbox_other_user}\",\"exp\":$((now + 300))}")"

check "un usuario distinto no comparte cupo con el que ya alcanzó el límite" \
  200 "$(alerts_inbox_status "${inbox_other_token}")"

echo
echo "Registro de Token FCM (US-06): JWT y Token Offloading en POST /notifications/tokens"

# Mismo esquema que /alerts y /alerts/inbox: el rate-limiting de esta Route
# es una instancia de plugin propia, así que reusar el sub no cruza cupos.
# La verificación exhaustiva del límite de 10/día es una sección aparte, más
# abajo, con un usuario dedicado para no consumir cupo de estos chequeos.
notif_body='{"fcm_token":"token-fcm-de-prueba"}'

check "sin Authorization, 401 sin necesidad de un JWT" \
  401 "$(notifications_post_status "" "${notif_body}")"

notif_expired_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${USER_SUB}\",\"exp\":$((now - 300))}")"
check "un JWT expirado se rechaza con 401" \
  401 "$(notifications_post_status "${notif_expired_token}" "${notif_body}")"

check "un JWT válido, firmado y sin vencer, pasa" \
  200 "$(notifications_post_status "${valid_token}" "${notif_body}")"

notif_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/notifications/tokens \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'Content-Type: application/json' \
  --data-binary "${notif_body}")"

check_contains "Notification recibe X-User-Id con el sub del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${notif_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el Authorization no se propaga al upstream (token offloading)" \
  "authorization" "$(printf '%s' "${notif_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_contains "el body (fcm_token) llega intacto al upstream" \
  "token-fcm-de-prueba" "${notif_upstream_view}"

notif_spoofed_view="$(docker exec "${GATEWAY}" curl -s \
  -X POST http://127.0.0.1:8000/api/v1/notifications/tokens \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'X-User-Id: usuario-suplantado' \
  -H 'Content-Type: application/json' \
  --data-binary "${notif_body}")"

check_contains "un X-User-Id forjado por el cliente se reemplaza por el del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${notif_spoofed_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el X-User-Id forjado no llega al upstream" \
  "usuario-suplantado" "$(printf '%s' "${notif_spoofed_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Registro de Token FCM (US-06): /internal/* no existe en Kong"

check "/internal/* no tiene Route: 404" \
  404 "$(docker exec "${GATEWAY}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/internal/notifications \
    -H 'Content-Type: application/json' \
    -d '{}')"

echo
echo "Registro de Token FCM (US-06): rate limiting a 10/día"

# Ventana `day`, no `minute`: a diferencia del rate-limiting de
# /alerts/inbox (ver más arriba), el riesgo de que esta ráfaga cruce el
# límite de la ventana a mitad de camino es despreciable (se necesitarían
# ~86400s para que la ventana rote, contra los pocos segundos que tardan 11
# requests secuenciales por `docker exec`), así que no hace falta un guard
# de reloj de pared acá.
notif_rl_user="4c5d6e7f-8a9b-4c1d-9e2f-3a4b5c6d7e8f"
notif_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${notif_rl_user}\",\"exp\":$((now + 300))}")"

for _ in $(seq 1 9); do
  notifications_post_status "${notif_rl_token}" "${notif_body}" >/dev/null
done

check "el request 10 del día todavía pasa" \
  200 "$(notifications_post_status "${notif_rl_token}" "${notif_body}")"

check "el request 11 del día se rechaza con 429" \
  429 "$(notifications_post_status "${notif_rl_token}" "${notif_body}")"

notif_other_user="2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
notif_other_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${notif_other_user}\",\"exp\":$((now + 300))}")"

check "un usuario distinto no comparte cupo con el que ya alcanzó el límite" \
  200 "$(notifications_post_status "${notif_other_token}" "${notif_body}")"

echo
echo "Baja de Token FCM (US-06): JWT y Token Offloading en DELETE /notifications/tokens"

# Mismo par jwt + token-offloading que el alta, pero esta Route es una
# instancia de plugin propia sin `rate-limiting`: el sub se reusa porque no
# hay cupo que cuidar acá.
check "sin Authorization, 401 sin necesidad de un JWT" \
  401 "$(notifications_delete_status "")"

del_expired_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${USER_SUB}\",\"exp\":$((now - 300))}")"
check "un JWT expirado se rechaza con 401" \
  401 "$(notifications_delete_status "${del_expired_token}")"

check "un JWT válido, firmado y sin vencer, pasa" \
  200 "$(notifications_delete_status "${valid_token}")"

del_upstream_view="$(docker exec "${GATEWAY}" curl -s \
  -X DELETE http://127.0.0.1:8000/api/v1/notifications/tokens \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'Content-Type: application/json' \
  --data-binary '{}')"

check_contains "Notification recibe X-User-Id con el sub del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${del_upstream_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el Authorization no se propaga al upstream (token offloading)" \
  "authorization" "$(printf '%s' "${del_upstream_view}" | tr '[:upper:]' '[:lower:]')"

del_spoofed_view="$(docker exec "${GATEWAY}" curl -s \
  -X DELETE http://127.0.0.1:8000/api/v1/notifications/tokens \
  -H "Authorization: Bearer ${valid_token}" \
  -H 'X-User-Id: usuario-suplantado' \
  -H 'Content-Type: application/json' \
  --data-binary '{}')"

check_contains "un X-User-Id forjado por el cliente se reemplaza por el del JWT" \
  "\"x-user-id\": \"${USER_SUB}\"" \
  "$(printf '%s' "${del_spoofed_view}" | tr '[:upper:]' '[:lower:]')"
check_not_contains "el X-User-Id forjado no llega al upstream" \
  "usuario-suplantado" "$(printf '%s' "${del_spoofed_view}" | tr '[:upper:]' '[:lower:]')"

echo
echo "Baja de Token FCM (US-06): sin rate-limiting, deliberadamente"

# Un límite alcanzado acá dejaría al dispositivo recibiendo notificaciones
# que ya no le corresponden — fuga de privacidad, no una molestia (ver
# kong/kong.yml). Quince requests secuenciales, muy por encima de los 10/día
# del alta, tienen que pasar todas: ni una sola `429`. De paso prueba la
# precedencia frente al alta: si un DELETE cayera por error en
# notification-tokens-post-route, heredaría su rate-limiting y esta
# secuencia fallaría mucho antes de la quince.
del_rl_user="7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a"
del_rl_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${del_rl_user}\",\"exp\":$((now + 300))}")"

del_rl_failures=0
for i in $(seq 1 15); do
  status="$(notifications_delete_status "${del_rl_token}")"
  if [[ "${status}" != "200" ]]; then
    del_rl_failures=$((del_rl_failures + 1))
  fi
done

check "quince DELETE seguidos del mismo usuario pasan todos (0 con status distinto de 200)" \
  0 "${del_rl_failures}"

# Confirma, de paso, que el alta conserva su propio límite tras agregar esta
# Route: un POST del mismo usuario que acaba de agotar el DELETE (sin cupo
# compartido entre Routes) todavía tiene que pasar.
check "el alta (POST) sigue funcionando para ese usuario tras la ráfaga de bajas" \
  200 "$(notifications_post_status "${del_rl_token}" "${notif_body}")"

echo
echo "Resiliencia (K2): reintentos de Kong ante un upstream interno lento"

# Gateway y upstream dedicados, aislados del resto de la suite: ninguno de los
# tres Services restantes se ejercita acá, así que apuntan a destinos
# inválidos, mismo patrón que usa el job "Configuración declarativa" de CI.
# Reutiliza el par JWT ya generado (jwt_public_key_escaped / sign_jwt): no
# hace falta uno nuevo para que este Gateway acepte valid_token-equivalentes.
echo "==> Levantando un upstream deliberadamente lento"
docker run -d --name "${SLOW_UPSTREAM}" --network "${NETWORK}" \
  -v "$(to_host_path "${SCRIPT_DIR}/slow-upstream/nginx.conf"):/conf/nginx.conf:ro" \
  --entrypoint sh kong:3.7 \
  -c 'mkdir -p /tmp/slow/logs && exec /usr/local/openresty/bin/openresty -c /conf/nginx.conf -p /tmp/slow -g "daemon off;"' \
  >/dev/null

echo "==> Levantando un segundo Gateway para la prueba de timeout/reintentos"
docker run -d --name "${GATEWAY_SLOW}" --network "${NETWORK}" \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -v "$(to_host_path "${sa_dir}/google-service-account.json"):/etc/vinculo-vial/google-service-account.json:ro" \
  -e "IDENTITY_SERVICE_URL=http://identity.invalid:8080" \
  -e "VEHICLE_SERVICE_URL=http://vehicle.invalid:8080" \
  -e "ALERT_SERVICE_URL=http://alert.invalid:8080" \
  -e "NOTIFICATION_SERVICE_URL=http://${SLOW_UPSTREAM}:8080" \
  -e "BENEFITS_SERVICE_URL=http://benefits.invalid:8080" \
  -e "PLAY_INTEGRITY_URL=http://${STUB}:8080" \
  -e "PLAY_PACKAGE_NAME=${PACKAGE_NAME}" \
  -e ATTESTATION_SOURCE=google \
  -e ATTESTATION_SSL_VERIFY=false \
  -e "JWT_PUBLIC_KEY=${jwt_public_key_escaped}" \
  -e "JWT_ISSUER=${JWT_ISSUER}" \
  vinculo-vial-gateway:integration >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${GATEWAY_SLOW}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${GATEWAY_SLOW}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
  echo "El segundo Gateway no llegó a estar healthy:"
  docker logs "${GATEWAY_SLOW}"
  exit 1
fi

slow_user="5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b"
slow_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${slow_user}\",\"exp\":$((now + 300))}")"

timeout_status="$(docker exec "${GATEWAY_SLOW}" curl -s -o /dev/null -w '%{http_code}' \
  -X POST http://127.0.0.1:8000/api/v1/notifications/tokens \
  -H "Authorization: Bearer ${slow_token}" \
  -H 'Content-Type: application/json' \
  --data-binary "${notif_body}")"

# Comportamiento nativo de Kong ante un timeout de upstream interno: 504, no
# 503. El contrato de resiliencia de la plataforma reserva esa diferencia
# deliberadamente para este caso (ver README).
check "un upstream que no responde dentro de read_timeout corta con 504" \
  504 "${timeout_status}"

slow_invocations="$(docker logs "${SLOW_UPSTREAM}" 2>&1 \
  | grep -c 'slow-upstream: invocacion recibida' || true)"
check "el upstream lento recibe exactamente 1 invocación pese a retries: 1" \
  1 "${slow_invocations}"

echo
echo "Resiliencia (Ola 5): presupuesto de las llamadas a Google y salud de los upstreams"

# Tercer Gateway, fresco (sin access token de Google en caché, que es lo que
# permite medir el reparto del presupuesto entre el canje de OAuth y
# decodeIntegrityToken) y con el healthcheck activo acelerado: con los valores
# por defecto (10s de intervalo, 3 fallas) sacar un target del balanceo tardaría
# cerca de medio minuto. Sólo notification-service apunta a un upstream real
# (el controlable); los otros tres, a destinos inválidos como en la sección
# anterior.
echo "==> Levantando un upstream controlable"
docker run -d --name "${FLAKY_UPSTREAM}" --network "${NETWORK}" \
  -v "$(to_host_path "${SCRIPT_DIR}/flaky-upstream/nginx.conf"):/conf/nginx.conf:ro" \
  --entrypoint sh kong:3.7 \
  -c 'mkdir -p /tmp/flaky/logs && exec /usr/local/openresty/bin/openresty -c /conf/nginx.conf -p /tmp/flaky -g "daemon off;"' \
  >/dev/null

echo "==> Levantando un tercer Gateway para la prueba de resiliencia"
docker run -d --name "${GATEWAY_RESILIENCE}" --network "${NETWORK}" \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -v "$(to_host_path "${sa_dir}/google-service-account.json"):/etc/vinculo-vial/google-service-account.json:ro" \
  -e "IDENTITY_SERVICE_URL=http://identity.invalid:8080" \
  -e "VEHICLE_SERVICE_URL=http://vehicle.invalid:8080" \
  -e "ALERT_SERVICE_URL=http://alert.invalid:8080" \
  -e "NOTIFICATION_SERVICE_URL=http://${FLAKY_UPSTREAM}:8080" \
  -e "BENEFITS_SERVICE_URL=http://benefits.invalid:8080" \
  -e "PLAY_INTEGRITY_URL=http://${STUB}:8080" \
  -e "PLAY_PACKAGE_NAME=${PACKAGE_NAME}" \
  -e ATTESTATION_SOURCE=google \
  -e ATTESTATION_SSL_VERIFY=false \
  -e "JWT_PUBLIC_KEY=${jwt_public_key_escaped}" \
  -e "JWT_ISSUER=${JWT_ISSUER}" \
  -e UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS=1 \
  -e UPSTREAM_HEALTHCHECK_TIMEOUT_SECONDS=1 \
  -e UPSTREAM_HEALTHCHECK_HEALTHY_THRESHOLD=1 \
  -e UPSTREAM_HEALTHCHECK_UNHEALTHY_THRESHOLD=2 \
  vinculo-vial-gateway:integration >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${GATEWAY_RESILIENCE}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${GATEWAY_RESILIENCE}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
  echo "El tercer Gateway no llegó a estar healthy:"
  docker logs "${GATEWAY_RESILIENCE}"
  exit 1
fi

# Un signup contra el tercer Gateway con el token de atestación dado. Imprime
# el body, un salto de línea, y "<status> <segundos>". El tiempo lo mide curl
# dentro del contenedor: no incluye el costo de `docker exec`.
resilience_signup_timed() {
  docker exec "${GATEWAY_RESILIENCE}" curl -s \
    -w '\n%{http_code} %{time_total}' \
    -X POST http://127.0.0.1:8000/api/v1/auth/signup \
    -H "X-App-Attestation: $1" \
    -H 'Content-Type: application/json' \
    --data-binary '{}'
}

# "dentro" si el valor cae en [mínimo, máximo], "fuera (<valor>s)" si no.
in_range() {
  awk -v t="$1" -v lo="$2" -v hi="$3" \
    'BEGIN { print (t >= lo && t <= hi) ? "dentro" : "fuera (" t "s)" }'
}

resilience_delete_status() {
  docker exec "${GATEWAY_RESILIENCE}" curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE http://127.0.0.1:8000/api/v1/notifications/tokens \
    -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' \
    --data-binary '{}'
}

flaky_control() {
  docker exec "${GATEWAY}" curl -s -o /dev/null "http://${FLAKY_UPSTREAM}:8080/control?$1"
}

flaky_invocations() {
  docker logs "${FLAKY_UPSTREAM}" 2>&1 | grep -c 'flaky-upstream: invocacion recibida' || true
}

echo
echo "Presupuesto agregado de Google (OAuth + decodeIntegrityToken)"

# Con el canje de OAuth demorado 2500ms (dentro de su techo de 3000) y Play
# Integrity colgado, el par tiene que cortar a los 4000ms del agregado: la
# segunda llamada recibe los 1500ms que quedan, no una ventana nueva de 3000
# (que daría ~5500ms). El piso de 3.8s verifica además que la demora del
# stub se aplicó: sin ella, Play Integrity cortaría solo a los 3000ms.
docker exec "${GATEWAY}" curl -s -o /dev/null "http://${STUB}:8080/control/token-delay?ms=2500"

budget_out="$(resilience_signup_timed SLOW)"
budget_body="${budget_out%$'\n'*}"
read -r budget_status budget_secs <<< "${budget_out##*$'\n'}"

docker exec "${GATEWAY}" curl -s -o /dev/null "http://${STUB}:8080/control/token-delay?ms=0"

check "un canje de OAuth lento y un decodeIntegrityToken colgado se traducen en 503" \
  503 "${budget_status}"
check_contains "la respuesta declara el error del contrato" \
  '"error":"service_unavailable"' "${budget_body}"
check_contains "la respuesta declara el motivo público del contrato" \
  '"reason":"dependency_unavailable"' "${budget_body}"
check "el par corta a los 4000ms del agregado, no a 2500+3000 (entre 3.8s y 4.6s)" \
  dentro "$(in_range "${budget_secs}" 3.8 4.6)"

# El access token quedó en caché por el canje anterior: ahora Play Integrity
# dispone del techo por llamada completo, y corta ahí.
timeout_out="$(resilience_signup_timed SLOW)"
timeout_body="${timeout_out%$'\n'*}"
read -r timeout_status timeout_secs <<< "${timeout_out##*$'\n'}"

check "con el access token en caché, un decodeIntegrityToken colgado se traduce en 503" \
  503 "${timeout_status}"
check_contains "la respuesta declara el motivo público del contrato" \
  '"reason":"dependency_unavailable"' "${timeout_body}"
check "corta en el techo por llamada de 3000ms, nunca una espera indefinida (entre 2.8s y 3.6s)" \
  dentro "$(in_range "${timeout_secs}" 2.8 3.6)"

echo
echo "Balanceo: un upstream que responde 5xx o 4xx sigue en el balanceo"

# Lo único que decide si una instancia está en el balanceo es /ready
# (healthcheck activo). El pasivo no cuenta el status HTTP: un 503 emitido
# por el servicio es contención por ruta (una dependencia caída detrás de su
# propio breaker), y si sacara a la instancia entera se caerían también las
# rutas que sí funcionan. DELETE /notifications/tokens no tiene
# rate-limiting, así que alcanza con un usuario para toda la sección.
res_now="$(date +%s)"
res_user="8e9f0a1b-2c3d-4e4f-9a5b-6c7d8e9f0a1b"
res_token="$(sign_jwt "{\"iss\":\"${JWT_ISSUER}\",\"sub\":\"${res_user}\",\"exp\":$((res_now + 300))}")"

flaky_control "ready=200&business=503"
upstream_before="$(flaky_invocations)"

# Diez, muy por encima del umbral de 2 de este Gateway. Las últimas dos van
# después de tres intervalos del healthcheck activo: si el pasivo contara
# HTTP, el target ya habría salido del balanceo.
not_503=0
for _ in $(seq 1 8); do
  [[ "$(resilience_delete_status "${res_token}")" == "503" ]] || not_503=$((not_503 + 1))
done
sleep 3
for _ in $(seq 1 2); do
  [[ "$(resilience_delete_status "${res_token}")" == "503" ]] || not_503=$((not_503 + 1))
done

check "diez 503 repetidos del upstream se reenvían tal cual (0 con status distinto)" \
  0 "${not_503}"
check "ninguno lo emitió el balanceador: el upstream recibió las diez" \
  10 "$(( $(flaky_invocations) - upstream_before ))"

# Un 4xx tampoco cuenta: es responsabilidad del cliente, no una falla del
# upstream.
flaky_control "business=400"
upstream_before="$(flaky_invocations)"

not_400=0
for _ in $(seq 1 5); do
  [[ "$(resilience_delete_status "${res_token}")" == "400" ]] || not_400=$((not_400 + 1))
done

check "cinco 4xx repetidos del upstream se reenvían tal cual (0 con status distinto)" \
  0 "${not_400}"
check "el upstream recibió las cinco: un 4xx no abre el circuito" \
  5 "$(( $(flaky_invocations) - upstream_before ))"

echo
echo "Balanceo: un target con /ready no sano sale del balanceo (503 sin tocar la red)"

# Las rutas de negocio siguen respondiendo 400: cualquier 503 a partir de acá
# sólo puede venir del balanceador, no del upstream.
flaky_control "ready=503"

balancer_status=""
for _ in $(seq 1 30); do
  balancer_status="$(resilience_delete_status "${res_token}")"
  if [[ "${balancer_status}" == "503" ]]; then
    break
  fi
  sleep 1
done

check "con /ready no sano, el balanceador responde 503" 503 "${balancer_status}"

upstream_before="$(flaky_invocations)"

open_not_503=0
for _ in $(seq 1 5); do
  [[ "$(resilience_delete_status "${res_token}")" == "503" ]] || open_not_503=$((open_not_503 + 1))
done

check "con el circuito abierto, cada request recibe 503 (0 con status distinto)" \
  0 "${open_not_503}"
check "con el circuito abierto, ninguna request llega al upstream" \
  "${upstream_before}" "$(flaky_invocations)"

echo
echo "Recuperación: un target no sano vuelve al balanceo cuando /ready se recupera"

# Sin esto, un `unhealthy.interval` en 0 deja el target fuera para siempre:
# Kong no vuelve a sondearlo, y un corte breve de la base propia del servicio
# lo saca del balanceo de forma permanente. Las rutas de negocio siguen
# respondiendo 400, así que un 400 sólo puede venir del upstream: es la
# prueba de que la request volvió a llegar.
flaky_control "ready=200"

recovered_status=""
for _ in $(seq 1 30); do
  recovered_status="$(resilience_delete_status "${res_token}")"
  if [[ "${recovered_status}" != "503" ]]; then
    break
  fi
  sleep 1
done

check "al recuperarse /ready, el target marcado por el activo vuelve al balanceo" \
  400 "${recovered_status}"

echo
echo "Recuperación: targets marcados por el healthcheck pasivo (timeouts y errores de conexión)"

# Cuarto Gateway, con el sondeo de targets SANOS apagado (healthy.interval = 0):
# sin él, el activo marcaría el target al instante y no habría forma de
# distinguir quién lo sacó del balanceo. Así sólo el pasivo puede hacerlo, y
# el activo (unhealthy.interval, 1s) queda como único camino de regreso. Que
# la primera request llegue al upstream aunque /ready ya esté no sano es la
# verificación de ese aislamiento. Fuera de la suite ese 0 no está permitido:
# el Gateway sólo lo acepta con GATEWAY_TEST_MODE=true (ver la guardia de
# arranque, más abajo).
echo "==> Levantando un upstream con el puerto cerrado"
docker run -d --name "${LATE_UPSTREAM}" --network "${NETWORK}" \
  -v "$(to_host_path "${SCRIPT_DIR}/flaky-upstream/nginx.conf"):/conf/nginx.conf:ro" \
  --entrypoint sh kong:3.7 \
  -c 'mkdir -p /tmp/flaky/logs && exec sleep infinity' \
  >/dev/null

echo "==> Levantando un cuarto Gateway para la prueba del healthcheck pasivo"
docker run -d --name "${GATEWAY_PASSIVE}" --network "${NETWORK}" \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -v "$(to_host_path "${sa_dir}/google-service-account.json"):/etc/vinculo-vial/google-service-account.json:ro" \
  -e "IDENTITY_SERVICE_URL=http://identity.invalid:8080" \
  -e "VEHICLE_SERVICE_URL=http://${LATE_UPSTREAM}:8080" \
  -e "ALERT_SERVICE_URL=http://alert.invalid:8080" \
  -e "NOTIFICATION_SERVICE_URL=http://${FLAKY_UPSTREAM}:8080" \
  -e "BENEFITS_SERVICE_URL=http://benefits.invalid:8080" \
  -e "PLAY_INTEGRITY_URL=http://${STUB}:8080" \
  -e "PLAY_PACKAGE_NAME=${PACKAGE_NAME}" \
  -e ATTESTATION_SOURCE=google \
  -e ATTESTATION_SSL_VERIFY=false \
  -e "JWT_PUBLIC_KEY=${jwt_public_key_escaped}" \
  -e "JWT_ISSUER=${JWT_ISSUER}" \
  -e UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS=1 \
  -e UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS=0 \
  -e GATEWAY_TEST_MODE=true \
  -e UPSTREAM_HEALTHCHECK_TIMEOUT_SECONDS=1 \
  -e UPSTREAM_HEALTHCHECK_HEALTHY_THRESHOLD=1 \
  -e UPSTREAM_HEALTHCHECK_UNHEALTHY_THRESHOLD=2 \
  vinculo-vial-gateway:integration >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${GATEWAY_PASSIVE}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${GATEWAY_PASSIVE}" curl -sf http://127.0.0.1:8100/status >/dev/null 2>&1; then
  echo "El cuarto Gateway no llegó a estar healthy:"
  docker logs "${GATEWAY_PASSIVE}"
  exit 1
fi

passive_delete_status() {
  docker exec "${GATEWAY_PASSIVE}" curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE http://127.0.0.1:8000/api/v1/notifications/tokens \
    -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' \
    --data-binary '{}'
}

passive_vehicles_status() {
  docker exec "${GATEWAY_PASSIVE}" curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/vehicles \
    -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' \
    --data-binary '{}'
}

# Timeouts: el upstream demora 12000ms (el read_timeout de notification-service
# es de 9000) y /ready ya está no sano. Dos requests en paralelo alcanzan el
# umbral de 2 timeouts en un solo read_timeout.
flaky_control "ready=503&business=200&delay=12000"

timeout_file_1="$(mktemp)"
timeout_file_2="$(mktemp)"
passive_delete_status "${res_token}" > "${timeout_file_1}" &
timeout_pid_1=$!
passive_delete_status "${res_token}" > "${timeout_file_2}" &
timeout_pid_2=$!
wait "${timeout_pid_1}"
wait "${timeout_pid_2}"

check "con /ready no sano pero sin sondeo de targets sanos, la request llega al upstream y corta por timeout (504)" \
  504 "$(cat "${timeout_file_1}")"
check "la segunda request en paralelo también corta por timeout (504)" \
  504 "$(cat "${timeout_file_2}")"
rm -f "${timeout_file_1}" "${timeout_file_2}"

# /ready sigue no sano, así que el activo no lo devuelve todavía: el 503 sólo
# puede ser la marca del pasivo.
check "los timeouts marcan el target como no sano: 503 del balanceador" \
  503 "$(passive_delete_status "${res_token}")"

flaky_control "ready=200&delay=0"

passive_timeout_recovered=""
for _ in $(seq 1 30); do
  passive_timeout_recovered="$(passive_delete_status "${res_token}")"
  if [[ "${passive_timeout_recovered}" != "503" ]]; then
    break
  fi
  sleep 1
done

check "al recuperarse /ready, el target marcado por timeouts vuelve al balanceo" \
  200 "${passive_timeout_recovered}"

# Errores de conexión: vehicle-service apunta a un contenedor que existe pero
# no tiene nada escuchando (conexión rechazada). Por el mismo motivo que arriba,
# la primera request llega al upstream y falla por conexión (502). Kong le
# reporta al pasivo un solo fallo por request (el final, no cada reintento),
# así que el umbral de 2 lo cruza la segunda request, que todavía recibe 502:
# el 503 del balanceador recién llega en la tercera.
check "con el puerto cerrado, la request falla por conexión (502) y no por el balanceador" \
  502 "$(passive_vehicles_status "${res_token}")"
check "la segunda falla por conexión también (502): cruza el umbral de 2" \
  502 "$(passive_vehicles_status "${res_token}")"
check "los errores de conexión marcan el target como no sano: 503 del balanceador" \
  503 "$(passive_vehicles_status "${res_token}")"

# El upstream empieza a escuchar: el activo lo detecta y lo devuelve.
docker exec -d "${LATE_UPSTREAM}" sh -c \
  'exec /usr/local/openresty/bin/openresty -c /conf/nginx.conf -p /tmp/flaky -g "daemon off;"'

passive_tcp_recovered=""
for _ in $(seq 1 30); do
  passive_tcp_recovered="$(passive_vehicles_status "${res_token}")"
  if [[ "${passive_tcp_recovered}" == "200" ]]; then
    break
  fi
  sleep 1
done

check "al empezar a escuchar el puerto, el target marcado por errores de conexión vuelve al balanceo" \
  200 "${passive_tcp_recovered}"

echo
echo "Guardia de arranque: los intervalos de sondeo no pueden ser 0"

guard_output="$(docker run --rm \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -e UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS=0 \
  vinculo-vial-gateway:integration 2>&1 || true)"

check_contains "con UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS=0 el Gateway no arranca" \
  "UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS debe ser un entero positivo" "${guard_output}"

# Con 0 en el intervalo de targets sanos, el activo no los sondea y un
# servicio con la base caída que sigue respondiendo 503 nunca saldría del
# balanceo. Sólo se permite declarando el modo test, que la suite usa para
# aislar el pasivo (cuarto Gateway, más arriba).
healthy_guard_output="$(docker run --rm \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -e UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS=0 \
  vinculo-vial-gateway:integration 2>&1 || true)"

check_contains "con UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS=0 el Gateway no arranca" \
  "UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS debe ser mayor que 0" "${healthy_guard_output}"

check_contains "con GATEWAY_TEST_MODE=true el Gateway acepta ese 0 y lo avisa por WARN" \
  "WARN: GATEWAY_TEST_MODE=true" "$(docker logs "${GATEWAY_PASSIVE}" 2>&1)"

echo
if (( failures > 0 )); then
  printf '\033[31m%d caso(s) fallaron\033[0m\n' "${failures}"
  echo
  echo "Logs del Gateway:"
  docker logs "${GATEWAY}" 2>&1 | grep -i "app-attestation" | tail -20
  exit 1
fi

printf '\033[32mTodos los casos de integración pasaron\033[0m\n'
