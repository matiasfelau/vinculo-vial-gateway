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
readonly PACKAGE_NAME=ar.vinculovial.app

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

# SHA-256 del body en hexadecimal: lo mismo que calcula el Gateway y lo que el
# Frontend le pasa a `setRequestHash()`.
body_hash() {
  docker exec "${GATEWAY}" sh -c "printf '%s' '$1' | sha256sum | cut -d' ' -f1"
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
docker run --rm --entrypoint sh kong:3.7 -c '
  openssl genrsa 2048 2>/dev/null
' > "${sa_dir}/private.pem"

docker run --rm -v "$(to_host_path "${sa_dir}"):/sa" --entrypoint resty kong:3.7 -e '
  local cjson = require "cjson.safe"
  local file = assert(io.open("/sa/private.pem"))
  local private_key = file:read("*a")
  file:close()

  local out = assert(io.open("/sa/google-service-account.json", "w"))
  out:write(cjson.encode({
    type = "service_account",
    project_id = "vinculo-vial-test",
    private_key_id = "stub-key-id",
    private_key = private_key,
    client_email = "gateway@vinculo-vial-test.iam.gserviceaccount.com",
    token_uri = "http://vv-it-google:8080/token",
  }))
  out:close()
'

echo "==> Levantando el Gateway"
docker run -d --name "${GATEWAY}" --network "${NETWORK}" \
  --env-file "$(to_host_path "${REPO_ROOT}/.env.example")" \
  -v "$(to_host_path "${sa_dir}/google-service-account.json"):/etc/vinculo-vial/google-service-account.json:ro" \
  -e "IDENTITY_SERVICE_URL=http://${UPSTREAM}:8080" \
  -e "PLAY_INTEGRITY_URL=http://${STUB}:8080" \
  -e "PLAY_PACKAGE_NAME=${PACKAGE_NAME}" \
  -e ATTESTATION_SOURCE=google \
  -e ATTESTATION_SSL_VERIFY=false \
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
if (( failures > 0 )); then
  printf '\033[31m%d caso(s) fallaron\033[0m\n' "${failures}"
  echo
  echo "Logs del Gateway:"
  docker logs "${GATEWAY}" 2>&1 | grep -i "app-attestation" | tail -20
  exit 1
fi

printf '\033[32mTodos los casos de integración pasaron\033[0m\n'
