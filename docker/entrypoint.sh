#!/usr/bin/env bash
#
# Renderiza la configuración declarativa de Kong y delega en el entrypoint de
# la imagen oficial.
#
# Kong DB-less no interpola variables de entorno dentro del kong.yml, así que
# se resuelven acá, en el arranque: el repo versiona una plantilla sin secretos
# y el contenedor genera el archivo final.
set -euo pipefail

TEMPLATE="${GATEWAY_DECLARATIVE_TEMPLATE:-/etc/kong/kong.yml.template}"
RENDERED="${KONG_DECLARATIVE_CONFIG:-/tmp/kong.declarative.yml}"

# Variables que la plantilla espera. Se listan explícitamente para que envsubst
# sustituya sólo éstas: cualquier otro `$` del YAML queda intacto.
REQUIRED_VARS=(
  IDENTITY_SERVICE_URL
  VEHICLE_SERVICE_URL
  ALERT_SERVICE_URL
  NOTIFICATION_SERVICE_URL
  ATTESTATION_SOURCE
  PLAY_PACKAGE_NAME
  GOOGLE_SERVICE_ACCOUNT_PATH
  PLAY_INTEGRITY_URL
  ATTESTATION_SSL_VERIFY
  APP_ATTESTATION_PSK
  ATTESTATION_APP_VERDICTS
  ATTESTATION_DEVICE_VERDICTS
  ATTESTATION_MAX_AGE_SECONDS
  ATTESTATION_REQUEST_HASH_ENCODING
  ATTESTATION_DEPENDENCY_TIMEOUT_MS
  ATTESTATION_DEPENDENCY_CALL_TIMEOUT_MS
  RATE_LIMIT_PER_MINUTE
  SIGNUP_MAX_BODY_MB
  SIGNIN_MAX_BODY_KB
  JWT_ISSUER
  JWT_PUBLIC_KEY
)

missing=()
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    missing+=("$var")
  fi
done

if (( ${#missing[@]} > 0 )); then
  # Se listan los nombres, nunca los valores.
  echo "FATAL: faltan variables de entorno requeridas: ${missing[*]}" >&2
  echo "       Copiar .env.example a .env y completarlo." >&2
  exit 1
fi

substitutions=""
for var in "${REQUIRED_VARS[@]}"; do
  substitutions+="\${${var}} "
done

envsubst "${substitutions}" < "${TEMPLATE}" > "${RENDERED}"

# El service account sólo se lee en la primera request, así que una ruta mal
# puesta se manifestaría como "todo el tráfico rechazado" en producción y no
# en el arranque. Se avisa acá, sin abortar: `mock` no lo necesita, y un
# volumen puede montarse después del arranque.
if [[ "${ATTESTATION_SOURCE}" == "google" && ! -r "${GOOGLE_SERVICE_ACCOUNT_PATH}" ]]; then
  echo "WARN: ATTESTATION_SOURCE=google pero no se puede leer" >&2
  echo "      ${GOOGLE_SERVICE_ACCOUNT_PATH}" >&2
  echo "      Toda atestación va a fallar hasta que el archivo esté montado." >&2
fi

# Falla temprano y con un mensaje claro si la configuración resultante no es
# válida, en lugar de dejar que Kong muera a mitad del arranque.
if ! kong config parse "${RENDERED}" >/dev/null; then
  echo "FATAL: la configuración declarativa renderizada no es válida" >&2
  exit 1
fi

exec /docker-entrypoint.sh "$@"
