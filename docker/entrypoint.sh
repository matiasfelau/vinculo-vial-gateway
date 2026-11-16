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
  BENEFITS_SERVICE_URL
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
  UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS
  UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS
  UPSTREAM_HEALTHCHECK_TIMEOUT_SECONDS
  UPSTREAM_HEALTHCHECK_HEALTHY_THRESHOLD
  UPSTREAM_HEALTHCHECK_UNHEALTHY_THRESHOLD
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

# Con un intervalo de 0 Kong no vuelve a sondear un target marcado no sano:
# un corte breve de su base lo dejaría fuera del balanceo para siempre. Es el
# único valor de healthcheck cuyo error no se nota hasta que ocurre la caída,
# así que se rechaza en el arranque.
if ! [[ "${UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "FATAL: UPSTREAM_HEALTHCHECK_INTERVAL_SECONDS debe ser un entero positivo" >&2
  echo "       (con 0 un target no sano no vuelve a sondearse y no se recupera)." >&2
  exit 1
fi

# Con 0 en el intervalo de targets SANOS el activo no los sondea: un servicio
# con la base caída que sigue respondiendo 503 nunca saldría del balanceo, lo
# opuesto al contrato (la salud la decide /ready). Sólo la suite de integración
# lo necesita en 0, para aislar el healthcheck pasivo, y lo declara con
# GATEWAY_TEST_MODE=true; en cualquier otro caso se rechaza en el arranque.
if ! [[ "${UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "FATAL: UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS debe ser un entero" >&2
  exit 1
fi

if [[ "${GATEWAY_TEST_MODE:-}" == "true" ]]; then
  echo "WARN: GATEWAY_TEST_MODE=true. Se permite UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS=0." >&2
  echo "      No usar fuera de la suite de integración." >&2
elif [[ "${UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS}" == "0" ]]; then
  echo "FATAL: UPSTREAM_HEALTHCHECK_HEALTHY_INTERVAL_SECONDS debe ser mayor que 0" >&2
  echo "       (con 0 el healthcheck activo no sondea targets sanos y un servicio con" >&2
  echo "       su base caída que responde 503 nunca sale del balanceo)." >&2
  exit 1
fi

# La plantilla referencia protocolo/host:puerto de cada upstream por separado
# (el Service necesita protocolo y puerto; el target de su Upstream necesita
# host:puerto), pero quien despliega sigue configurando una sola URL completa
# por servicio (*_SERVICE_URL, como siempre): se derivan acá para no pedirle
# que mantenga la misma información sincronizada en dos variables.
derive_url_parts() {
  local url="$1" prefix="$2"

  export "${prefix}_PROTOCOL=${url%%://*}"
  export "${prefix}_TARGET=${url#*://}"
  export "${prefix}_PORT=${url##*:}"
}

derive_url_parts "${IDENTITY_SERVICE_URL}" IDENTITY_SERVICE
derive_url_parts "${VEHICLE_SERVICE_URL}" VEHICLE_SERVICE
derive_url_parts "${ALERT_SERVICE_URL}" ALERT_SERVICE
derive_url_parts "${NOTIFICATION_SERVICE_URL}" NOTIFICATION_SERVICE
derive_url_parts "${BENEFITS_SERVICE_URL}" BENEFITS_SERVICE

DERIVED_VARS=(
  IDENTITY_SERVICE_PROTOCOL IDENTITY_SERVICE_TARGET IDENTITY_SERVICE_PORT
  VEHICLE_SERVICE_PROTOCOL VEHICLE_SERVICE_TARGET VEHICLE_SERVICE_PORT
  ALERT_SERVICE_PROTOCOL ALERT_SERVICE_TARGET ALERT_SERVICE_PORT
  NOTIFICATION_SERVICE_PROTOCOL NOTIFICATION_SERVICE_TARGET NOTIFICATION_SERVICE_PORT
  BENEFITS_SERVICE_PROTOCOL BENEFITS_SERVICE_TARGET BENEFITS_SERVICE_PORT
)

substitutions=""
for var in "${REQUIRED_VARS[@]}" "${DERIVED_VARS[@]}"; do
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
