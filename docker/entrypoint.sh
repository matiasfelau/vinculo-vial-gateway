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
  APP_ATTESTATION_PSK
  ATTESTATION_TOKEN_TTL_SECONDS
  RATE_LIMIT_PER_MINUTE
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

# Falla temprano y con un mensaje claro si la configuración resultante no es
# válida, en lugar de dejar que Kong muera a mitad del arranque.
if ! kong config parse "${RENDERED}" >/dev/null; then
  echo "FATAL: la configuración declarativa renderizada no es válida" >&2
  exit 1
fi

exec /docker-entrypoint.sh "$@"
