-- Plugin `app-attestation` — seguridad perimetral.
--
-- Valida que la request venga de una instalación legítima de la app en un
-- dispositivo íntegro, usando Google Play Integrity. Sin una atestación
-- aceptable, la request no alcanza la red interna.
--
-- El handler sólo orquesta; toda la lógica decidible vive en módulos puros que
-- se testean con Busted sin levantar Kong:
--
--   sources/*      de dónde sale el veredicto (Google en producción, mock en CI)
--   verdict.lua    qué veredictos se aceptan
--   request_hash   ligadura de la atestación con el body concreto
--   replay_guard   consumo de un solo uso
local errors = require "vv.errors"

local verdict_policy = require "kong.plugins.app-attestation.verdict"
local request_hash = require "kong.plugins.app-attestation.request_hash"
local replay_guard = require "kong.plugins.app-attestation.replay_guard"

local SOURCES = {
  google = require "kong.plugins.app-attestation.sources.google",
  mock = require "kong.plugins.app-attestation.sources.mock",
}

-- Prioridad 900: se ejecuta inmediatamente después del rate limiting global
-- (910). Es deliberado — quien dispare atestaciones inválidas en masa consume
-- igual su cuota antes de que lo rechacemos, y antes de que gastemos una
-- llamada a Google por cada intento.
local AppAttestation = {
  PRIORITY = 900,
  VERSION = "2.0.0",
}

-- El motivo va al log; al cliente siempre le llega la misma respuesta. El
-- `detail` es para el operador: dice qué se recibió frente a qué se esperaba,
-- que es lo único que permite distinguir una app mal configurada de un ataque.
local function reject(reason, detail)
  local message = "app-attestation: request rechazado (" .. reason .. ")"

  if detail then
    message = message .. " — " .. detail
  end

  return errors.exit(errors.INVALID_ATTESTATION, message)
end

function AppAttestation:access(conf)
  local token = kong.request.get_header(conf.header_name)

  -- Si el header viene repetido, el PDK devuelve una tabla: no es un token
  -- legítimo y se rechaza sin más análisis.
  if type(token) ~= "string" or token == "" then
    return reject("missing_header")
  end

  if #token > conf.max_token_bytes then
    return reject("token_too_large")
  end

  -- Descarta repeticiones evidentes antes de gastar una llamada a Google. El
  -- registro definitivo se hace recién cuando el veredicto llegó bien, para
  -- que una caída de Google no queme tokens que el usuario no pudo usar.
  local fingerprint = replay_guard.fingerprint(token)
  if conf.replay_guard and replay_guard.seen(fingerprint) then
    return reject("replay_detected")
  end

  -- Hash del body para la ligadura con el veredicto. Se lee crudo y se
  -- reenvía intacto: el Gateway no lo interpreta ni podría (viaja cifrado E2E).
  local body_hash
  if conf.require_request_hash then
    local raw_body, body_err = kong.request.get_raw_body()
    if not raw_body then
      -- Ocurre si el body no entró en `client_body_buffer_size`. Es una
      -- desconfiguración del Gateway, no un ataque, pero se falla cerrado.
      return reject("body_unavailable: " .. tostring(body_err))
    end

    local hash, hash_err = request_hash.compute(raw_body, conf.request_hash_encoding)
    if not hash then
      return reject(hash_err)
    end

    body_hash = hash
  end

  local source = SOURCES[conf.source]
  local verdict, source_err = source.fetch(token, conf)
  if not verdict then
    return reject(source_err)
  end

  -- Consumo definitivo: entre dos requests concurrentes con el mismo token,
  -- sólo una se lo queda.
  if conf.replay_guard then
    local consumed, replay_err =
      replay_guard.consume(fingerprint, conf.max_age_seconds + conf.clock_skew_seconds)

    if not consumed then
      return reject(replay_err)
    end
  end

  local ok, policy_err, policy_detail =
    verdict_policy.evaluate(verdict, conf, body_hash, ngx.now())
  if not ok then
    return reject(policy_err, policy_detail)
  end

  -- El token cumplió su función en el perímetro; no se propaga hacia adentro.
  if conf.strip_header then
    kong.service.request.clear_header(conf.header_name)
  end
end

return AppAttestation
