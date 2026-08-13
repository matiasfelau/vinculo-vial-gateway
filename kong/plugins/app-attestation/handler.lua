-- Plugin `app-attestation` — seguridad perimetral de US-01.
--
-- Valida el Mock App Attestation (`X-App-Attestation`): un JWT de vida corta,
-- firmado con HMAC-SHA256 contra una PSK compartida con la app, que simula el
-- veredicto de Google Play Integrity. Sin un token válido, la request no llega
-- a la red interna.
--
-- La lógica de validación es una función pura (`validate_token`) sin acceso al
-- entorno de request: el handler de Kong sólo la alimenta con el header y la
-- configuración. Eso es lo que permite testearla con Busted sin levantar Kong.
local cjson = require "cjson.safe"
local openssl_hmac = require "resty.openssl.hmac"
local bit = require "bit"
local errors = require "vv.errors"

local byte = string.byte
local bxor = bit.bxor
local bor = bit.bor
local decode_base64 = ngx.decode_base64

-- Prioridad 900: se ejecuta inmediatamente después del rate limiting global
-- (910). Es deliberado — un atacante que dispare atestaciones inválidas en
-- masa consume igual su cuota de rate limit antes de que lo rechacemos.
local PRIORITY = 900

-- Techo defensivo: un JWT de atestación legítimo pesa unos cientos de bytes.
local MAX_TOKEN_LENGTH = 4096

local AppAttestation = {
  PRIORITY = PRIORITY,
  VERSION = "1.0.0",
}

-- ── Utilidades ──────────────────────────────────────────────────────────────

-- Decodifica un segmento base64url (sin padding, como exige JWS).
local function decode_segment(segment)
  local normalized = segment:gsub("%-", "+"):gsub("_", "/")

  local remainder = #normalized % 4
  if remainder == 2 then
    normalized = normalized .. "=="
  elseif remainder == 3 then
    normalized = normalized .. "="
  elseif remainder ~= 0 then
    return nil
  end

  return decode_base64(normalized)
end

local function decode_json_segment(segment)
  local raw = decode_segment(segment)
  if not raw then
    return nil
  end

  local decoded = cjson.decode(raw)
  if type(decoded) ~= "table" then
    return nil
  end

  return decoded
end

local function hmac_sha256(key, message)
  local hmac, err = openssl_hmac.new(key, "sha256")
  if not hmac then
    return nil, err
  end

  local ok, update_err = hmac:update(message)
  if not ok then
    return nil, update_err
  end

  return hmac:final()
end

-- Comparación en tiempo constante: evita filtrar por temporización cuántos
-- bytes de la firma acertó quien la fabricó.
local function constant_time_equals(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
    return false
  end

  local diff = 0
  for i = 1, #a do
    diff = bor(diff, bxor(byte(a, i), byte(b, i)))
  end

  return diff == 0
end

-- `aud` puede ser un string o una lista, según RFC 7519.
local function audience_matches(claim, expected)
  if type(claim) == "string" then
    return claim == expected
  end

  if type(claim) == "table" then
    for _, value in ipairs(claim) do
      if value == expected then
        return true
      end
    end
  end

  return false
end

-- El veredicto de dispositivo de Play Integrity es una lista de etiquetas; se
-- exigen todas las requeridas.
local function device_verdicts_satisfied(claim, required)
  local present = {}

  if type(claim) == "string" then
    present[claim] = true
  elseif type(claim) == "table" then
    for _, value in ipairs(claim) do
      present[value] = true
    end
  else
    return false
  end

  for _, expected in ipairs(required or {}) do
    if not present[expected] then
      return false
    end
  end

  return true
end

-- ── Validación (función pura, testeable con Busted) ─────────────────────────

--- Valida un token de atestación.
-- @param token string|nil valor crudo del header `X-App-Attestation`
-- @param conf table configuración del plugin (ver schema.lua)
-- @param now number|nil timestamp UNIX; por defecto, el reloj de nginx
-- @return true en caso de token válido
-- @return nil, string motivo interno del rechazo (para logs, nunca al cliente)
function AppAttestation.validate_token(token, conf, now)
  if type(token) ~= "string" or token == "" then
    return nil, "missing_header"
  end

  if #token > MAX_TOKEN_LENGTH then
    return nil, "token_too_large"
  end

  local header_b64, payload_b64, signature_b64 =
    token:match("^([%w_%-]+)%.([%w_%-]+)%.([%w_%-]+)$")
  if not header_b64 then
    return nil, "malformed_token"
  end

  local header = decode_json_segment(header_b64)
  if not header then
    return nil, "malformed_header"
  end

  -- Sólo HMAC-SHA256. Rechazar cualquier otro `alg` cierra la puerta a
  -- `alg: none` y a confusión de algoritmos.
  if header.alg ~= "HS256" then
    return nil, "unsupported_alg"
  end

  -- La firma se verifica antes de mirar los claims: nada de lo que venga en el
  -- payload merece confianza hasta ese punto.
  local expected_signature, hmac_err =
    hmac_sha256(conf.psk, header_b64 .. "." .. payload_b64)
  if not expected_signature then
    return nil, "hmac_error: " .. tostring(hmac_err)
  end

  if not constant_time_equals(expected_signature, decode_segment(signature_b64)) then
    return nil, "invalid_signature"
  end

  local claims = decode_json_segment(payload_b64)
  if not claims then
    return nil, "malformed_claims"
  end

  now = now or ngx.now()
  local skew = conf.clock_skew_seconds or 0

  if type(claims.exp) ~= "number" then
    return nil, "missing_exp"
  end
  if now > claims.exp + skew then
    return nil, "expired_token"
  end

  if type(claims.iat) ~= "number" then
    return nil, "missing_iat"
  end
  if claims.iat - skew > now then
    return nil, "iat_in_future"
  end
  -- Vida máxima efectiva del token, independiente del `exp` que haya elegido
  -- la app: acota la ventana de replay.
  if now - claims.iat > conf.max_age_seconds + skew then
    return nil, "token_too_old"
  end

  if claims.nbf ~= nil then
    if type(claims.nbf) ~= "number" then
      return nil, "malformed_nbf"
    end
    if now + skew < claims.nbf then
      return nil, "token_not_yet_valid"
    end
  end

  if conf.expected_issuer and claims.iss ~= conf.expected_issuer then
    return nil, "issuer_mismatch"
  end

  if conf.expected_audience
    and not audience_matches(claims.aud, conf.expected_audience) then
    return nil, "audience_mismatch"
  end

  if claims.appRecognitionVerdict ~= conf.required_app_verdict then
    return nil, "app_verdict_rejected"
  end

  if not device_verdicts_satisfied(claims.deviceRecognitionVerdict,
                                   conf.required_device_verdicts) then
    return nil, "device_verdict_rejected"
  end

  return true
end

-- ── Fase de request ─────────────────────────────────────────────────────────

function AppAttestation:access(conf)
  local token = kong.request.get_header(conf.header_name)

  local ok, reason = AppAttestation.validate_token(token, conf)
  if not ok then
    -- El motivo interno va al log; la respuesta es siempre la misma. Nunca se
    -- loguea el token ni la PSK.
    return errors.exit(errors.INVALID_ATTESTATION,
                       "app-attestation: request rechazado (" .. reason .. ")")
  end

  -- El token cumplió su función en el perímetro; no se propaga hacia adentro.
  if conf.strip_header then
    kong.service.request.clear_header(conf.header_name)
  end
end

return AppAttestation
