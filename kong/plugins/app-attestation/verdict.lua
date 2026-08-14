-- Política de atestación: evalúa un veredicto de Play Integrity.
--
-- Trabaja sobre la forma canónica de Google (`tokenPayloadExternal`), venga de
-- donde venga: de `decodeIntegrityToken` en producción o del mock firmado con
-- PSK en CI. Ésa es la razón de separar política de fuente — la decisión de
-- seguridad es una sola y se testea una sola vez.
--
--   {
--     "requestDetails": { "requestPackageName", "requestHash"|"nonce",
--                         "timestampMillis" },
--     "appIntegrity":   { "appRecognitionVerdict", "packageName",
--                         "certificateSha256Digest" },
--     "deviceIntegrity":{ "deviceRecognitionVerdict": [...] },
--     "accountDetails": { "appLicensingVerdict" }
--   }
--
-- Función pura: no toca el request ni el reloj (el `now` se recibe). Es lo que
-- permite testear cada rama con Busted sin levantar Kong.
local constant_time = require "vv.constant_time"

local M = {}

-- Convierte a conjunto un campo que Google documenta como lista pero que
-- conviene tolerar como escalar.
local function to_set(value)
  local set = {}

  if type(value) == "string" then
    set[value] = true
  elseif type(value) == "table" then
    for _, item in ipairs(value) do
      set[item] = true
    end
  end

  return set
end

-- ¿Alguno de los valores presentados está entre los aceptados?
local function intersects(presented, accepted)
  local present = to_set(presented)

  for _, candidate in ipairs(accepted or {}) do
    if present[candidate] then
      return true
    end
  end

  return false
end

local function is_accepted(value, accepted)
  for _, candidate in ipairs(accepted or {}) do
    if value == candidate then
      return true
    end
  end

  return false
end

--- Evalúa el veredicto contra la política configurada.
-- @param verdict table `tokenPayloadExternal`
-- @param conf table configuración del plugin
-- @param body_hash string|nil hash del body en el encoding configurado
-- @param now number timestamp UNIX en segundos
-- @return true si la atestación es aceptable
-- @return nil, string motivo interno del rechazo (para logs, nunca al cliente)
function M.evaluate(verdict, conf, body_hash, now)
  if type(verdict) ~= "table" then
    return nil, "malformed_verdict"
  end

  -- ── requestDetails ────────────────────────────────────────────────────────
  local request_details = verdict.requestDetails
  if type(request_details) ~= "table" then
    return nil, "missing_request_details"
  end

  if conf.package_name
    and request_details.requestPackageName ~= conf.package_name then
    return nil, "request_package_mismatch"
  end

  -- Google lo emite como string de milisegundos. Es el reloj de Google, no el
  -- del dispositivo: es el control de frescura en el que se puede confiar.
  local timestamp_millis = tonumber(request_details.timestampMillis)
  if not timestamp_millis then
    return nil, "missing_timestamp"
  end

  local issued_at = timestamp_millis / 1000
  local skew = conf.clock_skew_seconds or 0

  if issued_at - skew > now then
    return nil, "timestamp_in_future"
  end

  if now - issued_at > conf.max_age_seconds + skew then
    return nil, "attestation_too_old"
  end

  -- Ligadura con el body: el hash lo eligió la app al pedir el token y Google
  -- lo devuelve tal cual, así que atarlo al body que efectivamente llegó
  -- impide reusar una atestación válida sobre otro payload.
  if conf.require_request_hash then
    -- `requestHash` en el flujo estándar; `nonce` en el clásico.
    local presented = request_details.requestHash or request_details.nonce

    if type(presented) ~= "string" or presented == "" then
      return nil, "missing_request_hash"
    end

    if type(body_hash) ~= "string" then
      return nil, "body_hash_unavailable"
    end

    if not constant_time.equals(presented, body_hash) then
      return nil, "request_hash_mismatch"
    end
  end

  -- ── appIntegrity ──────────────────────────────────────────────────────────
  local app_integrity = verdict.appIntegrity
  if type(app_integrity) ~= "table" then
    return nil, "missing_app_integrity"
  end

  if not is_accepted(app_integrity.appRecognitionVerdict,
                     conf.accepted_app_verdicts) then
    return nil, "app_verdict_rejected"
  end

  if conf.package_name
    and app_integrity.packageName ~= nil
    and app_integrity.packageName ~= conf.package_name then
    return nil, "app_package_mismatch"
  end

  -- Ata la atestación al certificado de firma de la app: sin esto, un APK
  -- republicado con el mismo package name por otro desarrollador pasaría.
  local expected_digests = conf.expected_certificate_digests
  if expected_digests and #expected_digests > 0 then
    if not intersects(app_integrity.certificateSha256Digest, expected_digests) then
      return nil, "certificate_digest_rejected"
    end
  end

  -- ── deviceIntegrity ───────────────────────────────────────────────────────
  local device_integrity = verdict.deviceIntegrity
  if type(device_integrity) ~= "table" then
    return nil, "missing_device_integrity"
  end

  -- Semántica "alguno de", no "todos": los veredictos de Google son niveles
  -- acumulativos (un dispositivo con MEETS_STRONG_INTEGRITY reporta también
  -- MEETS_DEVICE_INTEGRITY). Una lista vacía es la señal de dispositivo
  -- rooteado o manipulado, y no interseca con nada.
  if not intersects(device_integrity.deviceRecognitionVerdict,
                    conf.accepted_device_verdicts) then
    return nil, "device_verdict_rejected"
  end

  -- ── accountDetails (opcional) ─────────────────────────────────────────────
  local accepted_licensing = conf.accepted_licensing_verdicts
  if accepted_licensing and #accepted_licensing > 0 then
    local account_details = verdict.accountDetails
    if type(account_details) ~= "table" then
      return nil, "missing_account_details"
    end

    if not is_accepted(account_details.appLicensingVerdict, accepted_licensing) then
      return nil, "licensing_verdict_rejected"
    end
  end

  return true
end

return M
