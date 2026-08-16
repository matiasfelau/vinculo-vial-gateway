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

-- Lee un campo sin asumir que el objeto que lo contiene exista.
local function field_of(container, key)
  if type(container) ~= "table" then
    return nil
  end

  return container[key]
end

-- Largo máximo de un valor interpolado en el detalle que va al log.
local MAX_DETAIL_LENGTH = 120

-- Formatea un valor recibido para el log del operador.
--
-- Lo que se interpola sale de la respuesta de Google: no es secreto ni PII
-- (nombres de paquete, veredictos, hashes), pero se sanea igual — un salto de
-- línea en el valor permitiría inyectar una entrada de log falsa.
local function describe(value)
  if value == nil then
    return "ausente"
  end

  if type(value) == "table" then
    local items = {}
    for _, item in ipairs(value) do
      items[#items + 1] = describe(item)
    end

    return "[" .. table.concat(items, ", ") .. "]"
  end

  local text = (tostring(value):gsub("%c", " "))
  if #text > MAX_DETAIL_LENGTH then
    text = text:sub(1, MAX_DETAIL_LENGTH) .. "…"
  end

  return "'" .. text .. "'"
end

-- Verifica para qué app se emitió la atestación.
--
-- La identidad aparece en hasta dos lugares del veredicto, y Google no siempre
-- puebla los dos: la Standard API puede omitir
-- `requestDetails.requestPackageName` y dejar la identidad sólo en
-- `appIntegrity.packageName`. Exigir el primero rechazaría atestaciones
-- perfectamente válidas.
--
-- El criterio es: TODOS los valores presentes tienen que coincidir, y tiene que
-- haber al menos uno. Que falten los dos no se puede aceptar — sin ninguno no
-- hay forma de saber para qué app se emitió la atestación, y un token de
-- cualquier otra app pasaría.
local function check_package(verdict, expected)
  if not expected then
    return true
  end

  local sources = {
    {
      field = "requestDetails.requestPackageName",
      value = field_of(verdict.requestDetails, "requestPackageName"),
    },
    {
      field = "appIntegrity.packageName",
      value = field_of(verdict.appIntegrity, "packageName"),
    },
  }

  local found = false

  for _, source in ipairs(sources) do
    if type(source.value) == "string" and source.value ~= "" then
      found = true

      if source.value ~= expected then
        return nil, "package_mismatch",
          source.field .. "=" .. describe(source.value)
            .. ", esperado=" .. describe(expected)
      end
    end
  end

  if not found then
    return nil, "package_name_absent",
      "el veredicto no trae requestDetails.requestPackageName "
        .. "ni appIntegrity.packageName"
  end

  return true
end

--- Evalúa el veredicto contra la política configurada.
-- @param verdict table `tokenPayloadExternal`
-- @param conf table configuración del plugin
-- @param body_hash string|nil hash del body en el encoding configurado
-- @param now number timestamp UNIX en segundos
-- @return true si la atestación es aceptable
-- @return nil, string motivo interno del rechazo (para logs, nunca al cliente)
-- @return string|nil detalle del rechazo para el log: qué se recibió frente a
--         qué se esperaba. Tampoco sale al cliente.
function M.evaluate(verdict, conf, body_hash, now)
  if type(verdict) ~= "table" then
    return nil, "malformed_verdict"
  end

  -- ── requestDetails ────────────────────────────────────────────────────────
  local request_details = verdict.requestDetails
  if type(request_details) ~= "table" then
    return nil, "missing_request_details"
  end

  -- Identidad de la app: mira las dos ubicaciones posibles a la vez.
  local package_ok, package_reason, package_detail =
    check_package(verdict, conf.package_name)
  if not package_ok then
    return nil, package_reason, package_detail
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
      -- El error de integración más frecuente: la app hashea un payload y
      -- envía otro (re-serializado), o usa otro encoding que el configurado.
      -- Ver los dos valores es lo que distingue un caso del otro.
      return nil, "request_hash_mismatch",
        "veredicto=" .. describe(presented)
          .. ", body=" .. describe(body_hash)
          .. ", encoding=" .. describe(conf.request_hash_encoding)
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

  -- `appIntegrity.packageName` ya se verificó junto con
  -- `requestDetails.requestPackageName` en `check_package`.

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
    return nil, "device_verdict_rejected",
      "recibido=" .. describe(device_integrity.deviceRecognitionVerdict)
        .. ", aceptados=" .. describe(conf.accepted_device_verdicts)
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
