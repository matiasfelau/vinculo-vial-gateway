-- Plugin `token-offloading`.
--
-- Descarga a los servicios internos de todo lo relativo a la sesión: el JWT lo
-- verifica el plugin nativo `jwt` en el perímetro y este plugin traduce el
-- claim de identidad a un header simple (`X-User-Hash`), removiendo el
-- `Authorization` antes de reenviar. El upstream confía en el header porque
-- llegó por la red interna, detrás del Gateway.
--
-- Como en `app-attestation`, la extracción del claim es una función pura y
-- testeable; el handler sólo la conecta con el request.
local cjson = require "cjson.safe"

local decode_base64 = ngx.decode_base64

-- Prioridad 890: después del plugin `jwt` (1450), que es quien verifica la
-- firma y deja el token validado en `ngx.ctx`, y después de `app-attestation`
-- (900).
local PRIORITY = 890

-- Un identificador de usuario no tiene por qué ser largo; el techo evita que
-- un token raro genere un header desmedido.
local MAX_CLAIM_LENGTH = 256

local UNAUTHORIZED_STATUS = 401
local UNAUTHORIZED_BODY = {
  error = "unauthorized",
  reason = "invalid_token",
}
local JSON_HEADERS = { ["Content-Type"] = "application/json; charset=utf-8" }

local TokenOffloading = {
  PRIORITY = PRIORITY,
  VERSION = "1.0.0",
}

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

--- Extrae un claim del JWT ya verificado por el plugin `jwt`.
-- No se vuelve a validar la firma: eso ya ocurrió aguas arriba. Sí se valida
-- que el valor sea utilizable como header, para no reinyectar basura hacia
-- adentro.
-- @param token string JWT compacto
-- @param claim_name string claim a extraer
-- @return string valor del claim
-- @return nil, string motivo interno del fallo
function TokenOffloading.extract_claim(token, claim_name)
  if type(token) ~= "string" or token == "" then
    return nil, "missing_token"
  end

  local _, payload_b64 = token:match("^([%w_%-]+)%.([%w_%-]+)%.([%w_%-]+)$")
  if not payload_b64 then
    return nil, "malformed_token"
  end

  local raw = decode_segment(payload_b64)
  if not raw then
    return nil, "malformed_payload"
  end

  local claims = cjson.decode(raw)
  if type(claims) ~= "table" then
    return nil, "malformed_payload"
  end

  local value = claims[claim_name]
  if value == nil then
    return nil, "missing_claim"
  end

  if type(value) == "number" then
    value = tostring(value)
  elseif type(value) ~= "string" then
    return nil, "invalid_claim"
  end

  if value == "" or #value > MAX_CLAIM_LENGTH then
    return nil, "invalid_claim"
  end

  -- Un CR/LF en el valor permitiría inyectar headers arbitrarios al upstream.
  if value:find("%c") then
    return nil, "invalid_claim"
  end

  return value
end

function TokenOffloading:access(conf)
  -- Anti-spoofing: el header de identidad se descarta siempre, para que nadie
  -- lo pueda inyectar desde afuera. Sólo lo escribe este plugin.
  kong.service.request.clear_header(conf.header_name)

  -- El plugin `jwt` deja acá el token ya verificado.
  local token = ngx.ctx.authenticated_jwt_token

  local value, reason = TokenOffloading.extract_claim(token, conf.claim)
  if not value then
    kong.log.warn("token-offloading: no se pudo derivar la identidad (", reason, ")")
    return kong.response.exit(UNAUTHORIZED_STATUS, UNAUTHORIZED_BODY, JSON_HEADERS)
  end

  kong.service.request.set_header(conf.header_name, value)

  if conf.remove_authorization then
    kong.service.request.clear_header("Authorization")
  end
end

return TokenOffloading
