-- Fuente de veredictos: Google Play Integrity API.
--
-- El token que emite Play Integrity es opaco (un JWE anidado). En lugar de
-- desencriptarlo acá, se lo manda a `decodeIntegrityToken`, que lo devuelve
-- descifrado y verificado. La contra es un round-trip a Google en el camino
-- del request; a cambio, las claves de desencriptado las gestiona Google y no
-- hay material criptográfico que rotar en el Gateway.
local cjson = require "cjson.safe"
local http = require "resty.http"

local google_oauth = require "kong.plugins.app-attestation.google_oauth"

local M = {}

--- Interpreta la respuesta de `decodeIntegrityToken`. Pura, para testearla
--- sin red.
-- @return table `tokenPayloadExternal`
-- @return nil, string motivo interno del rechazo
function M.parse_response(status, body)
  if status == 400 then
    -- Google rechaza el token: manipulado, de otra app, o ya expirado.
    return nil, "playintegrity_token_rejected"
  end

  if status == 401 or status == 403 then
    -- Problema de credenciales del Gateway, no del cliente.
    return nil, "playintegrity_unauthorized"
  end

  if status ~= 200 then
    return nil, "playintegrity_http_" .. tostring(status)
  end

  local parsed = cjson.decode(body)
  if type(parsed) ~= "table" then
    return nil, "playintegrity_malformed_response"
  end

  local payload = parsed.tokenPayloadExternal
  if type(payload) ~= "table" then
    return nil, "playintegrity_missing_payload"
  end

  return payload
end

--- Canjea el token de integridad por su veredicto.
-- @param token string token opaco emitido por Play Integrity en el dispositivo
-- @param conf table configuración del plugin
-- @return table veredicto canónico
-- @return nil, string motivo interno del rechazo
function M.fetch(token, conf)
  local access_token, oauth_err = google_oauth.get_access_token(conf)
  if not access_token then
    return nil, oauth_err
  end

  local url = conf.playintegrity_url
    .. "/v1/"
    .. ngx.escape_uri(conf.package_name)
    .. ":decodeIntegrityToken"

  local client = http.new()
  client:set_timeout(conf.http_timeout_ms)

  local res, request_err = client:request_uri(url, {
    method = "POST",
    body = cjson.encode({ integrity_token = token }),
    headers = {
      ["Authorization"] = "Bearer " .. access_token,
      ["Content-Type"] = "application/json",
    },
    ssl_verify = conf.ssl_verify,
  })

  if not res then
    -- Google inalcanzable. Se falla cerrado: sin veredicto no se deja pasar
    -- tráfico a la red interna, que es justamente lo que este plugin protege.
    return nil, "playintegrity_unreachable: " .. tostring(request_err)
  end

  return M.parse_response(res.status, res.body)
end

return M
