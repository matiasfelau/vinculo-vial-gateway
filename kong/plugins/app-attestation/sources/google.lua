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
-- @return nil, string motivo interno del rechazo, string clasificación del
--         fallo ("upstream_error" si Google respondió 5xx o un cuerpo fuera
--         de contrato; "rejected" para un token de cliente inválido;
--         "gateway_fault" para un problema de credenciales o configuración
--         propias — ninguno de los tres es "Google caído")
function M.parse_response(status, body)
  if status == 400 then
    -- Google rechaza el TOKEN DEL CLIENTE: manipulado, de otra app, o ya
    -- expirado. Responsabilidad del cliente, no nuestra.
    return nil, "playintegrity_token_rejected", "rejected"
  end

  if status == 401 or status == 403 then
    -- Nuestro access token de OAuth es inválido: defecto propio del
    -- Gateway. No es "Google caído" (502/503) ni "token del cliente
    -- rechazado" (403 invalid_attestation) — tratarlo como cualquiera de
    -- los dos oculta un error de configuración detrás de una respuesta que
    -- sugiere que el problema es ajeno.
    return nil, "playintegrity_unauthorized", "gateway_fault"
  end

  if status ~= 200 then
    -- Cualquier otro código no documentado por esta API: un 5xx es la
    -- dependencia fallando; cualquier otro 4xx es, por descarte, algo mal
    -- armado de nuestro lado — no hay otro 4xx que Google documente como
    -- atribuible al cliente.
    local kind = status >= 500 and "upstream_error" or "gateway_fault"
    return nil, "playintegrity_http_" .. tostring(status), kind
  end

  local parsed = cjson.decode(body)
  if type(parsed) ~= "table" then
    return nil, "playintegrity_malformed_response", "upstream_error"
  end

  local payload = parsed.tokenPayloadExternal
  if type(payload) ~= "table" then
    return nil, "playintegrity_missing_payload", "upstream_error"
  end

  return payload
end

--- Canjea el token de integridad por su veredicto.
--
-- El canje de OAuth y el POST a decodeIntegrityToken comparten un único
-- presupuesto agregado (`conf.dependency_timeout_ms`): lo que consume el
-- primero se descuenta del segundo, nunca se duplica. Cada llamada además
-- respeta su propio techo (`conf.dependency_call_timeout_ms`), así que
-- ninguna de las dos puede sola agotar el presupuesto del par.
--
-- @param token string token opaco emitido por Play Integrity en el dispositivo
-- @param conf table configuración del plugin
-- @return table veredicto canónico
-- @return nil, string motivo interno del rechazo, string clasificación del
--         fallo (ver `parse_response`; "unavailable" si Google o el canje de
--         OAuth previo fueron inalcanzables, no respondieron a tiempo, o no
--         quedó presupuesto para intentar la segunda llamada)
function M.fetch(token, conf)
  local started_at = ngx.now()
  local oauth_timeout = math.min(conf.dependency_timeout_ms, conf.dependency_call_timeout_ms)

  local access_token, oauth_err, oauth_kind = google_oauth.get_access_token(conf, oauth_timeout)
  if not access_token then
    return nil, oauth_err, oauth_kind
  end

  local elapsed_ms = (ngx.now() - started_at) * 1000
  local remaining_ms = conf.dependency_timeout_ms - elapsed_ms
  if remaining_ms <= 0 then
    -- El canje de OAuth consumió todo el presupuesto del par (típicamente
    -- porque no había access token en caché y Google tardó): no tiene
    -- sentido intentar una segunda llamada sin tiempo para ella.
    return nil, "playintegrity_deadline_exceeded", "unavailable"
  end

  local url = conf.playintegrity_url
    .. "/v1/"
    .. ngx.escape_uri(conf.package_name)
    .. ":decodeIntegrityToken"

  local client = http.new()
  client:set_timeout(math.min(remaining_ms, conf.dependency_call_timeout_ms))

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
    -- Google inalcanzable. El perímetro sigue fallando cerrado (sin veredicto
    -- no se deja pasar tráfico a la red interna), pero el motivo que se le
    -- reporta al cliente ahora distingue esto de un veredicto negativo: ver
    -- `kind` más abajo y el handler, que lo traduce a 503 en vez de 403.
    return nil, "playintegrity_unreachable: " .. tostring(request_err), "unavailable"
  end

  return M.parse_response(res.status, res.body)
end

return M
