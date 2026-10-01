-- Access token de Google a partir de un service account.
--
-- Flujo `urn:ietf:params:oauth:grant-type:jwt-bearer`: se arma una aserción
-- JWT firmada con la clave privada del service account y se la canjea en
-- `oauth2.googleapis.com/token` por un access token de vida corta.
--
-- El token se cachea en memoria compartida entre workers: dura una hora, y
-- pedirlo en cada request agregaría un round-trip a Google por cada signup.
local cjson = require "cjson.safe"
local http = require "resty.http"

local jws = require "vv.jws"

local M = {}

-- Scope mínimo necesario para `decodeIntegrityToken`.
local SCOPE = "https://www.googleapis.com/auth/playintegrity"
local DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token"
local ASSERTION_LIFETIME = 3600

-- Se renueva antes de que expire para que ninguna request quede esperando la
-- renovación con un token ya vencido.
local REFRESH_MARGIN = 300

local DICT_NAME = "vv_attestation"
local CACHE_KEY = "google:access_token"

-- El JSON del service account se lee del disco una vez por worker: en DB-less
-- la configuración es inmutable en runtime, así que no puede cambiar sin
-- reiniciar.
local service_account_cache = {}

--- Extrae del JSON del service account lo que hace falta para firmar.
-- @return table { client_email, private_key, token_uri }
-- @return nil, string motivo del fallo (nunca incluye la clave privada)
function M.parse_service_account(raw_json)
  if type(raw_json) ~= "string" or raw_json == "" then
    return nil, "empty_service_account"
  end

  local parsed = cjson.decode(raw_json)
  if type(parsed) ~= "table" then
    return nil, "malformed_service_account_json"
  end

  if type(parsed.client_email) ~= "string" or parsed.client_email == "" then
    return nil, "service_account_missing_client_email"
  end

  if type(parsed.private_key) ~= "string" or parsed.private_key == "" then
    return nil, "service_account_missing_private_key"
  end

  return {
    client_email = parsed.client_email,
    private_key = parsed.private_key,
    token_uri = parsed.token_uri or DEFAULT_TOKEN_URL,
    private_key_id = parsed.private_key_id,
  }
end

--- Carga el service account desde archivo o desde la config, con caché.
function M.load_service_account(conf)
  local path = conf.service_account_path

  if path and path ~= "" then
    local cached = service_account_cache[path]
    if cached then
      return cached
    end

    local file, open_err = io.open(path, "r")
    if not file then
      return nil, "service_account_unreadable: " .. tostring(open_err)
    end

    local contents = file:read("*a")
    file:close()

    local account, err = M.parse_service_account(contents)
    if not account then
      return nil, err
    end

    service_account_cache[path] = account
    return account
  end

  if conf.service_account_json and conf.service_account_json ~= "" then
    return M.parse_service_account(conf.service_account_json)
  end

  return nil, "service_account_not_configured"
end

--- Arma la aserción JWT que se canjea por el access token.
-- Función pura: se testea sin tocar la red.
function M.build_assertion(account, now)
  local claims = {
    iss = account.client_email,
    scope = SCOPE,
    aud = account.token_uri,
    iat = now,
    exp = now + ASSERTION_LIFETIME,
  }

  local header
  if account.private_key_id then
    header = { kid = account.private_key_id }
  end

  return jws.sign_rs256(claims, account.private_key, header)
end

--- Interpreta la respuesta del endpoint de token. Pura, para poder testearla.
-- @return string access_token, number vida en segundos
-- @return nil, string motivo del fallo, string clasificación del fallo
--         ("upstream_error" si Google respondió 5xx o un cuerpo fuera de
--         contrato; "rejected" para cualquier otro caso, el default seguro)
function M.parse_token_response(status, body)
  if status ~= 200 then
    -- El cuerpo del error de Google no contiene datos del usuario, pero sí
    -- puede traer detalles del service account: se reporta sólo el status.
    local kind = status >= 500 and "upstream_error" or "rejected"
    return nil, "oauth_http_" .. tostring(status), kind
  end

  local parsed = cjson.decode(body)
  if type(parsed) ~= "table" then
    return nil, "oauth_malformed_response", "upstream_error"
  end

  if type(parsed.access_token) ~= "string" or parsed.access_token == "" then
    return nil, "oauth_missing_access_token", "upstream_error"
  end

  return parsed.access_token, tonumber(parsed.expires_in) or ASSERTION_LIFETIME
end

local function cache_get()
  local dict = ngx.shared[DICT_NAME]
  if not dict then
    return nil
  end

  return dict:get(CACHE_KEY)
end

local function cache_set(token, expires_in)
  local dict = ngx.shared[DICT_NAME]
  if not dict then
    return
  end

  local ttl = expires_in - REFRESH_MARGIN
  if ttl > 0 then
    dict:set(CACHE_KEY, token, ttl)
  end
end

--- Devuelve un access token válido, del caché o pidiéndole uno nuevo a Google.
-- @param conf table configuración del plugin
-- @param timeout_ms number techo de esta llamada en ms. Lo decide el llamador
--        (`sources/google.fetch`) según cuánto quede del presupuesto agregado
--        del par de llamadas; por defecto `dependency_call_timeout_ms`, para
--        que la función siga siendo segura si algún día se llama sola.
-- @return string access_token
-- @return nil, string motivo del fallo, string clasificación del fallo (ver
--         `parse_token_response`; "unavailable" si Google fue inalcanzable o
--         no respondió dentro de `timeout_ms`)
function M.get_access_token(conf, timeout_ms)
  local cached = cache_get()
  if cached then
    return cached
  end

  local account, account_err = M.load_service_account(conf)
  if not account then
    return nil, account_err, "rejected"
  end

  local assertion, assertion_err = M.build_assertion(account, ngx.time())
  if not assertion then
    return nil, assertion_err, "rejected"
  end

  local client = http.new()
  client:set_timeout(timeout_ms or conf.dependency_call_timeout_ms)

  local res, request_err = client:request_uri(account.token_uri, {
    method = "POST",
    body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
      .. "&assertion=" .. ngx.escape_uri(assertion),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
    ssl_verify = conf.ssl_verify,
  })

  if not res then
    return nil, "oauth_unreachable: " .. tostring(request_err), "unavailable"
  end

  local token, expires_in, kind = M.parse_token_response(res.status, res.body)
  if not token then
    return nil, expires_in, kind
  end

  cache_set(token, expires_in)

  return token
end

return M
