-- JWS compacto: verificación HS256 y firma RS256.
--
-- Dos usos en el Gateway:
--   - verificar el JWT del mock de atestación (HS256 contra la PSK);
--   - firmar la aserción del service account de Google (RS256), que es lo que
--     se canjea por un access token en `oauth2.googleapis.com`.
--
-- No pretende ser una librería JWT completa: sólo los dos algoritmos que se
-- usan, explícitos, sin negociación por el header del token.
local cjson = require "cjson.safe"
local openssl_hmac = require "resty.openssl.hmac"
local openssl_pkey = require "resty.openssl.pkey"
local openssl_digest = require "resty.openssl.digest"

local base64url = require "vv.base64url"
local constant_time = require "vv.constant_time"

local M = {}

--- Parte un JWT compacto en sus tres segmentos.
-- @return header_b64, payload_b64, signature_b64, o `nil` si no tiene la forma
function M.split(token)
  if type(token) ~= "string" then
    return nil
  end

  return token:match("^([%w_%-]+)%.([%w_%-]+)%.([%w_%-]+)$")
end

local function decode_json_segment(segment)
  local raw = base64url.decode(segment)
  if not raw then
    return nil
  end

  local decoded = cjson.decode(raw)
  if type(decoded) ~= "table" then
    return nil
  end

  return decoded
end

--- Verifica un JWT firmado con HMAC-SHA256 y devuelve sus claims.
--
-- La firma se verifica ANTES de decodificar los claims: nada de lo que venga
-- en el payload merece confianza hasta ese punto.
--
-- @param token string JWT compacto
-- @param key string secreto compartido
-- @return table claims
-- @return nil, string motivo interno del rechazo
function M.verify_hs256(token, key)
  if type(key) ~= "string" or key == "" then
    return nil, "missing_key"
  end

  local header_b64, payload_b64, signature_b64 = M.split(token)
  if not header_b64 then
    return nil, "malformed_token"
  end

  local header = decode_json_segment(header_b64)
  if not header then
    return nil, "malformed_header"
  end

  -- Sólo HS256. Rechazar cualquier otro `alg` cierra `alg: none` y la
  -- confusión de algoritmos (hacer pasar una clave pública RSA por secreto
  -- HMAC).
  if header.alg ~= "HS256" then
    return nil, "unsupported_alg"
  end

  local hmac, err = openssl_hmac.new(key, "sha256")
  if not hmac then
    return nil, "hmac_error: " .. tostring(err)
  end

  local ok, update_err = hmac:update(header_b64 .. "." .. payload_b64)
  if not ok then
    return nil, "hmac_error: " .. tostring(update_err)
  end

  if not constant_time.equals(hmac:final(), base64url.decode(signature_b64)) then
    return nil, "invalid_signature"
  end

  local claims = decode_json_segment(payload_b64)
  if not claims then
    return nil, "malformed_claims"
  end

  return claims
end

--- Firma un JWT con RS256.
-- @param claims table payload
-- @param private_key_pem string clave privada en PEM
-- @param extra_header table|nil headers adicionales (ej. `kid`)
-- @return string JWT compacto
-- @return nil, string motivo del fallo
function M.sign_rs256(claims, private_key_pem, extra_header)
  local key, err = openssl_pkey.new(private_key_pem)
  if not key then
    return nil, "invalid_private_key: " .. tostring(err)
  end

  local header = { alg = "RS256", typ = "JWT" }
  for k, v in pairs(extra_header or {}) do
    header[k] = v
  end

  local encoded_header = base64url.encode(cjson.encode(header))
  local encoded_claims = base64url.encode(cjson.encode(claims))
  if not encoded_header or not encoded_claims then
    return nil, "encode_error"
  end

  local signing_input = encoded_header .. "." .. encoded_claims

  local digest, digest_err = openssl_digest.new("sha256")
  if not digest then
    return nil, "digest_error: " .. tostring(digest_err)
  end

  local ok, update_err = digest:update(signing_input)
  if not ok then
    return nil, "digest_error: " .. tostring(update_err)
  end

  local signature, sign_err = key:sign(digest)
  if not signature then
    return nil, "sign_error: " .. tostring(sign_err)
  end

  return signing_input .. "." .. base64url.encode(signature)
end

return M
