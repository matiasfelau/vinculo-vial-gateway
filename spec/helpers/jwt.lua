-- Helper de tests: emite tokens de atestación como lo haría la app móvil.
-- Firma HMAC-SHA256 real, no un mock: los specs ejercitan el mismo camino
-- criptográfico que corre en producción.
local cjson = require "cjson.safe"
local openssl_hmac = require "resty.openssl.hmac"

local _M = {}

function _M.base64url_encode(raw)
  local encoded = ngx.encode_base64(raw)
  encoded = encoded:gsub("%+", "-"):gsub("/", "_"):gsub("=", "")
  return encoded
end

--- Arma y firma un JWT compacto.
-- @param claims table payload del token
-- @param psk string secreto compartido
-- @param header_overrides table|nil para forzar headers inválidos en los tests
function _M.sign(claims, psk, header_overrides)
  local header = { alg = "HS256", typ = "JWT" }
  for key, value in pairs(header_overrides or {}) do
    header[key] = value
  end

  local signing_input = _M.base64url_encode(cjson.encode(header))
    .. "."
    .. _M.base64url_encode(cjson.encode(claims))

  local hmac = assert(openssl_hmac.new(psk, "sha256"))
  assert(hmac:update(signing_input))

  return signing_input .. "." .. _M.base64url_encode(hmac:final())
end

--- Reemplaza el payload de un token ya firmado, dejando la firma original.
-- Simula a un atacante manipulando claims sin poder re-firmar.
function _M.tamper_payload(token, claims)
  local header_b64, _, signature_b64 = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  return header_b64
    .. "."
    .. _M.base64url_encode(cjson.encode(claims))
    .. "."
    .. signature_b64
end

return _M
