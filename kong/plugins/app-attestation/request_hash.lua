-- Hash del body, para ligar la atestación al request concreto.
--
-- La app calcula SHA-256 del payload y se lo pasa a Play Integrity en
-- `setRequestHash()`; Google lo devuelve intacto dentro del veredicto. El
-- Gateway recalcula el hash del body que efectivamente llegó y los compara.
-- Sin esta ligadura, una atestación válida capturada de una request sirve para
-- cualquier otra dentro de su ventana de vigencia.
--
-- Importante: hashear NO es inspeccionar. Se calcula sobre los bytes crudos y
-- el body se reenvía sin tocar; sigue siendo opaco para el Gateway (viaja
-- cifrado E2E y las claves están en Identity).
local openssl_digest = require "resty.openssl.digest"
local resty_string = require "resty.string"

local base64url = require "vv.base64url"
local constant_time = require "vv.constant_time"

local encode_base64 = ngx.encode_base64

local M = {}

-- El encoding es parte del contrato con el Frontend: ambos lados tienen que
-- representar los mismos 32 bytes igual, o la comparación falla siempre.
local ENCODERS = {
  hex = function(raw)
    return resty_string.to_hex(raw)
  end,
  base64 = function(raw)
    return encode_base64(raw)
  end,
  base64url = function(raw)
    return base64url.encode(raw)
  end,
}

--- Encodings soportados, para el schema del plugin.
function M.encodings()
  local names = {}
  for name in pairs(ENCODERS) do
    names[#names + 1] = name
  end
  table.sort(names)
  return names
end

--- Calcula el hash del body en el encoding indicado.
-- @param body string bytes crudos del body (puede ser "" si no hay body)
-- @param encoding string "hex" | "base64" | "base64url"
-- @return string hash codificado
-- @return nil, string motivo del fallo
function M.compute(body, encoding)
  if type(body) ~= "string" then
    return nil, "missing_body"
  end

  local encoder = ENCODERS[encoding]
  if not encoder then
    return nil, "unsupported_encoding"
  end

  local digest, err = openssl_digest.new("sha256")
  if not digest then
    return nil, "digest_error: " .. tostring(err)
  end

  local ok, update_err = digest:update(body)
  if not ok then
    return nil, "digest_error: " .. tostring(update_err)
  end

  local encoded = encoder(digest:final())
  if not encoded then
    return nil, "encode_error"
  end

  return encoded
end

--- Compara el hash presentado en el veredicto contra el del body real.
function M.matches(presented, body, encoding)
  local expected, err = M.compute(body, encoding)
  if not expected then
    return nil, err
  end

  return constant_time.equals(presented, expected)
end

return M
