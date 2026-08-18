-- base64url (RFC 4648 §5): el encoding que usan JWT/JWS, sin padding.
--
-- Vivía duplicado en los dos plugins. Como es la puerta de entrada de todo lo
-- que viene de afuera, conviene que haya una sola implementación y que esté
-- testeada.
local M = {}

local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64

--- Codifica bytes crudos a base64url sin padding.
function M.encode(raw)
  if type(raw) ~= "string" then
    return nil
  end

  local encoded = encode_base64(raw)
  if not encoded then
    return nil
  end

  return (encoded:gsub("%+", "-"):gsub("/", "_"):gsub("=", ""))
end

--- Decodifica base64url, reponiendo el padding que la especificación omite.
-- @return string bytes crudos, o `nil` si el segmento no es base64url válido
function M.decode(segment)
  if type(segment) ~= "string" or segment == "" then
    return nil
  end

  -- Un `+` o un `/` significa que esto es base64 clásico, no base64url:
  -- aceptarlo permitiría que el mismo contenido tenga dos representaciones.
  if segment:find("[+/=]") then
    return nil
  end

  local normalized = segment:gsub("%-", "+"):gsub("_", "/")

  local remainder = #normalized % 4
  if remainder == 2 then
    normalized = normalized .. "=="
  elseif remainder == 3 then
    normalized = normalized .. "="
  elseif remainder ~= 0 then
    -- Un resto de 1 no corresponde a ninguna longitud válida.
    return nil
  end

  return decode_base64(normalized)
end

return M
