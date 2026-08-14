-- Fuente de veredictos: mock firmado con PSK.
--
-- Existe para poder ejercitar el camino completo sin depender de Google: CI,
-- tests de integración y desarrollo sin dispositivo físico. El payload del JWT
-- tiene EXACTAMENTE la forma que devuelve `decodeIntegrityToken`, así que la
-- política que se valida acá es la misma que corre en producción — el mock no
-- puede "pasar" por tener una forma más laxa.
--
-- Nunca debe habilitarse en producción: quien tenga la PSK puede fabricar
-- cualquier veredicto.
local jws = require "vv.jws"

local M = {}

--- Verifica el JWT del mock y devuelve el veredicto que transporta.
-- @return table veredicto canónico
-- @return nil, string motivo interno del rechazo
function M.fetch(token, conf)
  local claims, err = jws.verify_hs256(token, conf.psk)
  if not claims then
    return nil, err
  end

  -- Vigencia del sobre JWT, además de la del veredicto. La frescura real la
  -- controla `requestDetails.timestampMillis` en la política, igual que con un
  -- token de Google; esto es sólo defensa en profundidad.
  if claims.exp ~= nil then
    if type(claims.exp) ~= "number" then
      return nil, "malformed_exp"
    end

    if ngx.time() > claims.exp + (conf.clock_skew_seconds or 0) then
      return nil, "mock_token_expired"
    end
  end

  return claims
end

return M
