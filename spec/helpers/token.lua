-- Helper de tests: arma un JWT compacto con claims arbitrarios.
--
-- La firma es un relleno a propósito. `token-offloading` corre después del
-- plugin `jwt` de Kong, que ya verificó la firma; volver a verificarla sería
-- duplicar el control. Que el helper no firme deja esa frontera explícita en
-- los tests.
local cjson = require "cjson.safe"

local base64url = require "vv.base64url"

local _M = {}

function _M.compact(claims, header_overrides)
  local header = { alg = "RS256", typ = "JWT" }
  for key, value in pairs(header_overrides or {}) do
    header[key] = value
  end

  return base64url.encode(cjson.encode(header))
    .. "."
    .. base64url.encode(cjson.encode(claims))
    .. "."
    .. base64url.encode("firma-ya-verificada-por-el-plugin-jwt")
end

return _M
