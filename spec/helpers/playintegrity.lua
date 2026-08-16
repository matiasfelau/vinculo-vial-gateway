-- Helper de tests: fabrica veredictos con la forma exacta que devuelve
-- `decodeIntegrityToken`, y tokens del mock firmados de verdad con HMAC.
--
-- Que el helper y producción compartan la misma forma es el punto: si el mock
-- tuviera una forma más laxa, los tests validarían una política que no es la
-- que corre contra Google.
local cjson = require "cjson.safe"
local openssl_hmac = require "resty.openssl.hmac"

local base64url = require "vv.base64url"

local _M = {}

_M.PACKAGE_NAME = "ar.felaufernandezbottaro.vinculovial"

-- Centinela para *quitar* una clave en los overrides: pasar `nil` no sirve,
-- porque `pairs` no itera claves ausentes.
_M.NONE = setmetatable({}, { __tostring = function() return "NONE" end })

-- Ramas del veredicto en las que un override parchea campos sueltos en vez de
-- reemplazar el objeto entero. Se enumeran en lugar de deducirlo de la forma
-- del valor: "es un array o es un objeto" es indistinguible cuando llega
-- vacío, y `deviceRecognitionVerdict = {}` — un dispositivo comprometido — es
-- justamente el caso que hay que poder expresar.
local NESTED_OBJECTS = {
  requestDetails = true,
  appIntegrity = true,
  deviceIntegrity = true,
  accountDetails = true,
}

local function merge(base, overrides)
  for key, value in pairs(overrides or {}) do
    if value == _M.NONE then
      base[key] = nil
    elseif NESTED_OBJECTS[key] and type(value) == "table"
      and type(base[key]) == "table" then
      for sub_key, sub_value in pairs(value) do
        base[key][sub_key] = sub_value ~= _M.NONE and sub_value or nil
      end
    else
      base[key] = value
    end
  end

  return base
end

--- Veredicto canónico de Play Integrity.
-- @param now number timestamp UNIX en segundos
-- @param overrides table|nil parches, anidados o con `NONE` para quitar
function _M.verdict(now, overrides)
  local base = {
    requestDetails = {
      requestPackageName = _M.PACKAGE_NAME,
      timestampMillis = tostring(math.floor(now * 1000)),
    },
    appIntegrity = {
      appRecognitionVerdict = "PLAY_RECOGNIZED",
      packageName = _M.PACKAGE_NAME,
      certificateSha256Digest = { "6a6a1474b5cbbb2b1aa57e0bc3" },
      versionCode = "42",
    },
    deviceIntegrity = {
      deviceRecognitionVerdict = { "MEETS_DEVICE_INTEGRITY" },
    },
    accountDetails = {
      appLicensingVerdict = "LICENSED",
    },
  }

  return merge(base, overrides)
end

--- Respuesta HTTP completa de `decodeIntegrityToken`.
function _M.decode_response(verdict)
  return cjson.encode({ tokenPayloadExternal = verdict })
end

--- Firma un veredicto como token del mock (HS256), tal como lo haría la app
--- cuando `source = mock`.
function _M.sign_mock(verdict, psk, header_overrides)
  local header = { alg = "HS256", typ = "JWT" }
  for key, value in pairs(header_overrides or {}) do
    header[key] = value
  end

  local signing_input = base64url.encode(cjson.encode(header))
    .. "."
    .. base64url.encode(cjson.encode(verdict))

  local hmac = assert(openssl_hmac.new(psk, "sha256"))
  assert(hmac:update(signing_input))

  return signing_input .. "." .. base64url.encode(hmac:final())
end

return _M
