-- Consumo de un solo uso de cada atestación.
--
-- `requestHash` ata el token al body y `timestampMillis` acota su vigencia,
-- pero dentro de esa ventana el mismo par (token, body) se puede reenviar. Con
-- esto, la primera request que presenta un token lo consume y las siguientes
-- se rechazan.
--
-- El registro vive en la memoria compartida del nodo. En un despliegue
-- multinodo cada nodo tendría su propio registro, así que la garantía pasa a
-- ser "una vez por nodo": para reforzarla habría que mover el registro a Redis,
-- igual que el contador del rate limiting.
local openssl_digest = require "resty.openssl.digest"
local resty_string = require "resty.string"

local DICT_NAME = "vv_attestation"
local KEY_PREFIX = "seen:"

local M = {}

-- Se avisa una vez por worker si el shared dict no está declarado, en lugar de
-- ensuciar el log en cada request.
local warned = false

local function dict()
  local shared = ngx.shared[DICT_NAME]

  if not shared and not warned then
    warned = true
    kong.log.err("app-attestation: el shared dict '", DICT_NAME,
                 "' no está declarado; la protección anti-replay queda ",
                 "desactivada. Agregar `nginx_http_lua_shared_dict` en kong.conf.")
  end

  return shared
end

--- Identificador corto y estable del token, para no guardarlo entero.
-- Guardar el token completo en memoria compartida sería guardar credenciales;
-- el hash alcanza para detectar la repetición.
function M.fingerprint(token)
  local digest = openssl_digest.new("sha256")
  if not digest then
    return nil
  end

  if not digest:update(token) then
    return nil
  end

  -- 128 bits de hash son suficientes para que una colisión no sea alcanzable,
  -- y ocupan la mitad en el diccionario.
  return KEY_PREFIX .. resty_string.to_hex(digest:final()):sub(1, 32)
end

--- ¿Este token ya fue consumido? Consulta sin reservar.
-- Se usa para descartar repeticiones evidentes antes de gastar una llamada a
-- Google.
function M.seen(fingerprint)
  local shared = dict()
  if not shared or not fingerprint then
    return false
  end

  return shared:get(fingerprint) ~= nil
end

--- Marca el token como consumido.
-- @return true si era la primera vez
-- @return nil, "replay" si ya estaba registrado
function M.consume(fingerprint, ttl)
  local shared = dict()
  if not shared or not fingerprint then
    -- Sin diccionario no hay garantía que dar; las demás defensas siguen en
    -- pie y ya se avisó por log.
    return true
  end

  -- `add` es atómico: entre dos requests concurrentes con el mismo token, sólo
  -- una obtiene el registro.
  local ok, err = shared:add(fingerprint, true, ttl)
  if ok then
    return true
  end

  if err == "exists" then
    return nil, "replay"
  end

  -- "no memory": el diccionario se llenó. Se prefiere dejar pasar (las otras
  -- validaciones siguen aplicando) antes que cortar todo el tráfico.
  kong.log.err("app-attestation: no se pudo registrar la atestación (", err, ")")
  return true
end

return M
