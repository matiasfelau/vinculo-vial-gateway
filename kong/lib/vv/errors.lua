-- Contrato de error del Gateway.
--
-- Todos los rechazos del perímetro responden con la misma forma:
--
--   { "error": "<código estable>", "reason": "<motivo público>" }
--
-- El motivo real del rechazo (firma inválida, token expirado, veredicto de
-- Play rechazado, …) va únicamente al log. Al cliente se le comunica que no
-- pasa, no por qué: distinguir "firma inválida" de "token expirado" le regala
-- a quien esté sondeando el control exactamente la señal que necesita para
-- afinarlo.
--
-- El contrato es cerrado a propósito: los motivos públicos son constantes de
-- este módulo, no strings sueltos esparcidos por los handlers.
local M = {}

local JSON_HEADERS = { ["Content-Type"] = "application/json; charset=utf-8" }

-- Motivos públicos. Deliberadamente genéricos y estables: forman parte del
-- contrato con la app, así que cambiarlos rompe clientes.
M.INVALID_ATTESTATION = "invalid_attestation"
M.INVALID_TOKEN = "invalid_token"

local CONTRACT = {
  [M.INVALID_ATTESTATION] = { status = 403, error = "forbidden" },
  [M.INVALID_TOKEN] = { status = 401, error = "unauthorized" },
}

--- Arma la respuesta pública de un rechazo.
-- @param public_reason string una de las constantes del módulo
-- @return number, table status y body; `nil` si el motivo no está en el contrato
function M.build(public_reason)
  local entry = CONTRACT[public_reason]
  if not entry then
    return nil
  end

  -- Tabla nueva en cada llamada: el contrato no se puede mutar desde afuera.
  return entry.status, { error = entry.error, reason = public_reason }
end

--- Corta la request con la respuesta estandarizada.
-- @param public_reason string constante del contrato
-- @param log_message string detalle interno, sólo para el log. Nunca debe
--        incluir el token ni la PSK.
function M.exit(public_reason, log_message)
  local status, body = M.build(public_reason)

  if log_message then
    kong.log.warn(log_message)
  end

  return kong.response.exit(status, body, JSON_HEADERS)
end

return M
