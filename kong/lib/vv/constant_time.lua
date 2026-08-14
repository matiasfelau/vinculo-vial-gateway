-- Comparación en tiempo constante.
--
-- Se usa para firmas y hashes: comparar con `==` corta en el primer byte que
-- difiere, y esa diferencia de tiempo le dice a quien está probando valores
-- cuántos bytes acertó, lo que permite construir el valor correcto byte a byte.
local bit = require "bit"

local byte = string.byte
local bxor = bit.bxor
local bor = bit.bor

local M = {}

--- Compara dos strings sin cortar en la primera diferencia.
-- La longitud sí se filtra (se compara antes), pero los valores que pasan por
-- acá son de largo fijo por construcción: HMAC-SHA256, SHA-256, hex de 64.
function M.equals(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
    return false
  end

  local diff = 0
  for i = 1, #a do
    diff = bor(diff, bxor(byte(a, i), byte(b, i)))
  end

  return diff == 0
end

return M
