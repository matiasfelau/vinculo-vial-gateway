#!/usr/bin/env resty
--
-- Arranca Busted dentro del runtime de OpenResty.
--
-- Los plugins usan las mismas APIs que en producción (`ngx.*`,
-- `resty.openssl`), así que los specs se ejecutan sobre ese runtime en lugar
-- de mockearlo. No se levanta Kong: sólo el intérprete.
setmetatable(_G, nil)

pcall(require, "luarocks.loader")

-- Cobertura (`spec/coverage.sh`): LuaCov engancha `os.exit` para volcar las
-- estadísticas al terminar, así que tiene que arrancar antes que Busted. Sin
-- `VV_COVERAGE` no se carga y los specs corren igual que siempre.
if os.getenv("VV_COVERAGE") == "1" then
  require("luacov.runner")(".luacov")
end

require("busted.runner")({ standalone = false })
