#!/usr/bin/env resty
--
-- Arranca Busted dentro del runtime de OpenResty.
--
-- Los plugins usan las mismas APIs que en producción (`ngx.*`,
-- `resty.openssl`), así que los specs se ejecutan sobre ese runtime en lugar
-- de mockearlo. No se levanta Kong: sólo el intérprete.
setmetatable(_G, nil)

pcall(require, "luarocks.loader")

require("busted.runner")({ standalone = false })
