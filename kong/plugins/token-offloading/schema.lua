-- Esquema de configuración del plugin `token-offloading`.
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "token-offloading",
  fields = {
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- Claim del token ya validado que identifica al usuario.
          {
            claim = {
              type = "string",
              required = true,
              default = "sub",
            },
          },
          -- Header con el que el upstream recibe esa identidad.
          {
            header_name = {
              type = "string",
              required = true,
              default = "X-User-Hash",
            },
          },
          -- Token offloading: el upstream no debería ver ni validar el JWT.
          -- Se puede desactivar para servicios que todavía lo necesiten.
          {
            remove_authorization = {
              type = "boolean",
              required = true,
              default = true,
            },
          },
        },
      },
    },
  },
}
