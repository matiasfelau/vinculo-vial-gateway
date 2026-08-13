-- Esquema de configuración del plugin `app-attestation`.
--
-- Nada de esto se hardcodea en el handler: la PSK y las ventanas de tiempo
-- llegan como configuración del plugin, que en `kong.yml` se resuelve contra
-- variables de entorno.
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "app-attestation",
  fields = {
    -- La atestación sólo tiene sentido sobre tráfico HTTP(S).
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- Secreto compartido con la app (HMAC-SHA256). `referenceable`
          -- habilita referencias a Vault/entorno además del valor literal.
          {
            psk = {
              type = "string",
              required = true,
              referenceable = true,
              len_min = 16,
            },
          },
          -- Header que transporta el veredicto mockeado de Play Integrity.
          {
            header_name = {
              type = "string",
              required = true,
              default = "X-App-Attestation",
            },
          },
          -- Vida máxima aceptada del token, medida desde `iat`. Acota la
          -- ventana de replay aunque el `exp` que emita la app sea generoso.
          {
            max_age_seconds = {
              type = "integer",
              required = true,
              default = 300,
              between = { 1, 3600 },
            },
          },
          -- Tolerancia al desfasaje de reloj entre el dispositivo y el Gateway.
          {
            clock_skew_seconds = {
              type = "integer",
              required = true,
              default = 30,
              between = { 0, 300 },
            },
          },
          -- Emisor y destinatario esperados. `null` desactiva la verificación.
          {
            expected_issuer = {
              type = "string",
              default = "vinculo-vial-app",
            },
          },
          {
            expected_audience = {
              type = "string",
              default = "vinculo-vial-gateway",
            },
          },
          -- Veredictos exigidos, con la nomenclatura de Play Integrity para que
          -- el reemplazo por la API real no cambie el contrato del header.
          {
            required_app_verdict = {
              type = "string",
              required = true,
              default = "PLAY_RECOGNIZED",
            },
          },
          {
            required_device_verdicts = {
              type = "array",
              required = true,
              elements = { type = "string" },
              default = { "MEETS_DEVICE_INTEGRITY" },
            },
          },
          -- El token de atestación es asunto del perímetro: por defecto no se
          -- reenvía al upstream (Identity nunca lo revisa).
          {
            strip_header = {
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
