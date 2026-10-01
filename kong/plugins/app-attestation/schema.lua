-- Esquema de configuración del plugin `app-attestation`.
--
-- Nada de esto se hardcodea en los handlers: credenciales, política y ventanas
-- de tiempo llegan como configuración del plugin, que en `kong.yml` se resuelve
-- contra variables de entorno.
local typedefs = require "kong.db.schema.typedefs"

local request_hash = require "kong.plugins.app-attestation.request_hash"

-- Veredictos de dispositivo que Google puede devolver. Los niveles son
-- acumulativos: un dispositivo con STRONG reporta también DEVICE y BASIC.
--
--   MEETS_STRONG_INTEGRITY  respaldo por hardware (key attestation)
--   MEETS_DEVICE_INTEGRITY  dispositivo Android certificado por Google
--   MEETS_BASIC_INTEGRITY   pasa controles básicos; puede estar rooteado
--   MEETS_VIRTUAL_INTEGRITY emulador con Play Services
local DEVICE_VERDICTS = {
  "MEETS_STRONG_INTEGRITY",
  "MEETS_DEVICE_INTEGRITY",
  "MEETS_BASIC_INTEGRITY",
  "MEETS_VIRTUAL_INTEGRITY",
}

local APP_VERDICTS = {
  "PLAY_RECOGNIZED",
  "UNRECOGNIZED_VERSION",
  "UNEVALUATED",
}

local LICENSING_VERDICTS = {
  "LICENSED",
  "UNLICENSED",
  "UNEVALUATED",
}

-- Un campo opcional sin valor puede llegar como `nil`, como `ngx.null` (así
-- representa Kong los campos ausentes) o como string vacío.
local function is_blank(value)
  return value == nil or value == ngx.null or value == ""
end

return {
  name = "app-attestation",
  fields = {
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- ── Fuente del veredicto ────────────────────────────────────────
          {
            source = {
              type = "string",
              required = true,
              default = "google",
              one_of = { "google", "mock" },
            },
          },
          -- Package name de la app en Play. Se verifica contra el veredicto,
          -- así que un token emitido para otra app no sirve.
          {
            package_name = {
              type = "string",
              required = true,
            },
          },

          -- ── Credenciales de Google (source = google) ────────────────────
          -- Se prefiere el archivo montado: mantiene el JSON fuera del
          -- entorno del proceso y de la configuración declarativa.
          {
            service_account_path = {
              type = "string",
            },
          },
          {
            service_account_json = {
              type = "string",
              referenceable = true,
            },
          },
          {
            playintegrity_url = {
              type = "string",
              required = true,
              default = "https://playintegrity.googleapis.com",
            },
          },
          -- Presupuesto total para el PAR de llamadas (canje de OAuth +
          -- decodeIntegrityToken), no por llamada: si la primera consume
          -- parte del presupuesto, a la segunda le queda el resto, nunca una
          -- ventana nueva de este mismo tamaño. Con el access token en caché
          -- (caso común) la primera llamada ni ocurre, así que la segunda
          -- dispone del presupuesto completo.
          {
            dependency_timeout_ms = {
              type = "integer",
              required = true,
              default = 4000,
              between = { 100, 30000 },
            },
          },
          -- Techo por llamada individual, aparte del agregado de arriba:
          -- ninguna de las dos llamadas puede sola consumir todo el
          -- presupuesto del par.
          {
            dependency_call_timeout_ms = {
              type = "integer",
              required = true,
              default = 3000,
              between = { 100, 30000 },
            },
          },
          -- Sólo se desactiva para apuntar a un stub local en los tests de
          -- integración; contra Google real tiene que estar en `true`.
          {
            ssl_verify = {
              type = "boolean",
              required = true,
              default = true,
            },
          },

          -- ── Credenciales del mock (source = mock) ───────────────────────
          {
            psk = {
              type = "string",
              referenceable = true,
              len_min = 16,
            },
          },

          -- ── Política ────────────────────────────────────────────────────
          {
            accepted_app_verdicts = {
              type = "array",
              required = true,
              elements = { type = "string", one_of = APP_VERDICTS },
              default = { "PLAY_RECOGNIZED" },
            },
          },
          -- Semántica "alguno de". El default acepta dispositivos Android
          -- certificados; agregar MEETS_BASIC_INTEGRITY admite dispositivos
          -- que pueden estar rooteados, y MEETS_VIRTUAL_INTEGRITY, emuladores.
          {
            accepted_device_verdicts = {
              type = "array",
              required = true,
              elements = { type = "string", one_of = DEVICE_VERDICTS },
              default = { "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY" },
            },
          },
          -- Vacío = no se verifica la licencia. Durante el desarrollo con la
          -- app instalada por sideload el veredicto es UNLICENSED.
          {
            accepted_licensing_verdicts = {
              type = "array",
              required = true,
              elements = { type = "string", one_of = LICENSING_VERDICTS },
              default = {},
            },
          },
          -- Huellas SHA-256 del certificado de firma de la app (base64url,
          -- como las devuelve Google). Vacío = no se verifica.
          {
            expected_certificate_digests = {
              type = "array",
              required = true,
              elements = { type = "string" },
              default = {},
            },
          },

          -- ── Ligadura con el request ─────────────────────────────────────
          {
            require_request_hash = {
              type = "boolean",
              required = true,
              default = true,
            },
          },
          {
            request_hash_encoding = {
              type = "string",
              required = true,
              default = "hex",
              one_of = request_hash.encodings(),
            },
          },
          {
            replay_guard = {
              type = "boolean",
              required = true,
              default = true,
            },
          },

          -- ── Ventanas de tiempo ──────────────────────────────────────────
          -- Vida máxima aceptada, medida desde el `timestampMillis` que emite
          -- Google. Acota la ventana de replay.
          {
            max_age_seconds = {
              type = "integer",
              required = true,
              default = 120,
              between = { 1, 3600 },
            },
          },
          {
            clock_skew_seconds = {
              type = "integer",
              required = true,
              default = 30,
              between = { 0, 300 },
            },
          },

          -- ── Transporte ──────────────────────────────────────────────────
          {
            header_name = {
              type = "string",
              required = true,
              default = "X-App-Attestation",
            },
          },
          {
            max_token_bytes = {
              type = "integer",
              required = true,
              default = 16384,
              between = { 256, 65536 },
            },
          },
          {
            strip_header = {
              type = "boolean",
              required = true,
              default = true,
            },
          },
        },
        entity_checks = {
          -- Cada fuente necesita su credencial. Sin esto, una configuración
          -- incompleta arrancaría bien y fallaría recién en la primera
          -- request, con todo el tráfico rechazado.
          {
            conditional = {
              if_field = "source",
              if_match = { eq = "mock" },
              then_field = "psk",
              then_match = { required = true },
            },
          },
          {
            custom_entity_check = {
              field_sources = {
                "source",
                "service_account_path",
                "service_account_json",
              },
              fn = function(config)
                if config.source == "google"
                  and is_blank(config.service_account_path)
                  and is_blank(config.service_account_json) then
                  return nil, "source = 'google' requiere service_account_path "
                    .. "o service_account_json"
                end

                return true
              end,
            },
          },
        },
      },
    },
  },
}
