local handler = require "kong.plugins.app-attestation.handler"
local jwt = require "spec.helpers.jwt"

-- Sólo para tests: la PSK real llega por variable de entorno.
local PSK = "psk-de-test-32-bytes-minimo-0123456789"
local NOW = 1735689600 -- 2025-01-01T00:00:00Z

-- Centinela para *quitar* un claim o una opción en los overrides: pasar `nil`
-- no sirve, porque `pairs` no itera claves ausentes.
local NONE = setmetatable({}, { __tostring = function() return "NONE" end })

-- Espejo de los defaults declarados en schema.lua; en runtime los completa Kong.
local function config(overrides)
  local conf = {
    psk = PSK,
    header_name = "X-App-Attestation",
    max_age_seconds = 300,
    clock_skew_seconds = 30,
    expected_issuer = "vinculo-vial-app",
    expected_audience = "vinculo-vial-gateway",
    required_app_verdict = "PLAY_RECOGNIZED",
    required_device_verdicts = { "MEETS_DEVICE_INTEGRITY" },
    strip_header = true,
  }

  for key, value in pairs(overrides or {}) do
    conf[key] = value ~= NONE and value or nil
  end

  return conf
end

-- Veredicto mockeado de Play Integrity, tal como lo emite la app.
local function claims(overrides)
  local payload = {
    iss = "vinculo-vial-app",
    aud = "vinculo-vial-gateway",
    iat = NOW,
    exp = NOW + 120,
    appRecognitionVerdict = "PLAY_RECOGNIZED",
    deviceRecognitionVerdict = { "MEETS_DEVICE_INTEGRITY" },
  }

  for key, value in pairs(overrides or {}) do
    payload[key] = value ~= NONE and value or nil
  end

  return payload
end

local function validate(token, conf_overrides, now)
  return handler.validate_token(token, config(conf_overrides), now or NOW)
end

describe("app-attestation", function()
  describe("token válido", function()
    it("acepta una atestación firmada, vigente y con los veredictos exigidos", function()
      assert.is_true(validate(jwt.sign(claims(), PSK)))
    end)

    it("acepta `aud` como lista, según RFC 7519", function()
      local token = jwt.sign(claims({ aud = { "otro-servicio", "vinculo-vial-gateway" } }), PSK)
      assert.is_true(validate(token))
    end)

    it("acepta `deviceRecognitionVerdict` como string simple", function()
      local token = jwt.sign(claims({ deviceRecognitionVerdict = "MEETS_DEVICE_INTEGRITY" }), PSK)
      assert.is_true(validate(token))
    end)

    it("tolera desfasaje de reloj dentro de la ventana configurada", function()
      -- El token venció hace 10s y la tolerancia es de 30s.
      local token = jwt.sign(claims({ exp = NOW - 10 }), PSK)
      assert.is_true(validate(token))
    end)
  end)

  describe("header ausente", function()
    it("rechaza cuando no viene el header", function()
      local ok, reason = validate(nil)
      assert.is_nil(ok)
      assert.equals("missing_header", reason)
    end)

    it("rechaza cuando el header viene vacío", function()
      local ok, reason = validate("")
      assert.is_nil(ok)
      assert.equals("missing_header", reason)
    end)
  end)

  describe("firma", function()
    it("rechaza un token firmado con otra PSK", function()
      local ok, reason = validate(jwt.sign(claims(), "psk-de-un-atacante-0123456789abcdef"))
      assert.is_nil(ok)
      assert.equals("invalid_signature", reason)
    end)

    it("rechaza un payload manipulado que conserva la firma original", function()
      -- El atacante extiende la vigencia del token sin poder re-firmarlo.
      local token = jwt.sign(claims(), PSK)
      local tampered = jwt.tamper_payload(token, claims({ exp = NOW + 86400 }))

      local ok, reason = validate(tampered)
      assert.is_nil(ok)
      assert.equals("invalid_signature", reason)
    end)

    it("rechaza `alg: none`", function()
      local token = jwt.sign(claims(), PSK, { alg = "none" })
      local ok, reason = validate(token)
      assert.is_nil(ok)
      assert.equals("unsupported_alg", reason)
    end)

    it("rechaza confusión de algoritmo (RS256)", function()
      local token = jwt.sign(claims(), PSK, { alg = "RS256" })
      local ok, reason = validate(token)
      assert.is_nil(ok)
      assert.equals("unsupported_alg", reason)
    end)
  end)

  describe("formato", function()
    it("rechaza un token que no es un JWT compacto", function()
      local ok, reason = validate("no-es-un-jwt")
      assert.is_nil(ok)
      assert.equals("malformed_token", reason)
    end)

    it("rechaza un token con segmentos faltantes", function()
      local ok, reason = validate("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ4In0")
      assert.is_nil(ok)
      assert.equals("malformed_token", reason)
    end)

    it("rechaza un token desmedidamente grande sin intentar validarlo", function()
      local ok, reason = validate(string.rep("a", 4097))
      assert.is_nil(ok)
      assert.equals("token_too_large", reason)
    end)
  end)

  describe("vigencia", function()
    it("rechaza un token expirado más allá de la tolerancia", function()
      local ok, reason = validate(jwt.sign(claims({ exp = NOW - 31 }), PSK))
      assert.is_nil(ok)
      assert.equals("expired_token", reason)
    end)

    it("rechaza un token sin `exp`", function()
      local ok, reason = validate(jwt.sign(claims({ exp = NONE }), PSK))
      assert.is_nil(ok)
      assert.equals("missing_exp", reason)
    end)

    it("rechaza un token sin `iat`", function()
      local ok, reason = validate(jwt.sign(claims({ iat = NONE }), PSK))
      assert.is_nil(ok)
      assert.equals("missing_iat", reason)
    end)

    it("rechaza un token emitido en el futuro", function()
      local ok, reason = validate(jwt.sign(claims({ iat = NOW + 120 }), PSK))
      assert.is_nil(ok)
      assert.equals("iat_in_future", reason)
    end)

    it("rechaza un token viejo aunque su `exp` sea generoso", function()
      -- Emitido hace una hora con vencimiento a un día: el `max_age_seconds`
      -- acota la ventana de replay igual.
      local token = jwt.sign(claims({ iat = NOW - 3600, exp = NOW + 86400 }), PSK)
      local ok, reason = validate(token)
      assert.is_nil(ok)
      assert.equals("token_too_old", reason)
    end)

    it("rechaza un token que todavía no entró en vigencia (`nbf`)", function()
      local ok, reason = validate(jwt.sign(claims({ nbf = NOW + 120 }), PSK))
      assert.is_nil(ok)
      assert.equals("token_not_yet_valid", reason)
    end)
  end)

  describe("claims de identidad del emisor", function()
    it("rechaza un `iss` distinto del esperado", function()
      local ok, reason = validate(jwt.sign(claims({ iss = "otra-app" }), PSK))
      assert.is_nil(ok)
      assert.equals("issuer_mismatch", reason)
    end)

    it("rechaza un token emitido para otro destinatario", function()
      local ok, reason = validate(jwt.sign(claims({ aud = "otro-gateway" }), PSK))
      assert.is_nil(ok)
      assert.equals("audience_mismatch", reason)
    end)

    it("omite la verificación cuando no se configura `expected_issuer`", function()
      local token = jwt.sign(claims({ iss = "cualquiera" }), PSK)
      assert.is_true(validate(token, { expected_issuer = NONE }))
    end)
  end)

  describe("veredictos de Play Integrity", function()
    it("rechaza una app no reconocida por Play", function()
      local token = jwt.sign(claims({ appRecognitionVerdict = "UNRECOGNIZED_VERSION" }), PSK)
      local ok, reason = validate(token)
      assert.is_nil(ok)
      assert.equals("app_verdict_rejected", reason)
    end)

    it("rechaza un dispositivo que no cumple integridad", function()
      local token = jwt.sign(claims({ deviceRecognitionVerdict = { "MEETS_BASIC_INTEGRITY" } }), PSK)
      local ok, reason = validate(token)
      assert.is_nil(ok)
      assert.equals("device_verdict_rejected", reason)
    end)

    it("exige todos los veredictos de dispositivo configurados", function()
      local token = jwt.sign(claims(), PSK)
      local ok, reason = validate(token, {
        required_device_verdicts = { "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY" },
      })
      assert.is_nil(ok)
      assert.equals("device_verdict_rejected", reason)
    end)

    it("rechaza un token sin veredicto de dispositivo", function()
      local token = jwt.sign(claims({ deviceRecognitionVerdict = NONE }), PSK)
      local ok, reason = validate(token)
      assert.is_nil(ok)
      assert.equals("device_verdict_rejected", reason)
    end)
  end)
end)
