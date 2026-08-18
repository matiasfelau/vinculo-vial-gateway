local google = require "kong.plugins.app-attestation.sources.google"
local mock = require "kong.plugins.app-attestation.sources.mock"
local play = require "spec.helpers.playintegrity"

local PSK = "psk-de-test-32-bytes-minimo-0123456789"
local NOW = 1735689600

describe("fuente google", function()
  describe("interpretación de la respuesta", function()
    it("extrae el veredicto de una respuesta exitosa", function()
      local verdict = play.verdict(NOW)
      local parsed = google.parse_response(200, play.decode_response(verdict))

      assert.equals(play.PACKAGE_NAME, parsed.requestDetails.requestPackageName)
      assert.equals("PLAY_RECOGNIZED", parsed.appIntegrity.appRecognitionVerdict)
      assert.same({ "MEETS_DEVICE_INTEGRITY" },
                  parsed.deviceIntegrity.deviceRecognitionVerdict)
    end)

    it("distingue un token rechazado por Google de un problema nuestro", function()
      -- 400: el token es inválido, manipulado o de otra app. Culpa del cliente.
      local verdict, reason = google.parse_response(400, '{"error":{"code":400}}')
      assert.is_nil(verdict)
      assert.equals("playintegrity_token_rejected", reason)

      -- 401/403: nuestras credenciales. El cliente no puede hacer nada.
      for _, status in ipairs({ 401, 403 }) do
        local _, unauthorized = google.parse_response(status, "{}")
        assert.equals("playintegrity_unauthorized", unauthorized)
      end
    end)

    it("reporta el status ante cualquier otro error", function()
      local verdict, reason = google.parse_response(503, "unavailable")
      assert.is_nil(verdict)
      assert.equals("playintegrity_http_503", reason)
    end)

    it("rechaza una respuesta 200 que no es JSON", function()
      local verdict, reason = google.parse_response(200, "<html>error</html>")
      assert.is_nil(verdict)
      assert.equals("playintegrity_malformed_response", reason)
    end)

    it("rechaza una respuesta 200 sin el payload esperado", function()
      local verdict, reason = google.parse_response(200, '{"otraCosa":{}}')
      assert.is_nil(verdict)
      assert.equals("playintegrity_missing_payload", reason)
    end)
  end)
end)

describe("fuente mock", function()
  local conf = { psk = PSK, clock_skew_seconds = 30 }

  it("devuelve el veredicto que transporta un token bien firmado", function()
    local verdict = play.verdict(NOW)
    local parsed = mock.fetch(play.sign_mock(verdict, PSK), conf)

    assert.equals(play.PACKAGE_NAME, parsed.requestDetails.requestPackageName)
    assert.same({ "MEETS_DEVICE_INTEGRITY" },
                parsed.deviceIntegrity.deviceRecognitionVerdict)
  end)

  it("rechaza un token firmado con otra PSK", function()
    local token = play.sign_mock(play.verdict(NOW), "psk-de-un-atacante-0123456789ab")
    local verdict, reason = mock.fetch(token, conf)

    assert.is_nil(verdict)
    assert.equals("invalid_signature", reason)
  end)

  it("rechaza `alg: none`", function()
    local token = play.sign_mock(play.verdict(NOW), PSK, { alg = "none" })
    local verdict, reason = mock.fetch(token, conf)

    assert.is_nil(verdict)
    assert.equals("unsupported_alg", reason)
  end)

  it("rechaza confusión de algoritmo (RS256)", function()
    local token = play.sign_mock(play.verdict(NOW), PSK, { alg = "RS256" })
    local verdict, reason = mock.fetch(token, conf)

    assert.is_nil(verdict)
    assert.equals("unsupported_alg", reason)
  end)

  it("rechaza algo que no es un JWT compacto", function()
    local verdict, reason = mock.fetch("no-es-un-jwt", conf)

    assert.is_nil(verdict)
    assert.equals("malformed_token", reason)
  end)

  it("rechaza un token cuyo sobre JWT ya expiró", function()
    local verdict = play.verdict(NOW)
    verdict.exp = ngx.time() - 3600

    local parsed, reason = mock.fetch(play.sign_mock(verdict, PSK), conf)

    assert.is_nil(parsed)
    assert.equals("mock_token_expired", reason)
  end)

  it("rechaza si no hay PSK configurada", function()
    local verdict, reason = mock.fetch(play.sign_mock(play.verdict(NOW), PSK), {})

    assert.is_nil(verdict)
    assert.equals("missing_key", reason)
  end)
end)
