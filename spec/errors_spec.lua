local errors = require "vv.errors"
local fake_kong = require "spec.helpers.fake_kong"

-- Motivos internos que los plugins pueden producir. Ninguno debe filtrarse a
-- la respuesta: son la señal que le diría a un atacante qué control tocó.
local INTERNAL_REASONS = {
  "missing_header",
  "malformed_token",
  "unsupported_alg",
  "invalid_signature",
  "expired_token",
  "token_too_old",
  "issuer_mismatch",
  "audience_mismatch",
  "app_verdict_rejected",
  "device_verdict_rejected",
  "missing_claim",
  "invalid_claim",
}

describe("contrato de error del Gateway", function()
  it("responde 403 forbidden ante una atestación rechazada", function()
    local status, body = errors.build(errors.INVALID_ATTESTATION)

    assert.equals(403, status)
    assert.same({ error = "forbidden", reason = "invalid_attestation" }, body)
  end)

  it("responde 401 unauthorized ante un token de sesión inutilizable", function()
    local status, body = errors.build(errors.INVALID_TOKEN)

    assert.equals(401, status)
    assert.same({ error = "unauthorized", reason = "invalid_token" }, body)
  end)

  it("responde 503 service_unavailable ante una dependencia inalcanzable", function()
    local status, body = errors.build(errors.DEPENDENCY_UNAVAILABLE)

    assert.equals(503, status)
    assert.same({ error = "service_unavailable", reason = "dependency_unavailable" }, body)
  end)

  it("responde 502 bad_gateway ante una dependencia que responde fuera de contrato", function()
    local status, body = errors.build(errors.DEPENDENCY_ERROR)

    assert.equals(502, status)
    assert.same({ error = "bad_gateway", reason = "dependency_error" }, body)
  end)

  it("responde 500 internal_error ante credenciales propias inválidas", function()
    local status, body = errors.build(errors.GATEWAY_FAULT)

    assert.equals(500, status)
    assert.same({ error = "internal_error", reason = "gateway_fault" }, body)
  end)

  it("no expone el motivo interno del rechazo", function()
    local _, body = errors.build(errors.INVALID_ATTESTATION)

    for _, internal_reason in ipairs(INTERNAL_REASONS) do
      assert.not_equals(internal_reason, body.reason)
    end

    -- El body tiene exactamente dos claves: nada de campos de diagnóstico.
    local keys = 0
    for _ in pairs(body) do
      keys = keys + 1
    end
    assert.equals(2, keys)
  end)

  it("devuelve una tabla nueva en cada llamada, para que nadie mute el contrato", function()
    local _, first = errors.build(errors.INVALID_ATTESTATION)
    first.reason = "manipulado"

    local _, second = errors.build(errors.INVALID_ATTESTATION)
    assert.equals("invalid_attestation", second.reason)
  end)

  it("el contrato es cerrado: un motivo desconocido no produce respuesta", function()
    assert.is_nil(errors.build("motivo_inventado"))
  end)

  describe("exit", function()
    local fake

    before_each(function()
      fake = fake_kong.install()
    end)

    after_each(function()
      fake.restore()
    end)

    it("corta la request con el status y el body del contrato, como JSON", function()
      errors.exit(errors.DEPENDENCY_UNAVAILABLE, "detalle interno")

      local exit = fake.last_exit()
      assert.equals(503, exit.status)
      assert.same({ error = "service_unavailable", reason = "dependency_unavailable" }, exit.body)
      assert.equals("application/json; charset=utf-8", exit.headers["Content-Type"])
    end)

    it("manda el detalle interno al log y no a la respuesta", function()
      errors.exit(errors.INVALID_ATTESTATION, "motivo-interno-secreto")

      assert.same({ "motivo-interno-secreto" }, fake.warns)
      for _, value in pairs(fake.last_exit().body) do
        assert.is_nil(tostring(value):find("motivo-interno-secreto", 1, true))
      end
    end)

    it("no escribe al log si no hay detalle", function()
      errors.exit(errors.INVALID_TOKEN)

      assert.same({}, fake.warns)
      assert.equals(401, fake.last_exit().status)
    end)
  end)
end)
