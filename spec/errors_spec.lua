local errors = require "vv.errors"

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
end)
