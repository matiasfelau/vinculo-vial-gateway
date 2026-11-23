local request_hash = require "kong.plugins.app-attestation.request_hash"

-- Sobre HPKE tal como lo manda la app en signup.
local BODY = '{"ephemeral_public_key":"AAAA","ciphertext":"BBBB"}'

describe("hash del body", function()
  describe("encodings", function()
    -- Vectores fijos: si alguno cambia, el contrato con el Frontend se rompió.
    it("calcula SHA-256 en hexadecimal", function()
      assert.equals(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        request_hash.compute("abc", "hex")
      )
    end)

    it("calcula SHA-256 en base64", function()
      assert.equals(
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
        request_hash.compute("abc", "base64")
      )
    end)

    it("calcula SHA-256 en base64url, sin padding", function()
      assert.equals(
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
        request_hash.compute("abc", "base64url")
      )
    end)

    it("rechaza un encoding no soportado", function()
      local hash, reason = request_hash.compute(BODY, "base32")
      assert.is_nil(hash)
      assert.equals("unsupported_encoding", reason)
    end)

    it("expone los encodings disponibles para el schema", function()
      assert.same({ "base64", "base64url", "hex" }, request_hash.encodings())
    end)
  end)

  describe("comparación", function()
    it("acepta el hash del mismo body", function()
      local hash = request_hash.compute(BODY, "hex")
      assert.is_true(request_hash.matches(hash, BODY, "hex"))
    end)

    it("rechaza el hash de otro body", function()
      local hash = request_hash.compute(BODY, "hex")
      local otro = '{"ephemeral_public_key":"AAAA","ciphertext":"MANIPULADO"}'
      assert.is_false(request_hash.matches(hash, otro, "hex"))
    end)

    it("rechaza un hash en otro encoding aunque sean los mismos bytes", function()
      -- Confundir el encoding entre el Frontend y el Gateway es el error más
      -- probable de integración: tiene que fallar, no pasar de casualidad.
      local hex = request_hash.compute(BODY, "hex")
      assert.is_false(request_hash.matches(hex, BODY, "base64"))
    end)

    it("maneja un body vacío sin romperse", function()
      local hash = request_hash.compute("", "hex")
      assert.equals(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hash
      )
    end)

    it("falla si no hay body", function()
      local hash, reason = request_hash.compute(nil, "hex")
      assert.is_nil(hash)
      assert.equals("missing_body", reason)
    end)
  end)

  describe("fallas de OpenSSL", function()
    local openssl_digest = require "resty.openssl.digest"
    local original_new

    before_each(function()
      original_new = openssl_digest.new
    end)

    after_each(function()
      openssl_digest.new = original_new
    end)

    it("falla cerrado si no se puede crear el digest", function()
      openssl_digest.new = function() return nil, "sin sha256" end

      local hash, reason = request_hash.compute("body", "hex")
      assert.is_nil(hash)
      assert.equals("digest_error: sin sha256", reason)
    end)

    it("falla cerrado si el digest no procesa el body", function()
      openssl_digest.new = function()
        return { update = function() return nil, "memoria" end }
      end

      local hash, reason = request_hash.compute("body", "hex")
      assert.is_nil(hash)
      assert.equals("digest_error: memoria", reason)
    end)
  end)

  describe("comparación ante errores", function()
    it("no acepta nada si no se puede calcular el hash esperado", function()
      local matches, reason = request_hash.matches("cualquier-cosa", "body", "rot13")
      assert.is_nil(matches)
      assert.equals("unsupported_encoding", reason)

      matches, reason = request_hash.matches("cualquier-cosa", nil, "hex")
      assert.is_nil(matches)
      assert.equals("missing_body", reason)
    end)
  end)
end)
