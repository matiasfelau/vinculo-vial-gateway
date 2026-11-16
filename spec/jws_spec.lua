local cjson = require "cjson.safe"
local openssl_digest = require "resty.openssl.digest"
local openssl_hmac = require "resty.openssl.hmac"
local openssl_pkey = require "resty.openssl.pkey"

local jws = require "vv.jws"
local base64url = require "vv.base64url"

local KEY = "secreto-hmac-de-test-0123456789ab"

-- Firma de verdad con HMAC-SHA256 un header y un payload ya serializados.
local function hs256(header_json, payload_json, key)
  local signing_input = base64url.encode(header_json) .. "." .. base64url.encode(payload_json)
  local hmac = assert(openssl_hmac.new(key or KEY, "sha256"))
  assert(hmac:update(signing_input))
  return signing_input .. "." .. base64url.encode(hmac:final())
end

local function token(claims, header)
  return hs256(cjson.encode(header or { alg = "HS256", typ = "JWT" }), cjson.encode(claims))
end

-- Reemplaza `module[name]` mientras dura el caso y lo repone al terminar.
local function stub(module, name, replacement, restorers)
  local original = module[name]
  module[name] = replacement
  restorers[#restorers + 1] = function() module[name] = original end
end

describe("jws", function()
  local restorers

  before_each(function()
    restorers = {}
  end)

  after_each(function()
    for _, restore in ipairs(restorers) do
      restore()
    end
  end)

  describe("split", function()
    it("parte un JWT compacto en sus tres segmentos", function()
      local header, payload, signature = jws.split("aaa.bbb.ccc")
      assert.same({ "aaa", "bbb", "ccc" }, { header, payload, signature })
    end)

    it("rechaza lo que no tiene exactamente tres segmentos base64url", function()
      assert.is_nil(jws.split("aaa.bbb"))
      assert.is_nil(jws.split("aaa.bbb.ccc.ddd"))
      assert.is_nil(jws.split("aaa.b b.ccc"))
      assert.is_nil(jws.split(""))
    end)

    it("rechaza lo que no es un string", function()
      assert.is_nil(jws.split(nil))
      assert.is_nil(jws.split({ "aaa.bbb.ccc" }))
      assert.is_nil(jws.split(42))
    end)
  end)

  describe("verify_hs256", function()
    it("devuelve los claims de un token bien firmado", function()
      local claims = jws.verify_hs256(token({ sub = "u-1", n = 7 }), KEY)
      assert.same({ sub = "u-1", n = 7 }, claims)
    end)

    it("rechaza si no hay clave con la que verificar", function()
      for _, missing in ipairs({ "", false, 12 }) do
        local claims, reason = jws.verify_hs256(token({ sub = "u-1" }), missing)
        assert.is_nil(claims)
        assert.equals("missing_key", reason)
      end

      local claims, reason = jws.verify_hs256(token({ sub = "u-1" }), nil)
      assert.is_nil(claims)
      assert.equals("missing_key", reason)
    end)

    it("rechaza un token que no es un JWT compacto", function()
      local claims, reason = jws.verify_hs256("no-es-un-jwt", KEY)
      assert.is_nil(claims)
      assert.equals("malformed_token", reason)
    end)

    it("rechaza un header que no es JSON", function()
      local claims, reason = jws.verify_hs256(hs256("no es json", '{"sub":"u-1"}'), KEY)
      assert.is_nil(claims)
      assert.equals("malformed_header", reason)
    end)

    it("rechaza un header que no es un objeto", function()
      local claims, reason = jws.verify_hs256(hs256("[1,2]", '{"sub":"u-1"}'), KEY)
      -- Un arreglo es una tabla válida pero no declara el algoritmo.
      assert.is_nil(claims)
      assert.equals("unsupported_alg", reason)
    end)

    it("rechaza `alg: none`, aunque el token venga bien armado", function()
      local forged = base64url.encode('{"alg":"none"}') .. "."
        .. base64url.encode('{"sub":"admin"}') .. "." .. "c2ln"
      local claims, reason = jws.verify_hs256(forged, KEY)

      assert.is_nil(claims)
      assert.equals("unsupported_alg", reason)
    end)

    it("rechaza otros algoritmos: no hay negociación por el header del token", function()
      for _, alg in ipairs({ "RS256", "HS512", "hs256" }) do
        local claims, reason = jws.verify_hs256(token({ sub = "u-1" }, { alg = alg }), KEY)
        assert.is_nil(claims)
        assert.equals("unsupported_alg", reason)
      end
    end)

    it("rechaza una firma hecha con otra clave", function()
      local forged = hs256('{"alg":"HS256"}', '{"sub":"u-1"}', "clave-de-un-atacante-0123456789")
      local claims, reason = jws.verify_hs256(forged, KEY)

      assert.is_nil(claims)
      assert.equals("invalid_signature", reason)
    end)

    it("rechaza un payload alterado después de firmar", function()
      local header_b64, _, signature_b64 = jws.split(token({ sub = "u-1" }))
      local tampered = header_b64 .. "." .. base64url.encode('{"sub":"admin"}')
        .. "." .. signature_b64

      local claims, reason = jws.verify_hs256(tampered, KEY)
      assert.is_nil(claims)
      assert.equals("invalid_signature", reason)
    end)

    it("rechaza una firma que no es base64url decodificable", function()
      local header_b64, payload_b64 = jws.split(token({ sub = "u-1" }))
      local claims, reason = jws.verify_hs256(header_b64 .. "." .. payload_b64 .. ".a", KEY)

      assert.is_nil(claims)
      assert.equals("invalid_signature", reason)
    end)

    it("rechaza un payload firmado correctamente pero que no es JSON", function()
      local claims, reason = jws.verify_hs256(hs256('{"alg":"HS256"}', "esto no es json"), KEY)

      assert.is_nil(claims)
      assert.equals("malformed_claims", reason)
    end)

    it("falla cerrado si OpenSSL no puede armar el HMAC", function()
      local signed = token({ sub = "u-1" })
      stub(openssl_hmac, "new", function() return nil, "sin motor" end, restorers)

      local claims, reason = jws.verify_hs256(signed, KEY)
      assert.is_nil(claims)
      assert.equals("hmac_error: sin motor", reason)
    end)

    it("falla cerrado si OpenSSL no puede procesar el mensaje", function()
      local signed = token({ sub = "u-1" })
      stub(openssl_hmac, "new", function()
        return { update = function() return nil, "memoria" end }
      end, restorers)

      local claims, reason = jws.verify_hs256(signed, KEY)
      assert.is_nil(claims)
      assert.equals("hmac_error: memoria", reason)
    end)
  end)

  describe("sign_rs256", function()
    local rsa = assert(openssl_pkey.new({ type = "RSA", bits = 2048 }))
    local PEM = assert(rsa:to_PEM("private"))

    local function verify(signed)
      local header_b64, claims_b64, signature_b64 = jws.split(signed)
      local digest = assert(openssl_digest.new("sha256"))
      assert(digest:update(header_b64 .. "." .. claims_b64))
      return rsa:verify(base64url.decode(signature_b64), digest)
    end

    it("firma con RS256 de forma verificable con la clave pública", function()
      local signed = assert(jws.sign_rs256({ iss = "gateway" }, PEM))
      local header_b64, claims_b64 = jws.split(signed)

      assert.same({ alg = "RS256", typ = "JWT" }, cjson.decode(base64url.decode(header_b64)))
      assert.same({ iss = "gateway" }, cjson.decode(base64url.decode(claims_b64)))
      assert.is_true(verify(signed))
    end)

    it("agrega los headers extra, como el `kid`", function()
      local signed = assert(jws.sign_rs256({ iss = "gateway" }, PEM, { kid = "abc123" }))
      local header = cjson.decode(base64url.decode((jws.split(signed))))

      assert.equals("abc123", header.kid)
      assert.equals("RS256", header.alg)
    end)

    it("falla con una clave privada inválida", function()
      local signed, reason = jws.sign_rs256({ iss = "gateway" }, "no es una clave")
      assert.is_nil(signed)
      assert.matches("^invalid_private_key", reason)
    end)

    it("falla cerrado si OpenSSL no puede crear el digest", function()
      stub(openssl_digest, "new", function() return nil, "sin sha256" end, restorers)

      local signed, reason = jws.sign_rs256({ iss = "gateway" }, PEM)
      assert.is_nil(signed)
      assert.equals("digest_error: sin sha256", reason)
    end)

    it("falla cerrado si OpenSSL no puede procesar el mensaje", function()
      stub(openssl_digest, "new", function()
        return { update = function() return nil, "memoria" end }
      end, restorers)

      local signed, reason = jws.sign_rs256({ iss = "gateway" }, PEM)
      assert.is_nil(signed)
      assert.equals("digest_error: memoria", reason)
    end)

    it("falla cerrado si la clave no logra firmar", function()
      stub(openssl_pkey, "new", function()
        return { sign = function() return nil, "clave sin permisos" end }
      end, restorers)

      local signed, reason = jws.sign_rs256({ iss = "gateway" }, PEM)
      assert.is_nil(signed)
      assert.equals("sign_error: clave sin permisos", reason)
    end)
  end)
end)
