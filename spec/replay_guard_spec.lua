local fake_kong = require "spec.helpers.fake_kong"

local MODULE = "kong.plugins.app-attestation.replay_guard"
local TOKEN = "token-de-atestacion-de-un-solo-uso"

describe("replay_guard", function()
  local fake, guard

  -- El módulo recuerda (por worker) que ya avisó que falta el shared dict:
  -- cada caso arranca con una copia limpia.
  local function fresh_guard()
    package.loaded[MODULE] = nil
    return require(MODULE)
  end

  before_each(function()
    fake = fake_kong.install()
    guard = fresh_guard()
  end)

  after_each(function()
    fake.restore()
    package.loaded[MODULE] = nil
  end)

  describe("fingerprint", function()
    it("es estable para el mismo token y distinto para otro", function()
      assert.equals(guard.fingerprint(TOKEN), guard.fingerprint(TOKEN))
      assert.are_not.equals(guard.fingerprint(TOKEN), guard.fingerprint(TOKEN .. "x"))
    end)

    it("guarda 128 bits de hash con prefijo, nunca el token", function()
      local fingerprint = guard.fingerprint(TOKEN)

      assert.matches("^seen:%x+$", fingerprint)
      assert.equals(#"seen:" + 32, #fingerprint)
      assert.is_nil(fingerprint:find(TOKEN, 1, true))
    end)
  end)

  describe("fingerprint ante fallas de OpenSSL", function()
    local openssl_digest = require "resty.openssl.digest"
    local original_new

    before_each(function()
      original_new = openssl_digest.new
    end)

    after_each(function()
      openssl_digest.new = original_new
    end)

    it("no inventa una huella si no se puede crear el digest", function()
      openssl_digest.new = function() return nil, "sin sha256" end
      assert.is_nil(guard.fingerprint(TOKEN))
    end)

    it("no inventa una huella si el digest no procesa el token", function()
      openssl_digest.new = function()
        return { update = function() return nil, "memoria" end }
      end
      assert.is_nil(guard.fingerprint(TOKEN))
    end)
  end)

  describe("consume", function()
    it("acepta la primera presentación y rechaza la segunda como replay", function()
      local fingerprint = guard.fingerprint(TOKEN)

      assert.is_true(guard.consume(fingerprint, 150))

      local ok, reason = guard.consume(fingerprint, 150)
      assert.is_nil(ok)
      assert.equals("replay", reason)
    end)

    it("registra el token con el TTL pedido, para que el registro expire solo", function()
      local fingerprint = guard.fingerprint(TOKEN)
      guard.consume(fingerprint, 150)

      assert.equals(150, fake.dict.ttls[fingerprint])
    end)

    it("no mezcla tokens distintos", function()
      assert.is_true(guard.consume(guard.fingerprint("token-a"), 150))
      assert.is_true(guard.consume(guard.fingerprint("token-b"), 150))
    end)

    it("deja pasar y lo avisa por log cuando el diccionario está lleno", function()
      fake.restore()
      fake = fake_kong.install({ dict = fake_kong.shared_dict({ full = true }) })
      guard = fresh_guard()

      assert.is_true(guard.consume(guard.fingerprint(TOKEN), 150))
      assert.equals(1, #fake.errs)
      assert.matches("no memory", fake.errs[1])
    end)

    it("deja pasar si no hay fingerprint que registrar", function()
      assert.is_true(guard.consume(nil, 150))
    end)
  end)

  describe("seen", function()
    it("consulta sin reservar: no consume el token", function()
      local fingerprint = guard.fingerprint(TOKEN)

      assert.is_false(guard.seen(fingerprint))
      assert.is_false(guard.seen(fingerprint))
      assert.is_true(guard.consume(fingerprint, 150))
    end)

    it("detecta un token ya consumido", function()
      local fingerprint = guard.fingerprint(TOKEN)
      guard.consume(fingerprint, 150)

      assert.is_true(guard.seen(fingerprint))
    end)

    it("sin fingerprint no afirma nada", function()
      assert.is_false(guard.seen(nil))
    end)
  end)

  describe("sin el shared dict declarado", function()
    before_each(function()
      fake.restore()
      fake = fake_kong.install({ dict = false })
      guard = fresh_guard()
    end)

    it("no bloquea tráfico: nada figura como visto y todo se consume", function()
      local fingerprint = guard.fingerprint(TOKEN)

      assert.is_false(guard.seen(fingerprint))
      assert.is_true(guard.consume(fingerprint, 150))
      assert.is_true(guard.consume(fingerprint, 150))
    end)

    it("avisa del problema de configuración una sola vez, no en cada request", function()
      local fingerprint = guard.fingerprint(TOKEN)

      guard.seen(fingerprint)
      guard.consume(fingerprint, 150)
      guard.seen(fingerprint)

      assert.equals(1, #fake.errs)
      assert.matches("vv_attestation", fake.errs[1])
    end)
  end)
end)
