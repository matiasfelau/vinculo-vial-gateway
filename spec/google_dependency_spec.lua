local cjson = require "cjson.safe"
local openssl_pkey = require "resty.openssl.pkey"

-- Par de claves generado en el arranque de la suite: nada de material
-- criptográfico versionado en el repo.
local key = assert(openssl_pkey.new({ type = "RSA", bits = 2048 }))

local SERVICE_ACCOUNT = cjson.encode({
  type = "service_account",
  project_id = "vinculo-vial",
  private_key_id = "abc123",
  private_key = assert(key:to_PEM("private")),
  client_email = "gateway@vinculo-vial.iam.gserviceaccount.com",
  token_uri = "https://oauth2.test/token",
})

local OAUTH_BODY = '{"access_token":"ya29.token","expires_in":3599,"token_type":"Bearer"}'
local VERDICT_BODY = cjson.encode({ tokenPayloadExternal = { requestDetails = {} } })

-- Los módulos bajo prueba toman `resty.http` al cargarse, así que se recargan
-- con un cliente falso inyectado y se restauran al terminar cada caso: ningún
-- otro spec debe ver la versión sustituida.
local MODULES = {
  "resty.http",
  "kong.plugins.app-attestation.google_oauth",
  "kong.plugins.app-attestation.sources.google",
}

local function conf(overrides)
  local base = {
    dependency_timeout_ms = 4000,
    dependency_call_timeout_ms = 3000,
    service_account_json = SERVICE_ACCOUNT,
    ssl_verify = false,
    playintegrity_url = "https://playintegrity.test",
    package_name = "ar.test.app",
  }

  for name, value in pairs(overrides or {}) do
    base[name] = value
  end

  return base
end

local function oauth_ok(elapsed_ms)
  return { status = 200, body = OAUTH_BODY, elapsed_ms = elapsed_ms }
end

local function verdict_ok(elapsed_ms)
  return { status = 200, body = VERDICT_BODY, elapsed_ms = elapsed_ms }
end

describe("llamadas a Google: clasificación de fallas y presupuesto", function()
  local saved_modules, saved_now, saved_shared
  local clock, calls, script, google

  before_each(function()
    saved_modules = {}
    for _, name in ipairs(MODULES) do
      saved_modules[name] = package.loaded[name]
    end

    clock = 1000.0
    calls = {}
    script = {}

    saved_now = ngx.now
    ngx.now = function()
      return clock
    end

    -- Caché del access token en memoria compartida, falsa: mismo contrato
    -- (`get`/`set`) que el shared dict `vv_attestation` real.
    saved_shared = ngx.shared
    local store = {}
    ngx.shared = {
      vv_attestation = {
        get = function(_, name)
          return store[name]
        end,
        set = function(_, name, value)
          store[name] = value
          return true
        end,
      },
    }

    package.loaded["resty.http"] = {
      new = function()
        local client = {}

        function client:set_timeout(ms)
          self.timeout = ms
        end

        -- Cada llamada consume el siguiente paso del guion y adelanta el
        -- reloj lo que "tardó": así se prueba el reparto del presupuesto sin
        -- esperar de verdad.
        function client:request_uri(url)
          local step = table.remove(script, 1)
          assert(step, "request_uri sin un paso en el guion: " .. url)

          calls[#calls + 1] = { url = url, timeout = self.timeout }
          clock = clock + (step.elapsed_ms or 0) / 1000

          if step.err then
            return nil, step.err
          end

          return { status = step.status, body = step.body }
        end

        return client
      end,
    }

    package.loaded["kong.plugins.app-attestation.google_oauth"] = nil
    package.loaded["kong.plugins.app-attestation.sources.google"] = nil
    google = require "kong.plugins.app-attestation.sources.google"
  end)

  after_each(function()
    ngx.now = saved_now
    ngx.shared = saved_shared

    for _, name in ipairs(MODULES) do
      package.loaded[name] = saved_modules[name]
    end
  end)

  describe("dependencia caída o sin respuesta → unavailable (503)", function()
    it("conexión rechazada en el canje de OAuth, sin llamar a Play Integrity", function()
      script = { { err = "connection refused" } }

      local verdict, reason, kind = google.fetch("token", conf())

      assert.is_nil(verdict)
      assert.matches("oauth_unreachable", reason)
      assert.equals("unavailable", kind)
      assert.equals(1, #calls)
    end)

    it("timeout de decodeIntegrityToken", function()
      script = { oauth_ok(), { err = "timeout" } }

      local verdict, reason, kind = google.fetch("token", conf())

      assert.is_nil(verdict)
      assert.matches("playintegrity_unreachable", reason)
      assert.equals("unavailable", kind)
      assert.equals(2, #calls)
    end)
  end)

  describe("dependencia que responde mal → upstream_error (502)", function()
    it("5xx del canje de OAuth, sin llamar a Play Integrity", function()
      script = { { status = 503, body = "unavailable" } }

      local verdict, reason, kind = google.fetch("token", conf())

      assert.is_nil(verdict)
      assert.equals("oauth_http_503", reason)
      assert.equals("upstream_error", kind)
      assert.equals(1, #calls)
    end)

    it("5xx de decodeIntegrityToken", function()
      script = { oauth_ok(), { status = 503, body = "unavailable" } }

      local verdict, reason, kind = google.fetch("token", conf())

      assert.is_nil(verdict)
      assert.equals("playintegrity_http_503", reason)
      assert.equals("upstream_error", kind)
    end)
  end)

  describe("un 4xx del token del cliente no es una falla de dependencia", function()
    it("repetido, nunca se clasifica como caída ni como respuesta inválida", function()
      script = { oauth_ok() }
      for _ = 1, 5 do
        script[#script + 1] = { status = 400, body = '{"error":{"code":400}}' }
      end

      for _ = 1, 5 do
        local verdict, reason, kind = google.fetch("token", conf())

        assert.is_nil(verdict)
        assert.equals("playintegrity_token_rejected", reason)
        assert.equals("rejected", kind)
      end

      -- Un solo canje de OAuth (queda en caché) y cinco llamadas a Play
      -- Integrity: nada de lo anterior alteró el camino de las siguientes.
      assert.equals(6, #calls)
    end)
  end)

  describe("presupuesto agregado del par OAuth + decodeIntegrityToken", function()
    it("la primera llamada recibe el techo por llamada, aunque el agregado sea mayor", function()
      script = { oauth_ok(), verdict_ok() }

      google.fetch("token", conf({ dependency_timeout_ms = 10000 }))

      assert.equals(3000, calls[1].timeout)
    end)

    it("lo que consume el canje de OAuth se descuenta de la segunda llamada", function()
      script = { oauth_ok(2500), verdict_ok() }

      local verdict = google.fetch("token", conf())

      assert.is_table(verdict)
      assert.equals(3000, calls[1].timeout)
      -- 4000 de agregado menos los 2500 que tardó el canje: quedan 1500, no
      -- una ventana nueva de 3000.
      assert.equals(1500, calls[2].timeout)
    end)

    it("sin presupuesto restante no intenta la segunda llamada", function()
      script = { oauth_ok(4000) }

      local verdict, reason, kind = google.fetch("token", conf())

      assert.is_nil(verdict)
      assert.equals("playintegrity_deadline_exceeded", reason)
      assert.equals("unavailable", kind)
      assert.equals(1, #calls)
    end)

    it("con el access token en caché la segunda llamada dispone del techo completo", function()
      script = { oauth_ok(), verdict_ok(), verdict_ok() }

      google.fetch("token", conf())
      google.fetch("token", conf())

      -- Dos llamadas a Play Integrity y un solo canje de OAuth.
      assert.equals(3, #calls)
      assert.matches("oauth2.test", calls[1].url)
      assert.matches("playintegrity.test", calls[3].url)
      assert.equals(3000, calls[3].timeout)
    end)
  end)
end)
