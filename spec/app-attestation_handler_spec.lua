local cjson = require "cjson.safe"

local fake_kong = require "spec.helpers.fake_kong"
local play = require "spec.helpers.playintegrity"
local request_hash = require "kong.plugins.app-attestation.request_hash"
local handler = require "kong.plugins.app-attestation.handler"
local google_source = require "kong.plugins.app-attestation.sources.google"

local PSK = "psk-de-test-32-bytes-minimo-0123456789"
local NOW = 1735689600
local BODY = '{"cipher":"cGF5bG9hZC1jaWZyYWRv"}'

-- El cuerpo público que ve el cliente ante CUALQUIER rechazo de atestación.
local PUBLIC_REJECTION = { error = "forbidden", reason = "invalid_attestation" }

local function conf(overrides)
  local c = {
    source = "mock",
    package_name = play.PACKAGE_NAME,
    psk = PSK,
    header_name = "X-App-Attestation",
    max_token_bytes = 16384,
    require_request_hash = true,
    request_hash_encoding = "hex",
    replay_guard = true,
    max_age_seconds = 120,
    clock_skew_seconds = 30,
    strip_header = true,
    accepted_app_verdicts = { "PLAY_RECOGNIZED" },
    accepted_device_verdicts = { "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY" },
    accepted_licensing_verdicts = {},
    expected_certificate_digests = {},
    dependency_timeout_ms = 4000,
    dependency_call_timeout_ms = 3000,
    ssl_verify = true,
  }

  for key, value in pairs(overrides or {}) do
    c[key] = value
  end

  return c
end

-- Token del mock atado al body indicado, firmado de verdad con la PSK.
local function signed_token(body, verdict_overrides)
  local overrides = { requestDetails = { requestHash = request_hash.compute(body, "hex") } }
  for key, value in pairs(verdict_overrides or {}) do
    overrides[key] = value
  end

  return play.sign_mock(play.verdict(NOW, overrides), PSK)
end

describe("app-attestation: handler", function()
  local fake

  local function run(opts, config)
    opts = opts or {}
    opts.now = NOW
    fake = fake_kong.install(opts)
    handler:access(config or conf())
    return fake
  end

  after_each(function()
    if fake then
      fake.restore()
      fake = nil
    end
  end)

  describe("request legítima", function()
    it("pasa sin cortar la request y no propaga el token hacia adentro", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY })

      assert.equals(0, #fake.exits)
      assert.same({ "X-App-Attestation" }, fake.cleared)
    end)

    it("conserva el header si `strip_header` está apagado", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY },
          conf({ strip_header = false }))

      assert.equals(0, #fake.exits)
      assert.same({}, fake.cleared)
    end)

    it("respeta el nombre de header configurado", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-Otro-Header"] = token }, body = BODY },
          conf({ header_name = "X-Otro-Header" }))

      assert.equals(0, #fake.exits)
      assert.same({ "X-Otro-Header" }, fake.cleared)
    end)

    it("no lee el body cuando la ligadura con el request está desactivada", function()
      local token = play.sign_mock(play.verdict(NOW), PSK)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY },
          conf({ require_request_hash = false }))

      assert.equals(0, #fake.exits)
      assert.equals(0, fake.body_reads)
    end)
  end)

  describe("rechazos al cliente", function()
    local function assert_rejected()
      assert.equals(1, #fake.exits)
      local exit = fake.last_exit()
      assert.equals(403, exit.status)
      assert.same(PUBLIC_REJECTION, exit.body)
      assert.matches("application/json", exit.headers["Content-Type"])
    end

    it("rechaza una request sin el header", function()
      run({ headers = {}, body = BODY })

      assert_rejected()
      assert.matches("missing_header", fake.warns[1])
    end)

    it("rechaza un header vacío", function()
      run({ headers = { ["X-App-Attestation"] = "" }, body = BODY })

      assert_rejected()
      assert.matches("missing_header", fake.warns[1])
    end)

    it("rechaza un header repetido, que el PDK entrega como tabla", function()
      run({ headers = { ["X-App-Attestation"] = { "a", "b" } }, body = BODY })

      assert_rejected()
      assert.matches("missing_header", fake.warns[1])
    end)

    it("rechaza un token más grande que el máximo, sin llegar a la fuente", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY },
          conf({ max_token_bytes = #token - 1 }))

      assert_rejected()
      assert.matches("token_too_large", fake.warns[1])
      assert.equals(0, fake.body_reads)
    end)

    it("rechaza si el body no está disponible, fallando cerrado", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = nil,
            body_err = "request body in temp file not supported" })

      assert_rejected()
      assert.matches("body_unavailable", fake.warns[1])
      assert.matches("temp file", fake.warns[1])
    end)

    it("rechaza un encoding de hash que no soporta, en vez de saltearse el control", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY },
          conf({ request_hash_encoding = "rot13" }))

      assert_rejected()
      assert.matches("unsupported_encoding", fake.warns[1])
    end)

    it("rechaza un token firmado con otra PSK", function()
      local forged = play.sign_mock(play.verdict(NOW), "psk-de-un-atacante-0123456789ab")
      run({ headers = { ["X-App-Attestation"] = forged }, body = BODY })

      assert_rejected()
      assert.matches("invalid_signature", fake.warns[1])
    end)

    it("rechaza una atestación atada a otro body y dice por qué en el log", function()
      local token = signed_token('{"cipher":"otro-payload"}')
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY })

      assert_rejected()
      assert.matches("request_hash_mismatch", fake.warns[1])
      assert.matches("encoding='hex'", fake.warns[1])
    end)

    it("rechaza un veredicto que no cumple la política", function()
      local token = signed_token(BODY, {
        deviceIntegrity = { deviceRecognitionVerdict = {} },
      })
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY })

      assert_rejected()
      assert.matches("device_verdict_rejected", fake.warns[1])
    end)

    it("responde igual ante cualquier causa: el motivo real queda sólo en el log", function()
      local bodies = {}

      for _, case in ipairs({
        { headers = {} },
        { headers = { ["X-App-Attestation"] = "no-es-un-jwt" } },
        { headers = { ["X-App-Attestation"] = signed_token('{"x":1}') } },
      }) do
        case.body = BODY
        run(case)
        bodies[#bodies + 1] = cjson.encode(fake.last_exit().body)
        fake.restore()
      end

      assert.equals(bodies[1], bodies[2])
      assert.equals(bodies[2], bodies[3])
    end)

    it("no filtra el token ni al log ni a la respuesta", function()
      local token = signed_token('{"cipher":"otro-payload"}')
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY })

      assert.is_nil(cjson.encode(fake.last_exit().body):find(token, 1, true))
      for _, line in ipairs(fake.warns) do
        assert.is_nil(line:find(token, 1, true))
      end
    end)
  end)

  describe("un solo uso (anti-replay)", function()
    it("rechaza el reenvío exacto de una atestación ya aceptada", function()
      local token = signed_token(BODY)
      local opts = { headers = { ["X-App-Attestation"] = token }, body = BODY }

      run(opts)
      assert.equals(0, #fake.exits)

      -- Segunda presentación: mismo nodo, mismo shared dict.
      local dict = fake.dict
      fake.restore()
      opts.dict = dict
      run(opts)

      assert.equals(1, #fake.exits)
      assert.equals(403, fake.last_exit().status)
      assert.matches("replay_detected", fake.warns[1])
    end)

    it("detecta el replay concurrente que el chequeo previo no vio", function()
      -- Dos requests con el mismo token pasan el `seen` antes de que cualquiera
      -- registre: el `add` atómico deja entrar sólo a una.
      local dict = fake_kong.shared_dict()
      local token = signed_token(BODY)
      dict.get = function() return nil end

      run({ headers = { ["X-App-Attestation"] = token }, body = BODY, dict = dict })
      assert.equals(0, #fake.exits)
      fake.restore()

      run({ headers = { ["X-App-Attestation"] = token }, body = BODY, dict = dict })
      assert.equals(1, #fake.exits)
      assert.equals(403, fake.last_exit().status)
      assert.matches("replay", fake.warns[1])
    end)

    it("registra la atestación con la vida máxima más la tolerancia de reloj", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY },
          conf({ max_age_seconds = 120, clock_skew_seconds = 30 }))

      local ttls = {}
      for _, ttl in pairs(fake.dict.ttls) do
        ttls[#ttls + 1] = ttl
      end
      assert.same({ 150 }, ttls)
    end)

    it("no registra nada si el anti-replay está apagado", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY },
          conf({ replay_guard = false }))

      assert.equals(0, #fake.exits)
      assert.is_nil(next(fake.dict.store))
    end)

    it("sigue funcionando sin shared dict, con las demás defensas en pie", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY, dict = false })

      assert.equals(0, #fake.exits)
    end)

    it("con el diccionario lleno prefiere dejar pasar antes que cortar el tráfico", function()
      local token = signed_token(BODY)
      run({ headers = { ["X-App-Attestation"] = token }, body = BODY,
            dict = fake_kong.shared_dict({ full = true }) })

      assert.equals(0, #fake.exits)
    end)

    it("consume el token aunque la política lo rechace: no hay segundo intento", function()
      local token = signed_token('{"cipher":"otro-payload"}')
      local opts = { headers = { ["X-App-Attestation"] = token }, body = BODY }

      run(opts)
      assert.matches("request_hash_mismatch", fake.warns[1])

      local dict = fake.dict
      fake.restore()
      opts.dict = dict
      run(opts)
      assert.matches("replay_detected", fake.warns[1])
    end)
  end)

  describe("fallas de la dependencia (fuente google)", function()
    local original_fetch

    before_each(function()
      original_fetch = google_source.fetch
    end)

    after_each(function()
      google_source.fetch = original_fetch
    end)

    local function fails_with(reason, kind)
      google_source.fetch = function()
        return nil, reason, kind
      end
    end

    local function run_google(opts)
      opts = opts or {}
      opts.headers = { ["X-App-Attestation"] = "token-opaco-de-play-integrity" }
      opts.body = BODY
      return run(opts, conf({ source = "google" }))
    end

    it("responde 503 si la dependencia está inalcanzable", function()
      fails_with("playintegrity_unreachable: timeout", "unavailable")
      run_google()

      local exit = fake.last_exit()
      assert.equals(503, exit.status)
      assert.same({ error = "service_unavailable", reason = "dependency_unavailable" }, exit.body)
      assert.matches("timeout", fake.warns[1])
    end)

    it("responde 502 si la dependencia contesta fuera de contrato", function()
      fails_with("playintegrity_http_503", "upstream_error")
      run_google()

      local exit = fake.last_exit()
      assert.equals(502, exit.status)
      assert.same({ error = "bad_gateway", reason = "dependency_error" }, exit.body)
    end)

    it("responde 500 si el defecto es de las credenciales propias", function()
      fails_with("service_account_unreadable", "gateway_fault")
      run_google()

      local exit = fake.last_exit()
      assert.equals(500, exit.status)
      assert.same({ error = "internal_error", reason = "gateway_fault" }, exit.body)
    end)

    it("responde 403 si Google rechaza el token del cliente", function()
      fails_with("playintegrity_token_rejected", "rejected")
      run_google()

      local exit = fake.last_exit()
      assert.equals(403, exit.status)
      assert.same(PUBLIC_REJECTION, exit.body)
    end)

    it("no quema el token cuando la dependencia falla: el usuario puede reintentar", function()
      fails_with("playintegrity_unreachable: timeout", "unavailable")
      run_google()
      assert.is_nil(next(fake.dict.store))

      -- Reintento con el mismo token, ahora con Google respondiendo.
      local dict = fake.dict
      fake.restore()
      google_source.fetch = function()
        return play.verdict(NOW, { requestDetails = { requestHash = request_hash.compute(BODY, "hex") } })
      end
      run_google({ dict = dict })

      assert.equals(0, #fake.exits)
    end)

    it("pasa el token y la configuración a la fuente configurada", function()
      local received
      google_source.fetch = function(token, config)
        received = { token = token, source = config.source }
        return play.verdict(NOW, { requestDetails = { requestHash = request_hash.compute(BODY, "hex") } })
      end
      run_google()

      assert.same({ token = "token-opaco-de-play-integrity", source = "google" }, received)
      assert.equals(0, #fake.exits)
    end)
  end)
end)
