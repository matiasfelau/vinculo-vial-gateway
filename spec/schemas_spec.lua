-- Valida los schemas de los plugins con la clase `Schema` de Kong, la misma que
-- usa `kong config parse` al arrancar: una configuración que acá no pasa, en
-- producción impide levantar el Gateway.
local Schema = require "kong.db.schema"

local attestation_def = require "kong.plugins.app-attestation.schema"
local offloading_def = require "kong.plugins.token-offloading.schema"

local PSK = string.rep("p", 16)

-- Aplica los defaults como lo hace Kong al cargar el `kong.yml` y valida.
local function validate(schema, config)
  local entity = schema:process_auto_fields({ config = config }, "insert")
  local ok, err = schema:validate(entity)
  return ok, err, entity.config
end

describe("schema de app-attestation", function()
  local schema = assert(Schema.new(attestation_def))

  local function google(overrides)
    local config = { source = "google", package_name = "ar.test.app",
                     service_account_path = "/run/secrets/sa.json" }
    for key, value in pairs(overrides or {}) do
      config[key] = value
    end
    return config
  end

  local function mock(overrides)
    local config = { source = "mock", package_name = "ar.test.app", psk = PSK }
    for key, value in pairs(overrides or {}) do
      config[key] = value
    end
    return config
  end

  describe("defaults seguros", function()
    local ok, _, config = validate(schema, google())

    it("acepta una configuración mínima de producción", function()
      assert.is_true(ok)
    end)

    it("verifica TLS, ligadura con el body y anti-replay por defecto", function()
      assert.is_true(config.ssl_verify)
      assert.is_true(config.require_request_hash)
      assert.is_true(config.replay_guard)
      assert.equals("hex", config.request_hash_encoding)
    end)

    it("acepta sólo dispositivos certificados, sin rooteados ni emuladores", function()
      assert.same({ "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY" },
                  config.accepted_device_verdicts)
      assert.same({ "PLAY_RECOGNIZED" }, config.accepted_app_verdicts)
    end)

    it("usa ventanas de tiempo acotadas y no propaga el token", function()
      assert.equals(120, config.max_age_seconds)
      assert.equals(30, config.clock_skew_seconds)
      assert.is_true(config.strip_header)
      assert.equals("X-App-Attestation", config.header_name)
    end)

    it("no exige licencia ni huella de certificado salvo que se configuren", function()
      assert.same({}, config.accepted_licensing_verdicts)
      assert.same({}, config.expected_certificate_digests)
    end)
  end)

  describe("credenciales de cada fuente", function()
    it("google exige service_account_path o service_account_json", function()
      local ok, err = validate(schema, { source = "google", package_name = "ar.test.app" })

      assert.is_nil(ok)
      assert.matches("service_account_path", err.config["@entity"][1])
    end)

    it("google acepta el JSON inline en lugar del archivo", function()
      local ok = validate(schema, { source = "google", package_name = "ar.test.app",
                                    service_account_json = "{}" })
      assert.is_true(ok)
    end)

    it("google trata un path vacío como ausente", function()
      local ok = validate(schema, google({ service_account_path = "" }))
      assert.is_nil(ok)
    end)

    it("mock exige la PSK", function()
      local ok, err = validate(schema, { source = "mock", package_name = "ar.test.app" })

      assert.is_nil(ok)
      assert.equals("required field missing", err.config.psk)
    end)

    it("mock rechaza una PSK corta", function()
      local ok, err = validate(schema, mock({ psk = "corta" }))

      assert.is_nil(ok)
      assert.is_not_nil(err.config.psk)
    end)

    it("mock acepta una PSK de largo suficiente", function()
      assert.is_true((validate(schema, mock())))
    end)

    it("exige el package name de la app", function()
      local ok, err = validate(schema, { source = "mock", psk = PSK })

      assert.is_nil(ok)
      assert.equals("required field missing", err.config.package_name)
    end)

    it("no admite una fuente desconocida", function()
      local ok, err = validate(schema, mock({ source = "otra" }))

      assert.is_nil(ok)
      assert.is_not_nil(err.config.source)
    end)
  end)

  describe("política", function()
    it("rechaza veredictos de dispositivo que Google no emite", function()
      local ok, err = validate(schema, google({ accepted_device_verdicts = { "MEETS_EVERYTHING" } }))

      assert.is_nil(ok)
      assert.is_not_nil(err.config.accepted_device_verdicts)
    end)

    it("rechaza veredictos de app o de licencia que Google no emite", function()
      local ok_app = validate(schema, google({ accepted_app_verdicts = { "TRUSTED" } }))
      local ok_lic = validate(schema, google({ accepted_licensing_verdicts = { "PIRATED" } }))

      assert.is_nil(ok_app)
      assert.is_nil(ok_lic)
    end)

    it("permite relajar la política explícitamente", function()
      local ok = validate(schema, google({
        accepted_device_verdicts = { "MEETS_BASIC_INTEGRITY" },
        accepted_licensing_verdicts = { "LICENSED" },
        expected_certificate_digests = { "6a6a1474b5cbbb2b1aa57e0bc3" },
      }))
      assert.is_true(ok)
    end)

    it("acepta sólo los encodings de hash que el Gateway sabe calcular", function()
      for _, encoding in ipairs({ "hex", "base64", "base64url" }) do
        assert.is_true((validate(schema, mock({ request_hash_encoding = encoding }))))
      end

      assert.is_nil((validate(schema, mock({ request_hash_encoding = "md5" }))))
    end)
  end)

  describe("rangos numéricos", function()
    local function rejects(field, value)
      local ok, err = validate(schema, mock({ [field] = value }))
      assert.is_nil(ok)
      assert.is_not_nil(err.config[field])
    end

    it("acota la vida máxima de la atestación (1 a 3600 s)", function()
      rejects("max_age_seconds", 0)
      rejects("max_age_seconds", 3601)
      assert.is_true((validate(schema, mock({ max_age_seconds = 3600 }))))
    end)

    it("acota la tolerancia de reloj (0 a 300 s)", function()
      rejects("clock_skew_seconds", -1)
      rejects("clock_skew_seconds", 301)
      assert.is_true((validate(schema, mock({ clock_skew_seconds = 0 }))))
    end)

    it("acota los timeouts hacia Google (100 a 30000 ms)", function()
      rejects("dependency_timeout_ms", 99)
      rejects("dependency_call_timeout_ms", 30001)
    end)

    it("acota el tamaño máximo del token (256 a 65536 bytes)", function()
      rejects("max_token_bytes", 255)
      rejects("max_token_bytes", 65537)
    end)
  end)
end)

describe("schema de token-offloading", function()
  local schema = assert(Schema.new(offloading_def))

  it("deriva la identidad del `sub` hacia X-User-Hash y quita el Authorization", function()
    local ok, _, config = validate(schema, {})

    assert.is_true(ok)
    assert.equals("sub", config.claim)
    assert.equals("X-User-Hash", config.header_name)
    assert.is_true(config.remove_authorization)
  end)

  it("permite configurar otro claim y otro header", function()
    local ok, _, config = validate(schema, { claim = "user_id", header_name = "X-User-Id",
                                             remove_authorization = false })

    assert.is_true(ok)
    assert.equals("user_id", config.claim)
    assert.equals("X-User-Id", config.header_name)
    assert.is_false(config.remove_authorization)
  end)

  it("rechaza tipos incorrectos", function()
    local ok, err = validate(schema, { remove_authorization = "si" })

    assert.is_nil(ok)
    assert.is_not_nil(err.config.remove_authorization)
  end)
end)
