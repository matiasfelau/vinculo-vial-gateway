-- Carga del service account y fallas propias del Gateway al pedir el access
-- token. Todo lo que falla acá es "defecto nuestro" (`gateway_fault`): ocurre
-- antes de salir a la red, así que no hace falta un cliente HTTP falso.
local cjson = require "cjson.safe"
local openssl_pkey = require "resty.openssl.pkey"

local MODULE = "kong.plugins.app-attestation.google_oauth"

local key = assert(openssl_pkey.new({ type = "RSA", bits = 2048 }))
local PRIVATE_KEY = assert(key:to_PEM("private"))

local ACCOUNT_JSON = cjson.encode({
  private_key_id = "abc123",
  private_key = PRIVATE_KEY,
  client_email = "gateway@vinculo-vial.iam.gserviceaccount.com",
  token_uri = "https://oauth2.test/token",
})

local function write_temp(contents)
  local path = os.tmpname()
  local file = assert(io.open(path, "w"))
  file:write(contents)
  file:close()
  return path
end

describe("service account de Google: carga y fallas propias", function()
  local google_oauth, saved_shared
  local temp_files

  before_each(function()
    -- Módulo limpio: el caché por path es estado del módulo.
    package.loaded[MODULE] = nil
    google_oauth = require(MODULE)
    saved_shared = ngx.shared
    ngx.shared = {}
    temp_files = {}
  end)

  after_each(function()
    ngx.shared = saved_shared
    package.loaded[MODULE] = nil
    for _, path in ipairs(temp_files) do
      os.remove(path)
    end
  end)

  local function temp(contents)
    local path = write_temp(contents)
    temp_files[#temp_files + 1] = path
    return path
  end

  describe("load_service_account", function()
    it("lee el service account del archivo montado", function()
      local account = google_oauth.load_service_account({ service_account_path = temp(ACCOUNT_JSON) })

      assert.equals("gateway@vinculo-vial.iam.gserviceaccount.com", account.client_email)
      assert.equals("https://oauth2.test/token", account.token_uri)
    end)

    it("lo lee del disco una sola vez por path", function()
      local path = temp(ACCOUNT_JSON)
      local first = google_oauth.load_service_account({ service_account_path = path })

      -- Si volviera a leer el archivo, ya no lo encontraría.
      os.remove(path)
      local second = google_oauth.load_service_account({ service_account_path = path })

      assert.is_not_nil(second)
      assert.equals(first, second)
    end)

    it("falla si el archivo no se puede abrir", function()
      local account, reason =
        google_oauth.load_service_account({ service_account_path = "/no/existe/sa.json" })

      assert.is_nil(account)
      assert.matches("^service_account_unreadable", reason)
    end)

    it("falla si el archivo no tiene un service account válido, sin cachearlo", function()
      local path = temp("esto no es json")
      local account, reason = google_oauth.load_service_account({ service_account_path = path })

      assert.is_nil(account)
      assert.equals("malformed_service_account_json", reason)

      -- Se arregla el archivo: la lectura siguiente tiene que verlo.
      local file = assert(io.open(path, "w"))
      file:write(ACCOUNT_JSON)
      file:close()
      assert.is_not_nil(google_oauth.load_service_account({ service_account_path = path }))
    end)

    it("usa el JSON inline si no hay path", function()
      local account = google_oauth.load_service_account({ service_account_json = ACCOUNT_JSON })
      assert.equals("abc123", account.private_key_id)
    end)

    it("prefiere el archivo al JSON inline", function()
      local other = cjson.encode({
        private_key = PRIVATE_KEY,
        client_email = "otra-cuenta@vinculo-vial.iam.gserviceaccount.com",
      })
      local account = google_oauth.load_service_account({
        service_account_path = temp(ACCOUNT_JSON),
        service_account_json = other,
      })

      assert.equals("gateway@vinculo-vial.iam.gserviceaccount.com", account.client_email)
    end)

    it("falla si no hay ninguna de las dos fuentes configuradas", function()
      local account, reason = google_oauth.load_service_account({})
      assert.is_nil(account)
      assert.equals("service_account_not_configured", reason)

      account, reason = google_oauth.load_service_account({
        service_account_path = "", service_account_json = "" })
      assert.is_nil(account)
      assert.equals("service_account_not_configured", reason)
    end)
  end)

  describe("get_access_token ante credenciales propias inválidas", function()
    it("clasifica la falta de service account como defecto del Gateway", function()
      local token, reason, kind = google_oauth.get_access_token({
        dependency_call_timeout_ms = 3000 })

      assert.is_nil(token)
      assert.equals("service_account_not_configured", reason)
      assert.equals("gateway_fault", kind)
    end)

    it("clasifica un archivo ilegible como defecto del Gateway", function()
      local token, reason, kind = google_oauth.get_access_token({
        service_account_path = "/no/existe/sa.json", dependency_call_timeout_ms = 3000 })

      assert.is_nil(token)
      assert.matches("service_account_unreadable", reason)
      assert.equals("gateway_fault", kind)
    end)

    it("clasifica una clave privada que no firma como defecto del Gateway", function()
      local broken = cjson.encode({
        client_email = "gateway@vinculo-vial.iam.gserviceaccount.com",
        private_key = "-----BEGIN PRIVATE KEY-----\nrota\n-----END PRIVATE KEY-----",
      })
      local token, reason, kind = google_oauth.get_access_token({
        service_account_json = broken, dependency_call_timeout_ms = 3000 })

      assert.is_nil(token)
      assert.matches("^invalid_private_key", reason)
      assert.equals("gateway_fault", kind)
    end)

    it("no deja la clave privada en el motivo que va al log", function()
      local _, reason = google_oauth.get_access_token({
        service_account_json = cjson.encode({
          client_email = "gateway@vinculo-vial.iam.gserviceaccount.com",
          private_key = "-----BEGIN PRIVATE KEY-----\nclave-secreta-rota\n-----END PRIVATE KEY-----",
        }),
        dependency_call_timeout_ms = 3000,
      })

      assert.is_nil(reason:find("clave-secreta-rota", 1, true))
    end)

    it("devuelve el access token cacheado sin tocar las credenciales", function()
      ngx.shared = { vv_attestation = {
        get = function() return "ya29.cacheado" end,
      } }

      -- Sin service account configurado: si intentara firmar, fallaría.
      assert.equals("ya29.cacheado", google_oauth.get_access_token({}))
    end)
  end)
end)
