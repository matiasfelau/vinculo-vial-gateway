local cjson = require "cjson.safe"
local openssl_pkey = require "resty.openssl.pkey"

local google_oauth = require "kong.plugins.app-attestation.google_oauth"
local base64url = require "vv.base64url"

-- Par de claves generado en el arranque de la suite: nada de material
-- criptográfico versionado en el repo.
local key = assert(openssl_pkey.new({ type = "RSA", bits = 2048 }))
local PRIVATE_KEY = assert(key:to_PEM("private"))

local function service_account_json(overrides)
  local account = {
    type = "service_account",
    project_id = "vinculo-vial",
    private_key_id = "abc123",
    private_key = PRIVATE_KEY,
    client_email = "gateway@vinculo-vial.iam.gserviceaccount.com",
    token_uri = "https://oauth2.googleapis.com/token",
  }

  for k, v in pairs(overrides or {}) do
    account[k] = v ~= false and v or nil
  end

  return cjson.encode(account)
end

describe("service account de Google", function()
  describe("lectura del JSON", function()
    it("extrae lo necesario para firmar", function()
      local account = google_oauth.parse_service_account(service_account_json())

      assert.equals("gateway@vinculo-vial.iam.gserviceaccount.com", account.client_email)
      assert.equals("https://oauth2.googleapis.com/token", account.token_uri)
      assert.equals("abc123", account.private_key_id)
    end)

    it("usa el endpoint por defecto si el JSON no trae token_uri", function()
      local account = google_oauth.parse_service_account(service_account_json({ token_uri = false }))
      assert.equals("https://oauth2.googleapis.com/token", account.token_uri)
    end)

    it("rechaza un JSON vacío", function()
      local account, reason = google_oauth.parse_service_account("")
      assert.is_nil(account)
      assert.equals("empty_service_account", reason)
    end)

    it("rechaza algo que no es JSON", function()
      local account, reason = google_oauth.parse_service_account("no soy json")
      assert.is_nil(account)
      assert.equals("malformed_service_account_json", reason)
    end)

    it("rechaza un service account sin client_email", function()
      local account, reason =
        google_oauth.parse_service_account(service_account_json({ client_email = false }))
      assert.is_nil(account)
      assert.equals("service_account_missing_client_email", reason)
    end)

    it("rechaza un service account sin clave privada", function()
      local account, reason =
        google_oauth.parse_service_account(service_account_json({ private_key = false }))
      assert.is_nil(account)
      assert.equals("service_account_missing_private_key", reason)
    end)
  end)

  describe("aserción JWT", function()
    local NOW = 1735689600

    it("arma una aserción que Google podría verificar", function()
      local account = google_oauth.parse_service_account(service_account_json())
      local assertion = assert(google_oauth.build_assertion(account, NOW))

      local header_b64, claims_b64, signature_b64 =
        assertion:match("^([%w_%-]+)%.([%w_%-]+)%.([%w_%-]+)$")
      assert.is_not_nil(header_b64)

      local header = cjson.decode(base64url.decode(header_b64))
      assert.equals("RS256", header.alg)
      assert.equals("abc123", header.kid)

      local claims = cjson.decode(base64url.decode(claims_b64))
      assert.equals("gateway@vinculo-vial.iam.gserviceaccount.com", claims.iss)
      assert.equals("https://www.googleapis.com/auth/playintegrity", claims.scope)
      assert.equals("https://oauth2.googleapis.com/token", claims.aud)
      assert.equals(NOW, claims.iat)
      assert.equals(NOW + 3600, claims.exp)

      -- La firma tiene que verificar de verdad contra la clave pública.
      local digest = assert(require("resty.openssl.digest").new("sha256"))
      assert(digest:update(header_b64 .. "." .. claims_b64))
      assert.is_true(key:verify(base64url.decode(signature_b64), digest))
    end)

    it("falla con una clave privada inválida en vez de firmar cualquier cosa", function()
      local assertion, reason = google_oauth.build_assertion({
        client_email = "x@y.iam.gserviceaccount.com",
        token_uri = "https://oauth2.googleapis.com/token",
        private_key = "-----BEGIN PRIVATE KEY-----\nrota\n-----END PRIVATE KEY-----",
      }, NOW)

      assert.is_nil(assertion)
      assert.matches("invalid_private_key", reason)
    end)
  end)

  describe("respuesta del endpoint de token", function()
    it("extrae el access token y su vigencia", function()
      local token, expires_in = google_oauth.parse_token_response(
        200, '{"access_token":"ya29.token","expires_in":3599,"token_type":"Bearer"}')

      assert.equals("ya29.token", token)
      assert.equals(3599, expires_in)
    end)

    it("reporta el status sin filtrar el cuerpo del error", function()
      -- El error de Google puede describir el service account: al log va el
      -- status, no el detalle.
      local token, reason = google_oauth.parse_token_response(
        400, '{"error":"invalid_grant","error_description":"Invalid JWT Signature"}')

      assert.is_nil(token)
      assert.equals("oauth_http_400", reason)
    end)

    it("rechaza un 200 sin access token", function()
      local token, reason = google_oauth.parse_token_response(200, '{"token_type":"Bearer"}')
      assert.is_nil(token)
      assert.equals("oauth_missing_access_token", reason)
    end)

    it("rechaza un 200 que no es JSON", function()
      local token, reason = google_oauth.parse_token_response(200, "<html>")
      assert.is_nil(token)
      assert.equals("oauth_malformed_response", reason)
    end)
  end)
end)
