local handler = require "kong.plugins.token-offloading.handler"
local token_helper = require "spec.helpers.token"
local fake_kong = require "spec.helpers.fake_kong"
local base64url = require "vv.base64url"

-- Prioridad nativa de `rate-limiting` en Kong 3.7 (fija, no configurable
-- desde kong.yml). US-05 usa `limit_by: header` sobre el mismo header que
-- este plugin escribe: si algún día `PRIORITY` bajara por debajo de este
-- valor, ese rate limiting por usuario dejaría de encontrar el header y
-- degradaría en silencio a otro criterio de límite.
local RATE_LIMITING_NATIVE_PRIORITY = 910

-- El plugin nativo `jwt` ya verificó la firma antes de que corra este plugin:
-- este sólo necesita un JWT bien formado del que extraer la identidad.


local USER_HASH = "8f14e45fceea167a5a36dedd4bea2543"

local function token(claims, header_overrides)
  return token_helper.compact(claims, header_overrides)
end

describe("token-offloading", function()
  describe("orden de ejecución", function()
    it("corre antes que `rate-limiting`, para que limit_by: header lo encuentre", function()
      assert.is_true(handler.PRIORITY > RATE_LIMITING_NATIVE_PRIORITY)
    end)
  end)

  describe("extracción del claim de identidad", function()
    it("devuelve el `sub` del token validado", function()
      local value = handler.extract_claim(token({ sub = USER_HASH, exp = 1735689600 }), "sub")
      assert.equals(USER_HASH, value)
    end)

    it("permite configurar otro claim", function()
      local value = handler.extract_claim(token({ user_id = USER_HASH }), "user_id")
      assert.equals(USER_HASH, value)
    end)

    it("normaliza un claim numérico a string", function()
      local value = handler.extract_claim(token({ sub = 42 }), "sub")
      assert.equals("42", value)
    end)
  end)

  describe("tokens que no permiten derivar identidad", function()
    it("falla si el plugin `jwt` no dejó un token en el contexto", function()
      local value, reason = handler.extract_claim(nil, "sub")
      assert.is_nil(value)
      assert.equals("missing_token", reason)
    end)

    it("falla ante un token que no es un JWT compacto", function()
      local value, reason = handler.extract_claim("no-es-un-jwt", "sub")
      assert.is_nil(value)
      assert.equals("malformed_token", reason)
    end)

    it("falla si el token no trae el claim configurado", function()
      local value, reason = handler.extract_claim(token({ exp = 1735689600 }), "sub")
      assert.is_nil(value)
      assert.equals("missing_claim", reason)
    end)

    it("falla si el claim está vacío", function()
      local value, reason = handler.extract_claim(token({ sub = "" }), "sub")
      assert.is_nil(value)
      assert.equals("invalid_claim", reason)
    end)

    it("falla si el claim no es un escalar", function()
      local value, reason = handler.extract_claim(token({ sub = { "a", "b" } }), "sub")
      assert.is_nil(value)
      assert.equals("invalid_claim", reason)
    end)

    it("falla si el claim excede el largo máximo", function()
      local value, reason = handler.extract_claim(token({ sub = string.rep("a", 257) }), "sub")
      assert.is_nil(value)
      assert.equals("invalid_claim", reason)
    end)

    it("rechaza un claim con CR/LF, que permitiría inyectar headers al upstream", function()
      local value, reason =
        handler.extract_claim(token({ sub = "abc\r\nX-Admin: true" }), "sub")
      assert.is_nil(value)
      assert.equals("invalid_claim", reason)
    end)
  end)

  describe("payloads que no se pueden decodificar", function()
    local function with_payload(payload_b64)
      return "eyJhbGciOiJSUzI1NiJ9." .. payload_b64 .. ".c2ln"
    end

    it("falla si el payload trae caracteres fuera de base64url", function()
      local value, reason = handler.extract_claim(with_payload("!!!!"), "sub")
      -- `!` no entra en el patrón de un JWT compacto: es un token malformado.
      assert.is_nil(value)
      assert.equals("malformed_token", reason)
    end)

    it("falla si el largo del payload no es decodificable", function()
      -- Un segmento base64url nunca tiene largo 1 módulo 4.
      local value, reason = handler.extract_claim(with_payload("abcde"), "sub")
      assert.is_nil(value)
      assert.equals("malformed_payload", reason)
    end)

    it("falla si el payload decodifica a algo que no es JSON", function()
      local value, reason =
        handler.extract_claim(with_payload(base64url.encode("esto no es json")), "sub")
      assert.is_nil(value)
      assert.equals("malformed_payload", reason)
    end)

    it("falla si el payload es JSON pero no un objeto", function()
      local value, reason =
        handler.extract_claim(with_payload(base64url.encode("[1,2,3]")), "sub")
      assert.is_nil(value)
      assert.equals("missing_claim", reason)

      value, reason = handler.extract_claim(with_payload(base64url.encode('"texto"')), "sub")
      assert.is_nil(value)
      assert.equals("malformed_payload", reason)
    end)

    it("falla si el claim es null", function()
      local value, reason = handler.extract_claim(token({ sub = ngx.null }), "sub")
      assert.is_nil(value)
      assert.equals("invalid_claim", reason)
    end)

    it("falla si no hay un token (cadena vacía)", function()
      local value, reason = handler.extract_claim("", "sub")
      assert.is_nil(value)
      assert.equals("missing_token", reason)
    end)
  end)

  describe("access", function()
    local fake
    local CONF = { claim = "sub", header_name = "X-User-Hash", remove_authorization = true }

    local function run(opts, conf)
      fake = fake_kong.install(opts)
      return handler:access(conf or CONF)
    end

    after_each(function()
      if fake then
        fake.restore()
        fake = nil
      end
    end)

    it("escribe la identidad en el header y quita el Authorization", function()
      local jwt = token({ sub = USER_HASH })
      fake = fake_kong.install({ headers = { Authorization = "Bearer " .. jwt } })
      -- El token lo deja el plugin `jwt` en el contexto compartido.
      kong.ctx.shared.authenticated_jwt_token = jwt
      handler:access(CONF)

      assert.equals(0, #fake.exits)
      assert.equals(USER_HASH, fake.set_headers["X-User-Hash"])
      assert.is_nil(kong.request.get_header("Authorization"))
    end)

    it("conserva el Authorization si `remove_authorization` está apagado", function()
      local jwt = token({ sub = USER_HASH })
      fake = fake_kong.install({ headers = { Authorization = "Bearer " .. jwt } })
      kong.ctx.shared.authenticated_jwt_token = jwt
      handler:access({ claim = "sub", header_name = "X-User-Hash", remove_authorization = false })

      assert.equals(USER_HASH, fake.set_headers["X-User-Hash"])
      assert.equals("Bearer " .. jwt, kong.request.get_header("Authorization"))
    end)

    it("usa `ngx.ctx` si el plugin `jwt` es de una versión que no usa `kong.ctx.shared`", function()
      fake = fake_kong.install()
      ngx.ctx.authenticated_jwt_token = token({ sub = USER_HASH })
      handler:access(CONF)
      ngx.ctx.authenticated_jwt_token = nil

      assert.equals(USER_HASH, fake.set_headers["X-User-Hash"])
    end)

    it("descarta el header de identidad que mande el cliente (anti-spoofing)", function()
      local jwt = token({ sub = USER_HASH })
      fake = fake_kong.install({ headers = { ["X-User-Hash"] = "otro-usuario" } })
      kong.ctx.shared.authenticated_jwt_token = jwt
      handler:access(CONF)

      assert.equals("X-User-Hash", fake.cleared[1])
      assert.equals(USER_HASH, kong.request.get_header("X-User-Hash"))
    end)

    it("respeta el claim y el header configurados", function()
      fake = fake_kong.install()
      kong.ctx.shared.authenticated_jwt_token = token({ user_id = "u-77" })
      handler:access({ claim = "user_id", header_name = "X-User-Id", remove_authorization = true })

      assert.equals("u-77", fake.set_headers["X-User-Id"])
    end)

    it("corta con 401 si no hay token, y sin dejar pasar el header spoofeado", function()
      run({ headers = { ["X-User-Hash"] = "otro-usuario" } })

      local exit = fake.last_exit()
      assert.equals(401, exit.status)
      assert.same({ error = "unauthorized", reason = "invalid_token" }, exit.body)
      assert.is_nil(kong.request.get_header("X-User-Hash"))
      assert.same({}, fake.set_headers)
    end)

    it("corta con 401 si el claim no sirve, y el motivo real queda sólo en el log", function()
      fake = fake_kong.install()
      kong.ctx.shared.authenticated_jwt_token = token({ sub = "abc\r\nX-Admin: true" })
      handler:access(CONF)

      local exit = fake.last_exit()
      assert.equals(401, exit.status)
      assert.same({ error = "unauthorized", reason = "invalid_token" }, exit.body)
      assert.matches("invalid_claim", fake.warns[1])
      assert.same({}, fake.set_headers)
    end)
  end)
end)
