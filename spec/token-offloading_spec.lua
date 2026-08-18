local handler = require "kong.plugins.token-offloading.handler"
local token_helper = require "spec.helpers.token"

-- El plugin nativo `jwt` ya verificó la firma antes de que corra este plugin:
-- este sólo necesita un JWT bien formado del que extraer la identidad.


local USER_HASH = "8f14e45fceea167a5a36dedd4bea2543"

local function token(claims, header_overrides)
  return token_helper.compact(claims, header_overrides)
end

describe("token-offloading", function()
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
end)
