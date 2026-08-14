local base64url = require "vv.base64url"

describe("base64url", function()
  it("codifica sin padding y con el alfabeto url-safe", function()
    -- Estos bytes producen `+` y `/` en base64 clásico.
    local raw = string.char(0xFF, 0xEF, 0xBE)
    assert.equals("/+++", ngx.encode_base64(raw))
    assert.equals("_---", base64url.encode(raw))
  end)

  it("es reversible para cualquier longitud", function()
    for length = 0, 32 do
      local raw = string.rep("x", length)
      assert.equals(raw, base64url.decode(base64url.encode(raw)) or "")
    end
  end)

  it("decodifica los tres largos de padding", function()
    assert.equals("a", base64url.decode("YQ"))
    assert.equals("ab", base64url.decode("YWI"))
    assert.equals("abc", base64url.decode("YWJj"))
  end)

  it("rechaza base64 clásico, para que un mismo valor no tenga dos formas", function()
    -- Aceptar ambos alfabetos permitiría presentar la misma firma con dos
    -- representaciones distintas.
    assert.is_nil(base64url.decode("_+++"))
    assert.is_nil(base64url.decode("YWJj="))
  end)

  it("rechaza un largo imposible", function()
    -- Un resto de 1 sobre 4 no corresponde a ninguna cantidad de bytes.
    assert.is_nil(base64url.decode("YWJjZ"))
  end)

  it("rechaza entradas que no son strings", function()
    assert.is_nil(base64url.decode(nil))
    assert.is_nil(base64url.decode(42))
    assert.is_nil(base64url.encode(nil))
  end)
end)
