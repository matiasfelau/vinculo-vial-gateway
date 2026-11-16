-- Helper de tests: un `kong` (PDK) y un `ngx.shared` mínimos, en memoria.
--
-- Los handlers dependen de globales que sólo existen dentro de Kong (`kong.*`).
-- Esto reemplaza únicamente esa frontera —el PDK y el shared dict— con fakes
-- que registran lo que el handler hace; todo lo demás (criptografía, JWS,
-- política) corre real. `restore()` deja los globales como estaban.
local _M = {}

local function lower_keys(headers)
  local out = {}
  for name, value in pairs(headers or {}) do
    out[name:lower()] = value
  end
  return out
end

--- Shared dict en memoria con la semántica de `ngx.shared.DICT` que usa el
--- Gateway: `get`, `set` y `add` atómico (falla con "exists" si ya estaba).
-- @param opts.full boolean si es true, `add` falla con "no memory"
function _M.shared_dict(opts)
  local dict = { store = {}, ttls = {}, full = opts and opts.full or false }

  function dict:get(key)
    return self.store[key]
  end

  function dict:set(key, value, ttl)
    self.store[key] = value
    self.ttls[key] = ttl
    return true
  end

  function dict:add(key, value, ttl)
    if self.full then
      return nil, "no memory"
    end

    if self.store[key] ~= nil then
      return nil, "exists"
    end

    self.store[key] = value
    self.ttls[key] = ttl
    return true
  end

  return dict
end

--- Instala el fake y devuelve su registro.
-- @param opts.headers table headers de la request entrante
-- @param opts.body string|nil body crudo de la request
-- @param opts.body_err string|nil error que devuelve `get_raw_body` sin body
-- @param opts.dict table|false shared dict `vv_attestation` (por defecto uno
--        nuevo; `false` simula que no está declarado)
-- @param opts.now number reloj fijo para `ngx.now()` y `ngx.time()`
function _M.install(opts)
  opts = opts or {}

  local fake = {
    headers = lower_keys(opts.headers),
    body = opts.body,
    body_err = opts.body_err,
    exits = {},
    warns = {},
    errs = {},
    cleared = {},
    set_headers = {},
    body_reads = 0,
  }

  if opts.dict == nil then
    fake.dict = _M.shared_dict()
  elseif opts.dict then
    fake.dict = opts.dict
  end

  local saved = {
    kong = _G.kong,
    shared = ngx.shared,
    now = ngx.now,
    time = ngx.time,
  }

  local function joined(...)
    local parts = {}
    for i = 1, select("#", ...) do
      parts[i] = tostring((select(i, ...)))
    end
    return table.concat(parts)
  end

  _G.kong = {
    request = {
      get_header = function(name)
        return fake.headers[name:lower()]
      end,
      get_raw_body = function()
        fake.body_reads = fake.body_reads + 1
        if fake.body == nil then
          return nil, fake.body_err or "request body not buffered"
        end
        return fake.body
      end,
    },
    service = {
      request = {
        clear_header = function(name)
          fake.cleared[#fake.cleared + 1] = name
          fake.headers[name:lower()] = nil
        end,
        set_header = function(name, value)
          fake.set_headers[name] = value
          fake.headers[name:lower()] = value
        end,
      },
    },
    response = {
      -- El PDK real corta la request; el fake la registra y devuelve un
      -- centinela para que el handler que hace `return kong.response.exit()`
      -- termine igual que en Kong.
      exit = function(status, body, headers)
        fake.exits[#fake.exits + 1] = { status = status, body = body, headers = headers }
        return "exit"
      end,
    },
    log = {
      warn = function(...) fake.warns[#fake.warns + 1] = joined(...) end,
      err = function(...) fake.errs[#fake.errs + 1] = joined(...) end,
    },
    ctx = { shared = {} },
  }

  ngx.shared = fake.dict and { vv_attestation = fake.dict } or {}

  if opts.now then
    ngx.now = function() return opts.now end
    ngx.time = function() return math.floor(opts.now) end
  end

  --- Última respuesta con la que el handler cortó la request, o `nil`.
  function fake.last_exit()
    return fake.exits[#fake.exits]
  end

  function fake.restore()
    _G.kong = saved.kong
    ngx.shared = saved.shared
    ngx.now = saved.now
    ngx.time = saved.time
  end

  return fake
end

return _M
