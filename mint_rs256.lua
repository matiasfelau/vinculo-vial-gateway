local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"
local digest = require "resty.openssl.digest"
local function b64(s) local e = ngx.encode_base64(s); return (e:gsub("%+","-"):gsub("/","_"):gsub("=","")) end
local f = assert(io.open("/tmp/priv.pem")); local pem = f:read("*a"); f:close()
local key = assert(pkey.new(pem))
local now = math.floor(ngx.now())
local claims = { iss = "vinculo-vial-identity", sub = "8f14e45fceea167a5a36dedd4bea2543", exp = now + 300, iat = now }
local si = b64(cjson.encode({ alg = "RS256", typ = "JWT" })) .. "." .. b64(cjson.encode(claims))
local d = assert(digest.new("sha256")); assert(d:update(si))
io.write(si .. "." .. b64(assert(key:sign(d))))
