local pkey = require "resty.openssl.pkey"
local key = assert(pkey.new({ type = "RSA", bits = 2048 }))
local f = assert(io.open("/tmp/priv.pem", "w")); f:write(assert(key:to_PEM("private"))); f:close()
local pub = assert(key:to_PEM("public"))
io.write((pub:gsub("\n", "\n")))
