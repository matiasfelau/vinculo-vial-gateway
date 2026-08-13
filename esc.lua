local f = assert(io.open("/tmp/pub.pem")); local pem = f:read("*a"); f:close()
pem = pem:gsub("\r", ""):gsub("\n", "\n")
local o = assert(io.open("/tmp/pub.esc", "w")); o:write(pem); o:close()
