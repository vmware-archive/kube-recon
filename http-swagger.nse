local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"
local table = require "table"

description = [[
Checks for swagger documentations entries in <code>/robots.txt</code> on a web server.

The higher the verbosity or debug level, the more disallowed entries are shown.
]]

---
--@output
-- 80/tcp  open   http    syn-ack
-- |  Path /swagger.json exist



author = "Yevgeny Pats"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http
local last_len = 0

-- parse all disallowed entries in body and add them to a strbuf
action = function(host, port)
  local dis_count, noun
  local paths = {"/swagger.json",
  		 "/swagger",
		 "/v1/swagger.json",
		 "/v1/swagger"}
  for i,v in ipairs(paths) do
    local answer = http.get(host, port, v)
    if answer.status == 200 then
      return "\n Path " .. v .. " exist"
    end
  end

  return nil
end
