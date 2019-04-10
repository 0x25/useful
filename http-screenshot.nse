description = [[ Screenshot of Web application (based on cutycapt) need -sV to detect service http/https - need apt install libqt5webkit5 on kali 19]]

author = ""
license = ""
categories = {"default", "discovery", "safe"}

local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local service_tunnel = port.version.service_tunnel -- need -sV
	local service = port.service
	local prefix = "http"
	
	local output = stdnse.output_table()

	if (service_tunnel ~= "ssl") then
		if(service == "https") then 
			prefix = "https"
		end
	else
		prefix = "https"
	end

	local target = host.targetname
	if host.targetname == nil then
		target = host.ip
	end

	local filename = "screenshot-nmap-"..target.."_"..port.number..".png" 
	local cmd = "cutycapt --insecure --max-wait=4000 --url=" .. prefix .. "://" .. target .. ":" .. port.number .. " --out=" .. filename .. " 2> /dev/null >/dev/null"

	stdnse.debug(1, "DEBUG CUTYCAPT >>> %s", cmd)
	
	output.prefix = prefix
	output.targetname = host.targetname
	output.port = port.number
	output.filename = filename
	output.cmd = cmd

  local ret = os.execute(cmd)

	local result = "failed (verify cutycapt is in your path) "..cmd

        if ret then
                result = "Saved to " .. filename
        end
	
	output.result = result	

	return output
end
