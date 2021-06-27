local stdnse = require "stdnse"
local shortport = require "shortport"

description=[[
Detecte Minecraft Bedrock server
]]

---
-- @usage
-- sudo nmap -n -Pn -sU -p19132 -T5 --open --script MinecraftBedrock <target>
-- @output
-- PORT      STATE         SERVICE REASON
-- Nmap scan report for 85.xxx.xxx.xxx
-- Host is up.
-- PORT      STATE SERVICE
-- 19132/udp open  Minecraft
-- | minecraftBedrock:
-- |   result: VMCPE;ServerName;440;1.17.2;1;8;1192474xxxxx57;1.17;Survival;1;52659;65535;
-- |   Game: VMCPE
-- |   ServerName: ServerName
-- |   ProtocolVersion: 440
-- |   ServerVersion: 1.17.2
-- |   PlayerCount: 1
-- |   PlayerLimit: 8
-- |   ServerId: 119247494xxxx664157
-- |   WorldName: 1.17
-- |   GameMode: Survival
-- |   NintendoLimited: 1
-- |   Ipv4Port: 52659
-- |_  Ipv6Port: 65535
---

author = "0x25"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

MCT_UDP_PORT = 19132
TIME_OUT=1000
HEX_PAYLOAD = "01000000000000000000ffff00fefefefefdfdfdfd12345678"
INDEX = {'Game','ServerName','ProtocolVersion','ServerVersion','PlayerCount','PlayerLimit','ServerId','WorldName','GameMode','NintendoLimited','Ipv4Port','Ipv6Port'}

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function string.split(s, delimiter)
    result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match);
    end
    return result;
end


portrule = shortport.portnumber(MCT_UDP_PORT, "udp")

action = function(host, port)

  local socket, status, infos
  local str_payload = string.fromhex(HEX_PAYLOAD)
  local output_tab = stdnse.output_table()

  port.version.name = "Minecraft"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "closed")

  stdnse.debug(2,">> MinecraftBerock IP : %s Port: %s", host.ip,MCT_UDP_PORT)
  socket = nmap.new_socket("udp")

  socket:set_timeout(tonumber(TIME_OUT))
  status = socket:connect(host.ip, MCT_UDP_PORT, "udp")
  stdnse.debug(2,">> MinecraftBerock socket status : %s", status)

  if( status == true ) then
    status = socket:send(str_payload)
    if( status == true ) then
      status, data = socket:receive_bytes(900)
      stdnse.debug(2,">> MinecraftBerock socket status : %s", status)

      if( status ) then
        values = data:sub(35)
        output_tab.result = values
        nmap.set_port_state(host, port, "open")

      else
        output_tab.result = "Socket receive error"
        stdnse.debug(2,">> MinecraftBerock socket receive error : %s", status)
      end
    else
      output_tab.result = "Socket send error"
      stdnse.debug(2,">> MinecraftBerock socket send error : %s", status)
    end
  else
    output_tab.result = "Socket connection error"
    stdnse.debug(2,">> MinecraftBerock socket connection error : %s", status)
  end

  socket:close()
  
  local values_tab = string.split(values,';')

  for k, v in pairs(INDEX) do
    output_tab[v] = values_tab[k]
  end

  return output_tab

end
