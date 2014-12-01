module(..., package.seeall)

local app = require("core.app")
local buffer = require("core.buffer")
local datagram = require("lib.protocol.datagram")
local ffi = require("ffi")
local filter = require("lib.pcap.filter")
local ipv4 = require("lib.protocol.ipv4")
local lib = require("core.lib")
local link = require("core.link")
local packet = require("core.packet")


PoC = {}

function PoC:new (arg)
   local conf = arg and config.parse_app_arg(arg) or {}
   local o = {
   }
   self = setmetatable(o, {__index = PoC})
   return self
end

function PoC:push()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")
   while not link.empty(i) and not link.full(o) do
      local p = link.receive(i)
	  link.transmit(o, p)
--	  return
   end
end
