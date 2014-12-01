module(..., package.seeall)

local link = require("core.link")

PoC = {}

function PoC:new (arg)
   return setmetatable({}, {__index = PoC})
end

function PoC:push()
   while not link.empty(self.input.input) and not link.full(self.output.output) do
	  link.transmit(self.output.output, link.receive(self.input.input))
	  return
   end
end
