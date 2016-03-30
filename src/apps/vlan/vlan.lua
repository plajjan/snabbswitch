module(..., package.seeall)

local packet = require("core.packet")
local bit = require("bit")
local ffi = require("ffi")

local C = ffi.C
local receive, transmit = link.receive, link.transmit
local cast = ffi.cast

Tagger = {}
Untagger = {}

-- 802.1q
local dotq_tpid = 0x8100
local o_ethernet_ethertype = 12
local uint32_ptr_t = ffi.typeof('uint32_t*')

local function make_vlan_tag(tag)
   return ffi.C.htonl(bit.bor(bit.lshift(dotq_tpid, 16), tag))
end

function Tagger:new(conf)
   local o = setmetatable({}, {__index=Tagger})
   o.tag = make_vlan_tag(assert(conf.tag))
   return o
end

function Tagger:push ()
   local input, output = self.input.input, self.output.output
   local tag = self.tag
   for _=1,link.nreadable(input) do
      local pkt = receive(input)
      local payload = pkt.data + o_ethernet_ethertype
      local length = pkt.length
      pkt.length = length + 4
      C.memmove(payload + 4, payload, length - o_ethernet_ethertype)
      cast(uint32_ptr_t, payload)[0] = tag
      transmit(output, pkt)
   end
end

function Untagger:new(conf)
   local o = setmetatable({}, {__index=Untagger})
   o.tag = make_vlan_tag(assert(conf.tag))
   return o
end

function Untagger:push ()
   local input, output = self.input.input, self.output.output
   local tag = self.tag
   for _=1,link.nreadable(input) do
      local pkt = receive(input)
      local payload = pkt.data + o_ethernet_ethertype
      if cast(uint32_ptr_t, payload)[0] ~= tag then
         -- Incorrect VLAN tag; drop.
         packet.free(pkt)
      else
         local length = pkt.length
         pkt.length = length - 4
         C.memmove(payload, payload + 4, length - o_ethernet_ethertype - 4)
         transmit(output, pkt)
      end
   end
end

function selftest()
   local basic_apps  = require("apps.basic.basic_apps")
   local engine      = require("core.app")
   local pcap        = require("apps.pcap.pcap")

   -- performance test
   -- baseline
   local c1 = config.new()
   config.app(c1, "source1", basic_apps.Source)
   config.app(c1, "sink1", basic_apps.Sink)
   config.link(c1, "source1.output -> sink1.input")
   engine.configure(c1)

   engine.main({duration=1, no_report=true})
   local pps_baseline = link.stats(engine.app_table.sink1.input.input).txpackets
   print("Effective rate - baseline: " .. string.format("%0.1f", tostring(pps_baseline)) .. " Mpps")

   -- tagger
   local c2 = config.new()
   config.app(c2, "source2", basic_apps.Source)
   config.app(c2, "tagger2", Tagger, { tag = 1234})
   config.app(c2, "sink2", basic_apps.Sink)
   config.link(c2, "source2.output -> tagger2.input")
   config.link(c2, "tagger2.output -> sink2.input")
   engine.configure(c2)

   engine.main({duration=1, no_report=true})
   local pps_tagger = link.stats(engine.app_table.sink2.input.input).txpackets
   print("Effective rate - Tagger  : " .. string.format("%0.1f", tostring(pps_tagger)) .. " Mpps")

   -- tagger + untagger
   local c3 = config.new()
   config.app(c3, "source3", basic_apps.Source)
   config.app(c3, "tagger3", Tagger, { tag = 1334})
   config.app(c3, "untagger3", Untagger, { tag = 1334})
   config.app(c3, "sink3", basic_apps.Sink)
   config.link(c3, "source3.output -> tagger3.input")
   config.link(c3, "tagger3.output -> untagger3.input")
   config.link(c3, "untagger3.output -> sink3.input")
   engine.configure(c3)

   engine.main({duration=1, no_report=true})
   local pps_tagger_untagger = link.stats(engine.app_table.sink3.input.input).txpackets
   print("Effective rate - Untagger: " .. string.format("%0.1f", tostring(pps_tagger_untagger)) .. " Mpps")
end
