module(..., package.seeall)

local app = require("core.app")
local buffer = require("core.buffer")
local packet = require("core.packet")
local link = require("core.link")
local ipv4 = require("lib.protocol.ipv4")
local filter = require("lib.pcap.filter")

local ethernet = require("lib.protocol.ethernet")
local datagram = require("lib.protocol.datagram")

local ffi = require("ffi")
local C = ffi.C

local ipv4_header_struct_ctype = ffi.typeof[[
struct {
   // ethernet
   char dmac[6];
   char smac[6];
   uint16_t ethertype;
   // ipv6
   uint32_t crap1; // version, ihl, dscp, ecn, total length
   uint32_t crap2; // id, flags, fragment offset
   uint32_t crap3; // ttl, protocol, header_checksum
   char src_ip[4];
   char dst_ip[4];
} __attribute__((packed))
]]

local ipv6_header_struct_ctype = ffi.typeof[[
struct {
   // ethernet
   char dmac[6];
   char smac[6];
   uint16_t ethertype;
   // ipv6
   uint32_t flow_id; // version, tc, flow_id
   int16_t payload_length;
   int8_t  next_header;
   uint8_t hop_limit;
   char src_ip[16];
   char dst_ip[16];
} __attribute__((packed))
]]

local paddress_ctype = ffi.typeof("uint64_t*")
local IPV6_SRC_IP_OFFSET = ffi.offsetof(ipv6_header_struct_ctype, 'src_ip')
local IPV4_SRC_IP_OFFSET = ffi.offsetof(ipv4_header_struct_ctype, 'src_ip')

local AF_INET = 2

DDoS = {}

-- I don't know what I'm doing
function DDoS:new (arg)
   print("-- DDoS Init --")
   local conf = arg and config.parse_app_arg(arg) or {}
   assert(conf.rate)
   assert(conf.bucket_capacity)
   conf.initial_capacity = conf.initial_capacity or conf.bucket_capacity
   local o =
   {
      blocklist = {},
      rules = conf.rules,
      srcs = {},
      rate = conf.rate,
      bucket_capacity = conf.bucket_capacity,
      bucket_content = conf.initial_capacity,
      block_period = conf.block_period
   }


   self = setmetatable(o, {__index = DDoS})

   -- TODO: need a periodic task to do various tasks like garbage collection
   -- but this isn't intialized in the proper way as the periodic function
   -- doesn't receive the 'self' object
--   timer.activate(timer.new(
--      "periodic",
--      function ()
--         self.periodic()
--      end,
--      1e9, -- every second
--      'repeating'
--   ))
   return self
end 


function DDoS:periodic()
   print("DDoS Periodic!!" .. type(self))
end


function DDoS:push () 
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   -- TODO: should establish one rule-set per destination IP (ie the target IP we are mitigation for)
   -- TODO: need to write ethernet headers on egress to match the MAC address of our "default gateway"

   while not link.empty(i) and not link.full(o) do
      local p = link.receive(i)
      local iovec = p.iovecs[0]

      dgram = datagram:new(p)

      -- dig out src IP from packet
      -- TODO: do we really need to do ntop on this? is that an expensive operation?
      local src_ip = ipv4:ntop(iovec.buffer.pointer + iovec.offset + 26)
--      if self.blocklist[src_ip] ~= nil then
--         packet.deref(p)
--      end

      -- TODO: do BPF style filter match
      for rule_name, rule in pairs(self.rules) do
         print("Evaling rule: " .. rule_name .. " match: " .. rule.filter)
         -- TODO: should precompute these filters
         local filter, errmsg = filter:new(rule.filter)
         assert(filter, errmsg and ffi.string(errmsg))
         if filter:match(dgram:payload()) then
            print("match")
         else
            link.transmit(o, p)
         end

      end


      -- get our data struct on that source IP
      if self.srcs[src_ip] == nil then
         print("New source ip: " .. src_ip)
         self.srcs[src_ip] = {
            rate = self.rate,
            bucket_content = self.bucket_capacity,
            bucket_capacity = self.bucket_capacity,
            block_until = nil
            }
      end
      local src = self.srcs[src_ip]

      -- TODO: is this expensive to do for every packet?
      -- TODO: when we are in block mode, we should stop calculating the rate.
      -- Just before (a few seconds) a block is about to expire, we should
      -- start calculating the rate again so we can extend the block if the
      -- rate is still too high
      --
      -- figure out rates n shit
      do
         local cur_now = tonumber(app.now())
         local last_time = src.last_time or cur_now
         src.bucket_content = math.max(0,math.min(
               src.bucket_content + src.rate * (cur_now - last_time),
               src.bucket_capacity
            ))
         src.last_time = cur_now
      end

      -- TODO: this is for pps, do the same for bps
      src.bucket_content = src.bucket_content - 1
      if src.bucket_content <= 0 then
         if src.block_until == nil then
            print("packet rate from: " .. tostring(src_ip) .. " too high, blocking")
         else
            --print("packet rate from: " .. tostring(src_ip) .. " too high, extending blocking")
         end
         src.block_until = tonumber(app.now()) + 10
      end

      if src.block_until ~= nil and src.block_until < tonumber(app.now()) then
         print("got packet: "..tostring(src_ip).. " was in block, now ALLOW!")
         src.block_until = nil
      end

      if src.block_until ~= nil then
         --print("got packet: "..tostring(src_ip).. " tokens: " .. src.bucket_content .. " IN BLOCK")
         packet.deref(p)
      else
         --print("got packet: "..tostring(src_ip).. " tokens: " .. src.bucket_content .. " PASS")
         link.transmit(o, p)
      end
   end

end

function DDoS:report()
   print("-- DDoS report --")
   print("Configured rate: " .. self.rate .. " pps")
   print("Configured block period: " .. self.block_period .. " seconds")
   print("Traffic from:")
   for key,_ in pairs(self.srcs) do
      local src = self.srcs[key]
      if src.block_until == nil then
         print("  " .. key .. " allowed")
      else
         print("  " .. key .. " blocked for another " .. string.format("%0.1f", tostring(src.block_until - tonumber(app.now()))) .. " seconds")
      end
   end
end


