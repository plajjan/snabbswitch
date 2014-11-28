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
   assert(conf.block_period >= 5, "block_period must be at least 5 seconds")
   local o =
   {
      blocklist = {},
      rules = conf.rules,
      block_period = conf.block_period
   }

   self = setmetatable(o, {__index = DDoS})

   -- pre-process rules
   for rule_name, rule in pairs(self.rules) do
      rule.srcs = {}
      -- compile the filter
      local filter, errmsg = filter:new(rule.filter)
      assert(filter, errmsg and ffi.string(errmsg))
      rule.cfilter = filter
   end

   -- schedule periodic task every second
   timer.activate(timer.new(
      "periodic",
      function () self:periodic() end,
      1e10, -- every 10 seconds
      'repeating'
   ))
   return self
end 


function DDoS:periodic()
--   print("DDoS Periodic!!")
   -- TODO: remove items from the blocklist
   -- TODO: just do one call to app.now() - if it's an expensive call
--   local cur_now = tonumber(app.now())
   for src_ip, blocklist in pairs(self.blocklist) do
      print("Checking block for: " .. src_ip)
      if blocklist.block_until < tonumber(app.now()) then
         self.blocklist[src_ip] = nil
      end
   end
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
      if src_ip == "90.130.74.151" then
         packet.deref(p)
         return
      end

      -- short cut for stuff in blocklist that is in state block
      if self.blocklist[src_ip] ~= nil and self.blocklist[src_ip].action == "block" then
--         print(src_ip .. " in blocklist")
         packet.deref(p)
         return
      end

      local rule_match = nil
      for rule_name, rule in pairs(self.rules) do
         if rule.cfilter:match(dgram:payload()) then
            --print(src_ip .. " Matched rule: " .. rule_name .. " [ " .. rule.filter .. " ]")
            rule_match = rule_name
         end
      end

      -- didn't match any rule, so permit it
      if rule_match == nil then
--         print("shortcut")
         link.transmit(o, p)
         return
      end

      -- get our data struct on that source IP
      -- TODO: we need to periodically clean this data struct up so it doesn't just fill up and consume all memory
      if self.rules[rule_match].srcs[src_ip] == nil then
--         print("New source ip: " .. src_ip)
         self.rules[rule_match].srcs[src_ip] = {
            pps_rate = self.rules[rule_match].pps_rate,
            pps_tokens = self.rules[rule_match].pps_burst,
            pps_capacity = self.rules[rule_match].pps_burst,
            bucket_content = self.bucket_capacity,
            bucket_capacity = self.bucket_capacity,
            block_until = nil
            }
      end
      local src = self.rules[rule_match].srcs[src_ip]

      -- figure out rates n shit
      do
         -- TODO: is this expensive to do for every packet?
         local cur_now = tonumber(app.now())
         local last_time = src.last_time or cur_now
         src.pps_tokens = math.max(0,math.min(
               src.pps_tokens + src.pps_rate * (cur_now - last_time),
               src.pps_capacity
            ))
         src.last_time = cur_now
      end

      -- TODO: this is for pps, do the same for bps
      src.pps_tokens = src.pps_tokens - 1
      if src.pps_tokens <= 0 then
         if src.block_until == nil then
            print("packet rate from: " .. tostring(src_ip) .. " too high, blocking")
         else
            print("packet rate from: " .. tostring(src_ip) .. " too high, extending blocking")
         end
         src.block_until = tonumber(app.now()) + self.block_period
         self.blocklist[src_ip] = { action = "block", block_until = tonumber(app.now()) + self.block_period-5}
      end

      if src.block_until ~= nil and src.block_until < tonumber(app.now()) then
         print("got packet: "..tostring(src_ip).. " was in block, now ALLOW!")
         src.block_until = nil
      end

      if src.block_until ~= nil then
         print("got packet: "..tostring(src_ip).. " tokens: " .. src.pps_tokens .. " IN BLOCK")
         packet.deref(p)
      else
         print("got packet: "..tostring(src_ip).. " matched: " .. tostring(rule_match) .. " tokens: " .. src.pps_tokens .. " PASS")
         link.transmit(o, p)
      end
   end

end

function DDoS:report()
   print("-- DDoS report --")
   print("Configured block period: " .. self.block_period .. " seconds")
   print("Block list:")
   for src_ip,blocklist in pairs(self.blocklist) do
      print("  " .. src_ip .. " blocked for another " .. string.format("%0.1f", tostring(blocklist.block_until - tonumber(app.now()))) .. " seconds")
   end
   print("Traffic rules:")
   for rule_name,rule in pairs(self.rules) do
      print(" - " .. rule_name .. " [ " .. rule.filter .. " ]  pps_rate: " .. rule.pps_rate)
      for src_ip,src_info in pairs(rule.srcs) do
         -- calculate rate of packets
         if self.blocklist[src_ip] ~= nil then
            -- if source is in blocklist it means we shortcut and thus don't
            -- calculate pps, so we write '-'
            rate = "    -"
         else
            rate = string.format("%5.0f", src_info.pps_tokens)
         end
         str = string.format("  %15s tokens: %s ", src_ip, rate)
         if src_info.block_until == nil then
            str = string.format("%s %-7s", str, "allowed")
         else
            str = string.format("%s %-7s", str, "blocked for another " .. string.format("%0.1f", tostring(src_info.block_until - tonumber(app.now()))) .. " seconds")
         end
         print(str)
      end
   end
end


