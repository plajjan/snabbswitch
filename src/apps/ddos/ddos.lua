module(..., package.seeall)

local app = require("core.app")
local buffer = require("core.buffer")
local datagram = require("lib.protocol.datagram")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local filter = require("lib.pcap.filter")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local lib = require("core.lib")
local link = require("core.link")
local packet = require("core.packet")

local C = ffi.C

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

   self.d = datagram:new()

   -- schedule periodic task every second
   timer.activate(timer.new(
      "periodic",
      function () self:periodic() end,
      1e9, -- every second
      'repeating'
   ))
   return self
end 


function DDoS:periodic()
   for src_ip, blocklist in pairs(self.blocklist) do
      print("Checking block for: " .. src_ip)
      if blocklist.block_until < tonumber(app.now()) then
         self.blocklist[src_ip] = nil
      end
   end

   for rule_name,rule in pairs(self.rules) do
      for src_ip,src_info in pairs(rule.srcs) do
         if src_info.block_until ~= nil and src_info.block_until < tonumber(app.now()) then
            src_info.block_until = nil
         end
      end
   end
end


function DDoS:push () 
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   -- TODO: should establish one rule-set per destination IP (ie the target IP we are mitigation for)
   -- TODO: need to write ethernet headers on egress to match the MAC address of our "default gateway"

   while not link.empty(i) and not link.full(o) do
      self:process_packet(i, o)
   end
end


function DDoS:process_packet(i, o)
   local p = link.receive(i)

   -- TODO: do we really need to do ntop on this? is that an expensive operation?

   -- dig out src IP from packet
   d = self.d:reuse(p, ethernet)
   d:parse_n(2)
   d:unparse(2)
   local eth, ip = unpack(d:stack())
   local src_ip
   if eth:type() == 0x0800 then
      src_ip = ipv4:ntop(ip:src())
   elseif eth:type() == 0x86dd then
      src_ip = ipv6:ntop(ip:src())
   else
      return
   end

   -- short cut for stuff in blocklist that is in state block
   if self.blocklist[src_ip] ~= nil and self.blocklist[src_ip].action == "block" then
      packet.deref(p)
      return
   end

   -- match up against our filter rules
   local rule_match = self:bpf_match(d)
   -- didn't match any rule, so permit it
   if rule_match == nil then
      link.transmit(o, p)
      return
   end

   local cur_now = tonumber(app.now())
   src = self:get_src(rule_match, src_ip)

   -- figure out rates
   if src.pps_tokens then
      src.pps_tokens = math.max(0,math.min(
            src.pps_tokens + src.pps_rate * (cur_now - src.last_time),
            src.pps_capacity
         ))
      src.pps_tokens = src.pps_tokens - 1
   end
   if src.bps_tokens then
      src.bps_tokens = math.max(0,math.min(
            src.bps_tokens + src.bps_rate * (cur_now - src.last_time),
            src.bps_capacity
         ))
      src.bps_tokens = src.bps_tokens - p.length
   end

   if src.pps_tokens and src.pps_tokens <= 0 or src.bps_tokens and src.bps_tokens <= 0 then
      src.block_until = cur_now + self.block_period
      self.blocklist[src_ip] = { action = "block", block_until = cur_now + self.block_period-5}
      packet.deref(p)
   else
      link.transmit(o, p)
   end

   src.last_time = cur_now
end


-- match against our BPF rules and return name of the match
function DDoS:bpf_match(d)
   for rule_name, rule in pairs(self.rules) do
      if rule.cfilter:match(d:payload()) then
         return rule_name
      end
   end
   return nil
end


function DDoS:get_src(rule_match, src_ip)
   -- get our data struct on that source IP
   -- TODO: we need to periodically clean this data struct up so it doesn't just fill up and consume all memory
   if self.rules[rule_match].srcs[src_ip] == nil then
      self.rules[rule_match].srcs[src_ip] = {
         last_time = tonumber(app.now()),
         pps_rate = self.rules[rule_match].pps_rate,
         pps_tokens = self.rules[rule_match].pps_burst,
         pps_capacity = self.rules[rule_match].pps_burst,
         bps_rate = self.rules[rule_match].bps_rate,
         bps_tokens = self.rules[rule_match].bps_burst,
         bps_capacity = self.rules[rule_match].bps_burst,
         block_until = nil
      }
   end
   return self.rules[rule_match].srcs[src_ip]
end


function DDoS:report()
   print("-- DDoS report --")
   local s_i = link.stats(self.input.input)
   local s_o = link.stats(self.output.output)
   print("Rx: " .. s_i.rxpackets .. " packets / " .. s_i.rxbytes .. " bytes")
   print("Tx: " .. s_o.txpackets .. " packets / " .. s_o.txbytes .. " bytes / " .. s_o.txdrop .. " packet drops")
   print("Configured block period: " .. self.block_period .. " seconds")
   print("Block list:")
   for src_ip,blocklist in pairs(self.blocklist) do
      print("  " .. src_ip .. " blocked for another " .. string.format("%0.1f", tostring(blocklist.block_until - tonumber(app.now()))) .. " seconds")
   end

   print("Traffic rules:")
   for rule_name,rule in pairs(self.rules) do
      print(string.format(" - Rule %-10s rate: %10spps / %10sbps  filter: %s", rule_name, (rule.pps_rate or "-"), (rule.bps_rate or "-"), rule.filter))
      for src_ip,src_info in pairs(rule.srcs) do
         -- calculate rate of packets
         -- TODO: calculate real PPS rate
         rate = string.format("%5s", "-")
         if self.blocklist[src_ip] == nil then
            -- if source is in blocklist it means we shortcut and thus don't
            -- calculate pps, so we write '-'
            rate = string.format("%5.0f", src_info.pps_tokens )
         end
         str = string.format("  %15s last: %d tokens: %s ", src_ip, tonumber(app.now())-src_info.last_time, rate)
         if src_info.block_until == nil then
            str = string.format("%s %-7s", str, "allowed")
         else
            str = string.format("%s %-7s", str, "blocked for another " .. string.format("%0.1f", tostring(src_info.block_until - tonumber(app.now()))) .. " seconds")
         end
         print(str)
      end
   end
end


