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
   local conf = arg and config.parse_app_arg(arg) or {}
   assert(conf.block_period >= 5, "block_period must be at least 5 seconds")
   local o =
   {
      blacklist = {
         ipv4 = {},
         ipv6 = {}
      },
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

   -- datagram object for reuse
   self.d = datagram:new()

   -- store casted ethertypes for fast matching
   self.ethertype_ipv4 = ffi.cast("uint16_t", 8)
   self.ethertype_ipv6 = ffi.cast("uint16_t", 56710)

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
   -- unblock old entries in blacklist
   for src_ip, ble in pairs(self.blacklist.ipv4) do
      if ble.block_until < tonumber(app.now()) then
         self.blacklist.ipv4[src_ip] = nil
      end
   end
   for src_ip, ble in pairs(self.blacklist.ipv6) do
      if ble.block_until < tonumber(app.now()) then
         self.blacklist.ipv6[src_ip] = nil
      end
   end

   -- and in rules
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
   local iov = p.iovecs[0]
   local afi

   -- dig out src IP from packet
   -- TODO: don't use ntop to convert IP to a string and base hash lookup on a
   -- string - use a radix trie or similar instead!
   local ethertype = ffi.cast("uint16_t*", iov.buffer.pointer + iov.offset + 12)[0]
   local src_ip
   if ethertype == self.ethertype_ipv4 then
      afi = "ipv4"
      src_ip = ffi.cast("uint32_t*", iov.buffer.pointer + iov.offset + 26)[0]
   elseif ethertype == self.ethertype_ipv6 then
      afi = "ipv6"
      -- TODO: this is slow, do something similar to IPv4
      src_ip = ipv6:ntop(iov.buffer.pointer + iov.offset + 22)
   else
      packet.deref(p)
      return
   end

   -- short cut for stuff in blacklist that is in state block
   -- TODO: blacklist is a table. use a Radix trie instead!
   local ble = self.blacklist[afi][src_ip]
   if ble and ble.action == "block" then
      packet.deref(p)
      return
   end

   d = self.d:reuse(p, ethernet)

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
   -- uses http://en.wikipedia.org/wiki/Token_bucket algorithm
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

   if src.pps_tokens and src.pps_tokens < 0 or src.bps_tokens and src.bps_tokens < 0 then
      src.block_until = cur_now + self.block_period
      self.blacklist[afi][src_ip] = { action = "block", block_until = cur_now + self.block_period-5 }
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
   print("Blacklist:")
   for src_ip,ble in pairs(self.blacklist.ipv4) do
      print("  " .. src_ip .. " blocked for another " .. string.format("%0.1f", tostring(ble.block_until - tonumber(app.now()))) .. " seconds")
   end

   print("Traffic rules:")
   for rule_name,rule in pairs(self.rules) do
      print(string.format(" - Rule %-10s rate: %10spps / %10sbps  filter: %s", rule_name, (rule.pps_rate or "-"), (rule.bps_rate or "-"), rule.filter))
      for src_ip,src_info in pairs(rule.srcs) do
         -- calculate rate of packets
         -- TODO: calculate real PPS rate
         pps_tokens = string.format("%5s", "-")
         -- if source is in blocklist it means we shortcut and thus don't
         -- calculate pps, so we write '-'
--         if self.blocklist[src_ip] == nil and src_info.pps_tokens then
--            pps_tokens = string.format("%5.0f", src_info.pps_tokens )
--         end
         str = string.format("  %15s last: %d tokens: %s ", src_ip, tonumber(app.now())-src_info.last_time, pps_tokens)
         if src_info.block_until == nil then
            str = string.format("%s %-7s", str, "allowed")
         else
            str = string.format("%s %-7s", str, "blocked for another " .. string.format("%0.1f", tostring(src_info.block_until - tonumber(app.now()))) .. " seconds")
         end
         print(str)
      end
   end
end


function selftest()
   print("DDoS selftest")

   local ok = true
--   if not test_logic() then
--      ok = false
--   end

   if not test_performance() then
      ok = false
   end

   if ok then
      print("All tests passed")
   else
      print("tests failed!")
   end

end


function test_logic()
   local pcap = require("apps.pcap.pcap")
   local basic_apps = require("apps.basic.basic_apps")

   buffer.preallocate(10000)

   local rules = {
      ntp = {
         filter = "udp and src port 123",
         pps_rate = 10,
         pps_burst = 20,
         bps_rate = nil,
         bps_burst = nil
      }
   }

   local c = config.new()
   config.app(c, "source", pcap.PcapReader, "apps/ddos/selftest.cap.input")
   config.app(c, "ddos", DDoS, { rules = rules, block_period = 60 })
   config.app(c, "sink", pcap.PcapWriter, "apps/ddos/selftest.cap.output")
   config.link(c, "source.output -> ddos.input")
   config.link(c, "ddos.output -> sink.input")
   app.configure(c)

   local ok = true

   -- the input pcap contains five ICMP packets from one source and 31995 NTP
   -- packets from another source

   print("== Logic test - matching NTP")
   print("  Rule for NTP packets with threshold of 10pps/20p burst, rest is allowed")
   print("  we should see a total of 25 packets = 5 ICMP (allowed) + 20 NTP (burst)")
   app.main({duration = 5}) -- should be long enough...
   -- Check results
   if io.open("apps/ddos/selftest.cap.output"):read('*a') ~=
      io.open("apps/ddos/selftest.cap.expect-1"):read('*a') then
      print([[file selftest.cap.output does not match selftest.cap.expect.
      Check for the mismatch like this (example):
      tshark -Vnr apps/ddos/selftest.cap.output > /tmp/selftest.cap.output.txt
      tshark -Vnr apps/ddos/selftest.cap.expect-1 > /tmp/selftest.cap.expect-1.txt
      diff -u /tmp/selftest.cap.{output,expect-1}.txt | less ]])
      ok = false
   else
      print("Logic test passed!")
   end

   return ok

end

function test_performance()
   local pcap = require("apps.pcap.pcap")
   local basic_apps = require("apps.basic.basic_apps")

   buffer.preallocate(10000)

   local rules = {
      ntp = {
         filter = "udp and src port 123",
         pps_rate = 10,
         pps_burst = 20,
         bps_rate = nil,
         bps_burst = nil
      }
   }

   local c = config.new()
   config.app(c, "source", pcap.PcapReader, "apps/ddos/selftest.cap.input")
   config.app(c, "repeater", basic_apps.FastRepeater)
   config.app(c, "ddos", DDoS, { rules = rules, block_period = 10 })
   config.app(c, "sink", basic_apps.FastSink)
   config.link(c, "source.output -> repeater.input")
   config.link(c, "repeater.output -> ddos.input")
   config.link(c, "ddos.output -> sink.input")
   app.configure(c)

   local ddos_app = app.app_table.ddos

   timer.activate(timer.new(
      "report",
      function()
          app.app_table.ddos:report()
      end,
      1e9,
      'repeating'
   ))

   local seconds_to_run = 30
   print("== Perf test - dropping NTP by match!")
   app.main({duration = seconds_to_run})

   print("source sent: " .. app.app_table.source.output.output.stats.txpackets)
   print("repeater sent: " .. app.app_table.repeater.output.output.stats.txpackets)
   print("sink received: " .. app.app_table.sink.input.input.stats.rxpackets)
   print("Effective rate: " .. string.format("%0.1f", tostring(app.app_table.repeater.output.output.stats.txpackets / seconds_to_run)))
   return true
end
