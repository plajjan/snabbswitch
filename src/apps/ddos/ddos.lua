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

   -- dig out src IP from packet
   -- TODO: don't use ntop to convert IP to a string and base hash lookup on a
   -- string - use a radix trie or similar instead!
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
         pps_tokens = string.format("%5s", "-")
         -- if source is in blocklist it means we shortcut and thus don't
         -- calculate pps, so we write '-'
         if self.blocklist[src_ip] == nil and src_info.pps_tokens then
            pps_tokens = string.format("%5.0f", src_info.pps_tokens )
         end
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


-- return statistics snapshot
function DDoS:get_stat_snapshot ()
   return
   {
      rxpackets = self.input.input.stats.txpackets,
      txpackets = self.output.output.stats.txpackets,
      time = tonumber(C.get_time_ns()),
   }
end


function selftest()
   print("DDoS selftest")

   local ok = true
   test_logic()

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
   local ddos_app = app.app_table.ddos

   local seconds_to_run = 5
   timer.activate(timer.new(
         "report",
         function ()
            seconds_to_run = seconds_to_run - 1
         end,
         1e9, -- every second
         'repeating'
      ))


   do
      print("\ntest performance")
      while seconds_to_run > 0 do
         app.breathe()
         timer.run()
         C.usleep(10) -- avoid busy loop
      end
   end

--   for key,value in pairs({ source = true }) do
--	   print("MODULE:" .. key)
--   end
   app.report()
   print("source sent: " .. app.app_table.source.output.output.stats.txpackets)
   print("repeater sent: " .. app.app_table.repeater.output.output.stats.txpackets)
   print("sink received: " .. app.app_table.sink.input.input.stats.rxpackets)
end
