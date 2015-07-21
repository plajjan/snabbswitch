module(..., package.seeall)

local app = require("core.app")
local datagram = require("lib.protocol.datagram")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local filter = require("lib.pcap.filter")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local lib = require("core.lib")
local link = require("core.link")
local packet = require("core.packet")
local pf = require("pf")        -- pflua

local C = ffi.C

DDoS = {}

-- I don't know what I'm doing
function DDoS:new (arg)
   local conf = arg and config.parse_app_arg(arg) or {}
   local o =
   {
      blacklist = {
         ipv4 = {},
         ipv6 = {}
      },
      sources = {},
      rules = conf.rules,
      initial_block_time = conf.initial_block_time or 10,
      max_block_time = conf.max_block_time or 600,
      last_report = nil
   }

   self = setmetatable(o, {__index = DDoS})
   assert(self.initial_block_time >= 5, "initial_block_time must be at least 5 seconds")
   assert(self.max_block_time >= 5, "max_block_time must be at least 5 seconds")

   -- pre-process rules
   for rule_name, rule in pairs(self.rules) do
      rule.name = rule_name
      -- compile the filter
      local filter = pf.compile_filter(rule.filter)
      assert(filter)
      rule.cfilter = filter

      -- use default burst value of 2*rate
      if rule.pps_burst == nil and rule.pps_rate then
         rule.pps_burst = 2 * rule.pps_rate
      end
      if rule.bps_burst == nil and rule.bps_rate then
         rule.bps_burst = 2 * rule.bps_rate
      end
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

   -- TODO do stuff with sources struct

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

function ntop(num)
   oct1 = math.floor(num) % 2 ^ 8
   oct2 = math.floor(num / 2 ^ 8) % 2 ^ 8
   oct3 = math.floor(num / 2 ^ 16) % 2 ^ 8
   oct4 = math.floor(num / 2 ^ 24) % 2 ^ 8
   return oct1 .. "." .. oct2 .. "." .. oct3 .. "." .. oct4
end


function DDoS:process_packet(i, o)
   local p = link.receive(i)
   local afi

   -- get ethertype of packet
   local ethertype = ffi.cast("uint16_t*", packet.data(p) + 12)[0]

   -- TODO: don't use ntop to convert IP to a string and base hash lookup on a
   -- string - use a Patricia trie or similar instead!

   -- dig out src IP from packet
   local src_ip
   if ethertype == self.ethertype_ipv4 then
      afi = "ipv4"
      -- IPv4 source address is 26 bytes in
      src_ip = ffi.cast("uint32_t*", packet.data(p) + 26)[0]
   elseif ethertype == self.ethertype_ipv6 then
      afi = "ipv6"
      -- TODO: this is slow, do something similar to IPv4
      -- IPv6 source address is 22 bytes in
      src_ip = ipv6:ntop(packet.data(p) + 22)
   else
      packet.free(p)
      return
   end

   -- short cut for stuff in blacklist that is in state block
   -- TODO: blacklist is a table. use a Radix trie instead!
   -- Doing a simple match against a static IP cast as a uint32_t increases
   -- performance to 23Mpps on my laptop from 9Mpps when matching in this table.
   -- Using a Patricia tree, I hope we can end up somewhere in between..
   -- 14.8Mpps would be perfect ;)
   local ble = self.blacklist[afi][src_ip]
   if ble and ble.action == "block" then
      packet.free(p)
      return
   end

   d = self.d:reuse(p, ethernet)

   -- match up against our filter rules
   local rule = self:bpf_match(d)
   -- didn't match any rule, so permit it
   if rule == nil then
      link.transmit(o, p)
      return
   end

   local cur_now = tonumber(app.now())
   src = self:get_src(src_ip, rule)

   -- uses http://en.wikipedia.org/wiki/Token_bucket algorithm
   -- figure out pps rate
   if rule.pps_rate then
      src.pps_tokens = math.max(0,
            math.min(
               src.pps_tokens + rule.pps_rate * (cur_now - src.last_time),
               rule.pps_burst)
         ) - 1
   end
   -- figure out bps rate
   if rule.bps_rate then
      src.bps_tokens = math.max(0,
            math.min(
               src.bps_tokens + rule.bps_rate * (cur_now - src.last_time),
               rule.bps_burst)
         ) - p.length
   end

   -- if pps/bps rate exceeds threshold, block!
   if rule.pps_rate and src.pps_tokens < 0 or rule.bps_rate and src.bps_tokens < 0 then
      local block_time = math.min(src.last_block_time * 2, self.max_block_time)
      src.block_until = cur_now + block_time
      src.last_block_time = block_time
      self.blacklist[afi][src_ip] = { action = "block", block_until = src.block_until - 5 }
   end

   if src.block_until and src.block_until < cur_now then
      packet.free(p)
   else
      link.transmit(o, p)
   end

   src.last_time = cur_now
end


-- match against our BPF rules and return name of the match
function DDoS:bpf_match(d)
   for rule_name, rule in pairs(self.rules) do
      if rule.cfilter(d:payload()) then
         return rule
      end
   end
   return nil
end


-- return data struct on source ip for specific rule
function DDoS:get_src(src_ip, rule)
   -- get our data struct on that source IP
   -- TODO: we need to periodically clean this data struct up so it doesn't just fill up and consume all memory

   if self.sources[src_ip] == nil then
      self.sources[src_ip] = {
         rule = {}
         }
   end

   if self.sources[src_ip].rule[rule.name] == nil then
      self.sources[src_ip].rule[rule.name] = {
         last_time = tonumber(app.now()),
         pps_tokens = rule.pps_burst,
         bps_tokens = rule.bps_burst,
         block_until = nil,
         last_block_time = self.initial_block_time / 2
      }
   end
   return self.sources[src_ip].rule[rule.name]
end


function DDoS:get_stats_snapshot()
   return {
      rxpackets = self.input.input.stats.txpackets,
      rxbytes = self.input.input.stats.txbytes,
      txpackets = self.output.output.stats.txpackets,
      txbytes = self.output.output.stats.txbytes,
      txdrop = self.output.output.stats.txdrop,
      time = tonumber(C.get_time_ns()),
   }
end

function num_prefix (num)
   if num > 1e12 then
      return string.format("%0.2fT", tostring(num / 1e12))
   end
   if num > 1e9 then
      return string.format("%0.2fG", tostring(num / 1e9))
   end
   if num > 1e6 then
      return string.format("%0.2fM", tostring(num / 1e6))
   end
   if num > 1e3 then
      return string.format("%0.2fk", tostring(num / 1e3))
   end
   return string.format("%0.2f", tostring(num))
end


function DDoS:report()
   if self.last_stats == nil then
      self.last_stats = self:get_stats_snapshot()
      return
   end
   last = self.last_stats
   cur = self:get_stats_snapshot()

   print("\n-- DDoS report --")
   print("Configured initial block period: " .. self.initial_block_time .. " seconds")
   print("Configured maximum block period: " .. self.max_block_time .. " seconds")
   print("Rx: " .. num_prefix((cur.rxpackets - last.rxpackets) / ((cur.time - last.time) / 1e9)) .. "pps / " .. cur.rxpackets .. " packets / " .. cur.rxbytes .. " bytes")
   print("Tx: " .. num_prefix((cur.txpackets - last.txpackets) / ((cur.time - last.time) / 1e9)) .. "pps / " .. cur.txpackets .. " packets / " .. cur.txbytes .. " bytes / " .. cur.txdrop .. " packet drops")
   print("Blacklist:")
   for src_ip,ble in pairs(self.blacklist.ipv4) do
      print("  " .. ntop(src_ip) .. " blocked for another " .. string.format("%0.1f", tostring(ble.block_until - tonumber(app.now()))) .. " seconds")
   end

   print("Traffic rules:")
   for rule_name,rule in pairs(self.rules) do
      print(string.format(" - Rule %-10s rate: %10spps / %10sbps  filter: %s", rule_name, (rule.pps_rate or "-"), (rule.bps_rate or "-"), rule.filter))
      for src_ip,src_info in pairs(self.sources) do
         if src_info.rule[rule_name] ~= nil then
            local sr_info = src_info.rule[rule_name]

            -- calculate rate of packets
            -- TODO: calculate real PPS rate
            pps_tokens = string.format("%5s", "-")

            str = string.format("  %15s last: %d tokens: %s ", ntop(src_ip), tonumber(app.now())-sr_info.last_time, pps_tokens)
            if sr_info.block_until == nil then
               str = string.format("%s %-7s", str, "allowed")
            else
               str = string.format("%s %-7s", str, "blocked for another " .. string.format("%0.1f", tostring(sr_info.block_until - tonumber(app.now()))) .. " seconds")
            end
            print(str)
         end
      end
   end

   self.last_stats = cur
end


function selftest()
   print("DDoS selftest")

   local ok = true
   if not test_logic() then
      ok = false
   end

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
   config.app(c, "source", pcap.PcapReader, "apps/ddostop/selftest.cap.input")
   config.app(c, "ddos", DDoS, { rules = rules })
   config.app(c, "sink", pcap.PcapWriter, "apps/ddostop/selftest.cap.output")
   config.link(c, "source.output -> ddos.input")
   config.link(c, "ddos.output -> sink.input")
   app.configure(c)

   local ok = true

   -- the input pcap contains five ICMP packets from one source and 31995 NTP
   -- packets from another source

   print("== Logic test - matching NTP")
   print("  Rule for NTP packets with threshold of 10pps/20p burst, rest is allowed")
   print("  we should see a total of 25 packets = 5 ICMP (allowed) + 20 NTP (burst)")
--   app.main({duration = 5}) -- should be long enough...
   app.breathe()
   -- Check results
   if io.open("apps/ddostop/selftest.cap.output"):read('*a') ~=
      io.open("apps/ddostop/selftest.cap.expect-1"):read('*a') then
      print([[file selftest.cap.output does not match selftest.cap.expect.
      Check for the mismatch like this (example):
      tshark -Vnr apps/ddostop/selftest.cap.output > /tmp/selftest.cap.output.txt
      tshark -Vnr apps/ddostop/selftest.cap.expect-1 > /tmp/selftest.cap.expect-1.txt
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

   print("== Perf test - fast path - dropping NTP by match!")
   local rules = {
      ntp = {
         filter = "udp and src port 123",
         pps_rate = 10
      }
   }

   local c = config.new()
   config.app(c, "source", pcap.PcapReader, "apps/ddostop/selftest.cap.input")
   config.app(c, "repeater", basic_apps.Repeater)
   config.app(c, "ddos", DDoS, { rules = rules })
   config.app(c, "sink", basic_apps.Sink)
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

--   engine.Hz = false
   local start_time = tonumber(C.get_time_ns())
   app.main({duration = 20})
--   for i = 1, 500000 do
--      app.breathe()
--      timer.run()
--   end
--   local deadline = lib.timer(seconds_to_run * 1e9)
--   repeat app.breathe() until deadline()
   local stop_time = tonumber(C.get_time_ns())
   local elapsed_time = (stop_time - start_time) / 1e9
   print("elapsed time ", elapsed_time, "seconds")

   print("source sent: " .. app.app_table.source.output.output.stats.txpackets)
   print("repeater sent: " .. app.app_table.repeater.output.output.stats.txpackets)
   print("sink received: " .. app.app_table.sink.input.input.stats.rxpackets)
   print("Effective rate: " .. string.format("%0.1f", tostring(app.app_table.repeater.output.output.stats.txpackets / elapsed_time)))
   return true
end
