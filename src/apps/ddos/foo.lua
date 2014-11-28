#!/usr/bin/env snabb

local app       = require("core.app")
local buffer    = require("core.buffer")
local config    = require("core.config")
local timer     = require("core.timer")
local pci       = require("lib.hardware.pci")
local intel10g	= require("apps.intel.intel10g")
local intel_app = require("apps.intel.intel_app")
local basic_apps = require("apps.basic.basic_apps")
local main      = require("core.main")
local PcapReader= require("apps.pcap.pcap").PcapReader
local LoadGen   = require("apps.intel.loadgen").LoadGen

local DDoS = require("apps.ddos.ddos").DDoS

local ffi = require("ffi")
local C = ffi.C

function is_device_suitable (pcidev, patterns)
   if not pcidev.usable or pcidev.driver ~= 'apps.intel.intel10g' then
      return false
   end
   if #patterns == 0 then
      return true
   end
   for _, pattern in ipairs(patterns) do
      if pcidev.pciaddress:gmatch(pattern)() then
         return true
      end
   end
end


function run (args)
	local filename = table.remove(args, 1)
	local patterns = args
	local c = config.new()

	--	TODO: should default to do input and output on same port and bind to all available ports
--	local nics = 0
--	pci.scan_devices()
--	for _,device in ipairs(pci.devices) do
--		if is_device_suitable(device, patterns) then
--			nics = nics + 1
--			local name = "nic"..nics
--			print("PCI id: "..device.pciaddress.." name: "..name)
--			config.app(c, name, LoadGen, device.pciaddress)
--			config.link(c, "source."..tostring(nics).."->"..name..".input")
--		end
--	end

   local rules = {
      icmp = {
         filter = "icmp",
         pps_rate = 1000,
         pps_burst = 1000,
         bps_rate = nil,
         bps_burst = nil
      },
      ntp = {
         filter = "udp and src port 123",
         pps_rate = 1,
         pps_burst = 2,
         bps_rate = nil,
         bps_burst = nil
      }
   }
   config.app(c, "ddos", DDoS, { rules = rules, block_period = 20 })

   config.app(c, "nic0", intel_app.Intel82599, { pciaddr = "0000:02:00.0" })
   config.app(c, "nic1", intel_app.Intel82599, { pciaddr = "0000:02:00.1" })

   config.link(c, "nic0.tx -> ddos.input")
   config.link(c, "ddos.output -> nic1.rx")

   app.configure(c)

--   local fn = function ()
--      -- TODO: only reports statistics for DDoS app?
--      local d = app.app_table["ddos"]
--      --d.report()
--      app.report_each_app()
--   end
--   local t = timer.new("report", fn, 1e9, 'repeating')
--   timer.activate(t)

   buffer.preallocate(100000)
   app.main()

end

run(main.parameters)

