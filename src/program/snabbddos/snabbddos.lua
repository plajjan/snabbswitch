module(..., package.seeall)

local engine    = require("core.app")
local config    = require("core.config")
local timer     = require("core.timer")
local pci       = require("lib.hardware.pci")
local intel10g  = require("apps.intel.intel10g")
local intel_app = require("apps.intel.intel_app")
local ipv4      = require("lib.protocol.ipv4")
local json      = require("lib.json")
local lib       = require("core.lib")
local main      = require("core.main")

local Tap       = require("apps.tap.tap").Tap
local ddos      = require("apps.ddos.ddos")
local vlan      = require("apps.vlan.vlan")

local usage = require("program.snabbddos.README_inc")

local long_opts = {
   help         = "h",
   config       = "c",
   clean        = "C",
   dirty        = "D"
}

function run (args)
   local intf_dirty, intf_clean
   local config_file_path
   local report = false
   local vlan_tag = false

   -- argument parsing
   local opt = {}
   function opt.h (arg) print(usage) main.exit(1) end
   function opt.c (arg) config_file_path = arg end
   function opt.r (arg) report = true end
   function opt.C (arg) intf_clean = arg end
   function opt.D (arg) intf_dirty = arg end
   function opt.V (arg) vlan_tag = arg end
   args = lib.dogetopt(args, opt, "hc:rD:C:V:", long_opts)

   local c = config.new()

   -- setup interfaces
   config.app(c, "dirty", Tap, intf_dirty)
   config.app(c, "clean", Tap, intf_clean)

   -- read mitigations configuration
   local config_file = assert(io.open(config_file_path, "r"))
   local config_json = config_file:read("*all")
   local mitigation_config = {}
   -- prepare the config
   for entry, value in pairs(json.decode(config_json)) do
      -- convert IP address tring to numbers in network byte order
      mitigation_config[ddos.pton(entry)] = value
   end

   if report then
      timer.activate(timer.new(
         "report",
         function()
             engine.app_table.ddos:report()
         end,
         1e9,
         'repeating'
      ))
   end

   config.app(c, "ddos", ddos.DDoS, { mitigations = mitigation_config })
   config.link(c, "dirty.output -> ddos.input")
   if vlan_tag then
      print("Using VLAN tag: " .. vlan_tag)
      config.app(c, "vlan_tagger", vlan.Tagger, { tag = vlan_tag })
      config.link(c, "ddos.output -> vlan_tagger.input")
      config.link(c, "vlan_tagger.output -> clean.input")
   else
      config.link(c, "ddos.output -> clean.input")
   end
   engine.configure(c)
   engine.main()
end
