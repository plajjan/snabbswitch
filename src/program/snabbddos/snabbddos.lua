module(..., package.seeall)

local S         = require("syscall")
local engine    = require("core.app")
local config    = require("core.config")
local timer     = require("core.timer")
local pci       = require("lib.hardware.pci")
local intel10g  = require("apps.intel.intel10g")
local intel_app = require("apps.intel.intel_app")
local ipv4      = require("lib.protocol.ipv4")
local lib       = require("core.lib")
local main      = require("core.main")

local Tap       = require("apps.tap.tap").Tap
local ddos      = require("apps.ddos.ddos")
local vlan      = require("apps.vlan.vlan")

local usage = require("program.snabbddos.README_inc")

local long_opts = {
   help         = "h",
   mconfig      = "m",
   clean        = "C",
   dirty        = "D",
   vlan         = "V"
}

local function fatal(msg)
   print('error: '..msg)
   main.exit(1)
end


local function file_exists(path)
   local stat = S.stat(path)
   return stat and stat.isreg
end

local function dir_exists(path)
   local stat = S.stat(path)
   return stat and stat.isdir
end

local function nic_exists(pci_addr)
   local devices="/sys/bus/pci/devices"
   return dir_exists(("%s/%s"):format(devices, pci_addr)) or
      dir_exists(("%s/0000:%s"):format(devices, pci_addr))
end

function parse_args(args)
   -- argument parsing
   local opt = {
      report = false,
      vlan = false
   }
   local handlers = {}
   -- help
   function handlers.h (arg) print(usage) main.exit(1) end
   -- mitigation config
   function handlers.m (arg) opt.mconfig_file_path = arg end
   -- report
   function handlers.r (arg) opt.report = true end
   -- interface clean
   function handlers.C (arg) opt.intf_clean = arg end
   -- interface dirty
   function handlers.D (arg)
      opt.intf_dirty = arg
   end
   function handlers.V (arg) opt.vlan_tag = arg end
   args = lib.dogetopt(args, handlers, "hm:rD:C:V:", long_opts)

   if not opt.intf_clean then fatal("Missing argument -C") end
   if not opt.intf_dirty then fatal("Missing argument -D") end
   if not opt.mconfig_file_path then fatal("Missing argument -m") end

   return opt
end

function run (args)
   local opt = parse_args(args)

   local c = config.new()

   -- setup interfaces
   if nic_exists(opt.intf_dirty) then
   else
      print("dirty interface '" .. opt.intf_dirty .. "' is not an existing PCI device, assuming tap interface")
      config.app(c, "dirty", Tap, opt.intf_dirty)
   end
   if nic_exists(opt.intf_dirty) then
   else
      print("dirty interface '" .. opt.intf_dirty .. "' is not an existing PCI device, assuming tap interface")
      config.app(c, "clean", Tap, opt.intf_clean)
   end

   -- report every second
   if opt.report then
      timer.activate(timer.new(
         "report",
         function()
             engine.app_table.ddos:report()
         end,
         1e9,
         'repeating'
      ))
   end

   -- TODO: we need the reverse path set up as well so we can reply to ARP
   -- packets but first we need the ARP app
   config.app(c, "ddos", ddos.DDoS, { config_file_path = opt.mconfig_file_path })
   config.link(c, "dirty.output -> ddos.input")
   -- if vlan_tag is set we tag all egress/clean packets with a VLAN tag
   if opt.vlan_tag then
      print("Using VLAN tag: " .. opt.vlan_tag)
      config.app(c, "vlan_tagger", vlan.Tagger, { tag = opt.vlan_tag })
      config.link(c, "ddos.output -> vlan_tagger.input")
      config.link(c, "vlan_tagger.output -> clean.input")
   else
      config.link(c, "ddos.output -> clean.input")
   end
   engine.configure(c)
   engine.main()
end
