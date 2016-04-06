module(..., package.seeall)

local Intel82599 = require("apps.intel.intel_app").Intel82599
local S         = require("syscall")
local engine    = require("core.app")
local config    = require("core.config")
local timer     = require("core.timer")
local pci       = require("lib.hardware.pci")
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
   cvlan        = "M",
   dvlan        = "N",

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
      clean_vlan = false
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
   function handlers.M (arg) opt.clean_vlan = arg end
   function handlers.N (arg) opt.dirty_vlan = arg end
   args = lib.dogetopt(args, handlers, "hm:rC:D:M:N:", long_opts)

   if not opt.intf_dirty then fatal("Missing argument -D") end
   if not opt.intf_clean then
      print("Clean interface not specified, assuming SnabbDDoS-on-a-stick")
      opt.intf_clean = opt.intf_dirty
   end
   if not opt.mconfig_file_path then fatal("Missing argument -m") end

   return opt
end

function run (args)
   local opt = parse_args(args)

   local c = config.new()

   -- TODO: we need the reverse path set up as well so we can reply to ARP
   -- packets but first we need the ARP app

   if opt.intf_clean == opt.intf_dirty then
      -- same physical interface used for dirty and clean traffic which means we
      -- use VLAN tag to put clean traffic on a separate logical interface and
      -- send out on the physical "dirty" interface. We only tag clean traffic
      -- since there is a performance penalty incurred by tagging and
      -- statistically we will have less packets on the clean side

      print("Using same physical interface for dirty and clean traffic")
      -- if dirty and clean interface is the same, require vlan tagging
      if not opt.clean_vlan then
         fatal("VLAN id must be set to use same interface for dirty and clean traffic")
      end
      local basic_apps = require("apps.basic.basic_apps")

      -- setup physical interface, 10G or tap
      if nic_exists(opt.intf_dirty) then
         config.app(c, "nic", Intel82599, {
            pciaddr=opt.intf_dirty,
         })
         -- input and output interface names
         iif_name = "rx"
         oif_name = "tx"
      else
         print("dirty interface '" .. opt.intf_dirty .. "' is not an existing PCI device, assuming tap interface")
         config.app(c, "nic", Tap, opt.intf_dirty)

         -- input and output interface names
         iif_name = "input"
         oif_name = "output"
      end

      config.app(c, "nic_tee", basic_apps.Tee)
      config.app(c, "dirty_untag", vlan.Untagger, { tag = tonumber(opt.dirty_vlan) })
      config.app(c, "dirty_tag", vlan.Tagger, { tag = tonumber(opt.dirty_vlan) })
      config.app(c, "clean_untag", vlan.Untagger, { tag = tonumber(opt.clean_vlan) })
      config.app(c, "clean_tag", vlan.Tagger, { tag = tonumber(opt.clean_vlan) })
      config.app(c, "nic_join", basic_apps.Join)
      config.app(c, "ddos", ddos.DDoS, { config_file_path = opt.mconfig_file_path })

      -- link apps
      config.link(c, "nic."..oif_name.." -> nic_tee.input")
      config.link(c, "nic_tee.dirty -> dirty_untag.input")
      config.link(c, "nic_tee.clean -> clean_untag.input")

      config.link(c, "dirty_untag.output -> ddos.input")
      config.link(c, "ddos.output -> clean_tag.input")

      config.link(c, "dirty_tag.output -> nic_join.dirty")
      config.link(c, "clean_tag.output -> nic_join.clean")
      config.link(c, "nic_join.out -> nic."..iif_name)

   else
      -- different physical interfaces for dirty and clean traffic

      config.app(c, "ddos", ddos.DDoS, { config_file_path = opt.mconfig_file_path })

      -- setup physical dirty interface, 10G or tap
      if nic_exists(opt.intf_dirty) then -- 10G
         config.app(c, "dirty", Intel82599, {
            pciaddr=opt.intf_dirty,
         })

         -- link dirty -> ddos
         config.link(c, "dirty.tx -> ddos.input")

      else -- tap
         print("dirty interface '" .. opt.intf_dirty .. "' is not an existing PCI device, assuming tap interface")
         config.app(c, "dirty", Tap, opt.intf_dirty)

         -- link dirty -> ddos
         config.link(c, "dirty.output -> ddos.input")
      end

      -- setup physical clean interface, 10G or tap
      if nic_exists(opt.intf_clean) then -- 10G
         config.app(c, "clean", Intel82599, {
            pciaddr=opt.intf_clean
         })

         -- VLAN tagging on egress?
         if opt.clean_vlan then
            config.app(c, "vlan_tagger", vlan.Tagger, { tag = opt.clean_vlan })
            -- link ddos -> vlan -> clean
            config.link(c, "ddos.output -> vlan_tagger.input")
            config.link(c, "vlan_tagger.output -> clean.rx")
         else
            -- link ddos -> clean
            config.link(c, "ddos.output -> clean.rx")
         end
      else -- tap
         print("clean interface '" .. opt.intf_clean .. "' is not an existing PCI device, assuming tap interface")
         config.app(c, "clean", Tap, opt.intf_clean)

         -- VLAN tagging on egress?
         if opt.clean_vlan then
            config.app(c, "vlan_tagger", vlan.Tagger, { tag = opt.clean_vlan })
            -- link ddos -> vlan -> clean
            config.link(c, "ddos.output -> vlan_tagger.input")
            config.link(c, "vlan_tagger.output -> clean.input")
         else
            -- link ddos -> clean
            config.link(c, "ddos.output -> clean.input")
         end
      end
   end

   -- report every second
   if opt.report then
      timer.activate(timer.new(
         "report",
         function()
             engine.app_table.ddos:report()
             engine:report_apps()
             engine:report_links()
         end,
         1e9,
         'repeating'
      ))
   end

   engine.configure(c)
   engine.main()
end
