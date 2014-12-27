module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C

require("apps.patricia.lua_patricia_h")

patricia = {}

--
-- Create a new patricia trie
--
function patricia:new ()
   self.__index = self
   self.trie = C.New_Patricia(32)
   return setmetatable({}, self)
end

--
-- Add a prefix to the trie
-- Expects an IPv4 address in string representation: 1.3.3.7
--
function patricia:add_prefix (prefix)
   assert(self.trie)
   local a = ffi.cast("char *", prefix)
   local p = C.ascii2prefix(2, a) -- 2 for IPv4
   local node = C.patricia_lookup(self.trie, p)
   return node
   --node.user1 = "foo"
   --C.make_and_lookup(self.trie, p)
end

--
-- Lookup prefix in trie
-- Expects an IPv4 address in string representation: 1.3.3.7
--
function patricia:lookup_s(prefix)
   return C.try_search_best(self.trie, ffi.cast("char *", prefix))
end

--
-- Lookup prefix in trie
-- Expects an IPv4 address as an integer (Lua number)
--
function patricia:lookup_i(prefix)
   return C.search_best2(self.trie, prefix)
end

function patricia:new_prefix(prefix)
   return C.create_prefix(2, prefix, 32)
end
