#!/usr/bin/env lua
--
-- Copyright 2025 ISP RAS
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--------------------------------------------------------------------------

local xml2lua = require("xml2lua")
local handler = require("xmlhandler.tree")
local luzer = require("luzer")

echo = ""

function fuzzerr_handler(msg)
    local errstr = { 
        "Unbalanced Tag",
        "Incomplete XML Document",
        "Error Parsing XML",
        "Error Parsing XMLDecl",
        "XMLDecl not at start of document",
        "Invalid XMLDecl attributes",
        "End Tag Attributes Invalid",
        "Error Parsing Comment",
        "Error Parsing CDATA",
        "Error Parsing DTD",
        "Error Parsing Processing Instruction",
    }
    local count = 0
    for i, v in ipairs(errstr) do
        local x, y = string.find(msg, v)
        -- Break if match found
        if not x then count = count + 1 else break end
    end
    -- Save unmatched error message
    if count == 11 then
        echo = msg .. "\n" .. debug.traceback()
    end
end

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    if #buf < 2 then return nil end
    local str = fdp:consume_string(#buf - 1)
    local parser = xml2lua.parser(handler)
    -- Put parser:parse(str) under xpcall to skip handled errors
    success = xpcall(function() parser:parse(str) end, fuzzerr_handler)
    if not success then
        -- Raise error if unmatched
        if string.len(echo) > 1 then
            error(echo)
        end
    end
end

local args = {}

luzer.Fuzz(TestOneInput, nil, args)
