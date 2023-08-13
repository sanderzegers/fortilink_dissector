--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <https://www.gnu.org/licenses/>.


local fllldp_info =
{
    version = "0.1",
    author = "Sander Zegers",
    description = "This plugin parses Fortinet FortiLink LLDP Payloads",
}

set_plugin_info(fllldp_info)

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
}


local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(...)
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end

reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)


local localtlv_types = 
{
    [0x00] = "End of LLDPDU",
    [0x01] = "Chassis Id",
    [0x02] = "Port Id",
    [0x03] = "Time to Live",
    [0x04] = "Port Description",
    [0x05] = "System Name",
    [0x06] = "System Description",
    [0x07] = "System Capabilities",
    [0x08] = "Management Address",
    [0x7F] = "Organization Specific",
}

local flp_types = 
{
    [0x00] = "0",
    [0x01] = "1",
    [0x02] = "2",
    [0x03] = "3",
}


local fllldp = Proto.new("fllldp","FortiLink LLDP")


fllldp.fields.hostname = ProtoField.string("fllldp.hostname", "Fortiswitch Hostname")
fllldp.fields.serial = ProtoField.string("fllldp.serial", "Fortiswitch SerialNr")

fllldp.fields.tlv_type = ProtoField.uint16("lldp.tlv.type","TLV Type",base.DEC,localtlv_types,0xfe00)
fllldp.fields.tlv_len = ProtoField.uint16("lldp.tlv.len","TLV Length",base.DEC,nil,0x1ff)
-- use already existing field: lldp.orgtlv.oui
-- field_tlvoui = Field.new("lldp.orgtlv.oui")
fllldp.fields.tlv_oui = ProtoField.uint24("lldp.orgtlv.oui", "Organization Unique Code",base.HEX)

fllldp.fields.tlv_flinktype = ProtoField.uint8("lldp.tlv.flinktype", "FortiLink Packet Type",base.DEC,flp_types)
fllldp.fields.tlv_content = ProtoField.bytes("lldp.unknown_subtype.content")

-- Trunk Flags
fllldp.fields.fllldp_isl_port_options = ProtoField.uint32("fllldp.auto_isl_port_options","ISL Link options",base.HEX)
 -- Auto create ISL between switches:
fllldp.fields.fllldp_auto_isl = ProtoField.uint8("fllldp.auto_isl","auto-isl",base.DEC,nil,0x1)
 -- Create auto mclag isl between switches:
 fllldp.fields.fllldp_auto_mclag_isl = ProtoField.uint8("fllldp.auto_mclag_isl","auto-mclag-icl",base.DEC,nil,0x2)
 -- Switch is already configured as MCLAG switch:
 fllldp.fields.fllldp_mclag_switch = ProtoField.uint8("fllldp.is_mclag_switch","mclag-switch",base.DEC,nil,0x4)
 -- Switch requests ISL-Fortilink
 fllldp.fields.fllldp_isl_fortilink = ProtoField.uint8("fllldp.isl_fortilink","isl-fortilink",base.DEC,nil,0x10)



fllldp.fields.fllldp_isl_port_group = ProtoField.uint16("fllldp.auto_isl_port_group","auto-isl-port-group",base.DEC)

fllldp.fields.fllldp_trunknamelen = ProtoField.uint8("fllldp.trunknamelen","Trunkname length",base.DEC)
fllldp.fields.fllldp_trunkname = ProtoField.string("fllldp.trunkname", "Trunkname")



function fllldp.dissector(tvb,pinfo,root)

    dprint2("-->")

    local tlv_type_length = tvb(0,2)
    
    local tlv_oui = tvb(2,3)
    local tlv_subtype = tvb(5,1) 
    local tlv_content = tvb(6,tvb:len()-6)

    dprint2(tlv_oui)
    dprint2(tlv_subtype)
    dprint2(tlv_content)
    dprint2("<--")


    -- TLV Header

    if tlv_subtype:uint() == 0x01 then
        tree = root:add(tvb(0,tvb:len()),"FortiSwitch Hostname = " .. tlv_content:string())
    
    elseif tlv_subtype:uint() == 0x02 then
        tree = root:add(tvb(0,tvb:len()),"FortiSwitch Serial = " .. tlv_content:string())
    
    elseif tlv_subtype:uint() == 0x03 then
        tree = root:add(tvb(0,tvb:len()),"FortiSwitch - Link Properties")
    end

    tree:add(fllldp.fields.tlv_type,tlv_type_length)
    tree:add(fllldp.fields.tlv_len,tlv_type_length)
    tree:add(fllldp.fields.tlv_oui,tlv_oui)
    tree:add(fllldp.fields.tlv_flinktype,tlv_subtype)


    -- TLV Content

    if tlv_subtype:uint() == 0x01 then
    
        tree:add(fllldp.fields.hostname,tlv_content)
    
    elseif tlv_subtype:uint() == 0x02 then
    
        tree:add(fllldp.fields.serial,tlv_content)
    
    elseif tlv_subtype:uint() == 0x03 then
    
        local subtree = tree:add(fllldp.fields.fllldp_isl_port_options,tlv_content(0,4))

        subtree:add(fllldp.fields.fllldp_auto_isl,tlv_content(2,2))
        subtree:add(fllldp.fields.fllldp_auto_mclag_isl,tlv_content(2,2))
        subtree:add(fllldp.fields.fllldp_mclag_switch,tlv_content(2,2))
        subtree:add(fllldp.fields.fllldp_isl_fortilink,tlv_content(2,2))
        
        tree:add(fllldp.fields.fllldp_isl_port_group,tlv_content(4,1))
        tree:add(fllldp.fields.fllldp_trunknamelen,tlv_content(5,1))
        tree:add(fllldp.fields.fllldp_trunkname,tlv_content(6,16))
        
    end

end


local lldp_orgtlv_oui_table = DissectorTable.get("lldp.orgtlv.oui")
lldp_orgtlv_oui_table:add(0x085b0e, fllldp)



local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences

fllldp.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function fllldp.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = fllldp.prefs.debug
    reset_debug_level()

end

dprint2("pcapfile Prefs registered")