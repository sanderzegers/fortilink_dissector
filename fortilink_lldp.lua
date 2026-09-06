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
    version = "0.5",
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
    debug_level  = debug_level.DISABLED,
}


local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    dprint = function() end
    dprint2 = function() end

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

local isl_trunk_mode_selectors =
{
    [0x00] = "Static/non-LACP",
    [0x01] = "LACP active, slow",
    [0x02] = "LACP active, fast",
    [0x03] = "Static/non-LACP (alternate encoding)",
}

-- Lua 5.4 removed the bit32 library. Keep option masking compatible with
-- Wireshark builds using Lua 5.2 through 5.4.
local function clear_option_bits(value,mask)
    local bit_value = 1

    while mask > 0 do
        if mask % 2 == 1 and math.floor(value / bit_value) % 2 == 1 then
            value = value - bit_value
        end
        mask = math.floor(mask / 2)
        bit_value = bit_value * 2
    end

    return value
end


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
fllldp.fields.fllldp_auto_isl = ProtoField.bool("fllldp.auto_isl","auto-isl",32,nil,0x1)
 -- Create auto mclag isl between switches:
 fllldp.fields.fllldp_auto_mclag_isl = ProtoField.bool("fllldp.auto_mclag_isl","auto-mclag-icl",32,nil,0x2)
 -- Switch is already configured as MCLAG switch:
 fllldp.fields.fllldp_mclag_switch = ProtoField.bool("fllldp.is_mclag_switch","mclag-switch",32,nil,0x4)
 -- Switch requests ISL-Fortilink
 fllldp.fields.fllldp_isl_fortilink = ProtoField.bool("fllldp.isl_fortilink","isl-fortilink",32,nil,0x10)
 fllldp.fields.fllldp_trunk_mode_selector = ProtoField.uint32("fllldp.trunk_mode_selector","Trunk mode selector",base.DEC,isl_trunk_mode_selectors,0x60)
 fllldp.fields.fllldp_loop_guard = ProtoField.bool("fllldp.loop_guard","Loop guard",32,nil,0x80)
 fllldp.fields.fllldp_trunk_flags = ProtoField.uint32("fllldp.trunk_flags","Legacy grouped trunk flags",base.HEX,nil,0xe0)
 fllldp.fields.fllldp_fortilink_trunk = ProtoField.bool("fllldp.fortilink_trunk","FortiLink trunk mode",32,nil,0x100)
 fllldp.fields.fllldp_auto_network = ProtoField.bool("fllldp.auto_network","Auto-network enabled",32,nil,0x200)
 fllldp.fields.fllldp_p2p = ProtoField.bool("fllldp.p2p","P2P mode",32,nil,0x400)
 fllldp.fields.fllldp_static_isl = ProtoField.bool("fllldp.static_isl","Static ISL",32,nil,0x800)
 fllldp.fields.fllldp_mrp = ProtoField.bool("fllldp.mrp","MRP mode",32,nil,0x2000)
 fllldp.fields.fllldp_unknown_options = ProtoField.uint32("fllldp.unknown_options","Unknown option bits",base.HEX)



fllldp.fields.fllldp_isl_port_group = ProtoField.uint8("fllldp.auto_isl_port_group","auto-isl-port-group",base.DEC)

fllldp.fields.fllldp_peer_id_len = ProtoField.uint8("fllldp.peer_id_len","Peer switch identifier length",base.DEC)
fllldp.fields.fllldp_peer_id = ProtoField.string("fllldp.peer_id", "Peer switch identifier")
fllldp.fields.fllldp_trailing_data = ProtoField.bytes("fllldp.trailing_data", "Trailing data")

fllldp.experts.too_short = ProtoExpert.new("fllldp.too_short", "FortiLink LLDP TLV is too short", expert.group.MALFORMED, expert.severity.ERROR)
fllldp.experts.peer_id_truncated = ProtoExpert.new("fllldp.peer_id_truncated", "Peer switch identifier is truncated", expert.group.MALFORMED, expert.severity.ERROR)



function fllldp.dissector(tvb,pinfo,root)

    dprint2("-->")

    if tvb:len() < 6 then
        local short_tree = root:add(fllldp,tvb(),"FortiLink LLDP - Truncated")
        short_tree:add_proto_expert_info(fllldp.experts.too_short,
            string.format("FortiLink organizational TLV needs at least 6 bytes; only %d available",tvb:len()))
        if tvb:len() > 0 then
            short_tree:add(fllldp.fields.tlv_content,tvb())
        end
        return
    end

    local tlv_type_length = tvb(0,2)
    
    local tlv_oui = tvb(2,3)
    local tlv_subtype = tvb(5,1) 
    local tlv_content = tvb(6,tvb:len()-6)
    local subtype = tlv_subtype:uint()

    dprint2(tlv_oui)
    dprint2(tlv_subtype)
    dprint2(tlv_content)
    dprint2("<--")


    -- TLV Header

    local tree

    if subtype == 0x01 then
        tree = root:add(tvb(0,tvb:len()),"FortiSwitch Hostname = " .. tlv_content:string())
    
    elseif subtype == 0x02 then
        tree = root:add(tvb(0,tvb:len()),"FortiSwitch Serial = " .. tlv_content:string())
    
    elseif subtype == 0x03 then
        tree = root:add(tvb(0,tvb:len()),"FortiSwitch - Link Properties")
    else
        tree = root:add(tvb(0,tvb:len()),string.format("FortiSwitch - Unknown subtype 0x%02x", subtype))
    end

    tree:add(fllldp.fields.tlv_type,tlv_type_length)
    tree:add(fllldp.fields.tlv_len,tlv_type_length)
    tree:add(fllldp.fields.tlv_oui,tlv_oui)
    tree:add(fllldp.fields.tlv_flinktype,tlv_subtype)


    -- TLV Content

    if subtype == 0x01 then
    
        tree:add(fllldp.fields.hostname,tlv_content)
    
    elseif subtype == 0x02 then
    
        tree:add(fllldp.fields.serial,tlv_content)
    
    elseif subtype == 0x03 then

        if tlv_content:len() < 6 then
            tree:add(fllldp.fields.tlv_content,tlv_content)
            tree:add_proto_expert_info(fllldp.experts.too_short,
                string.format("FortiLink link-properties payload needs at least 6 bytes; only %d available",tlv_content:len()))
            return
        end

        local options_range = tlv_content(0,4)
        local subtree = tree:add(fllldp.fields.fllldp_isl_port_options,options_range)

        subtree:add(fllldp.fields.fllldp_auto_isl,options_range)
        subtree:add(fllldp.fields.fllldp_auto_mclag_isl,options_range)
        subtree:add(fllldp.fields.fllldp_mclag_switch,options_range)
        subtree:add(fllldp.fields.fllldp_isl_fortilink,options_range)
        subtree:add(fllldp.fields.fllldp_trunk_mode_selector,options_range)
        subtree:add(fllldp.fields.fllldp_loop_guard,options_range)
        subtree:add(fllldp.fields.fllldp_trunk_flags,options_range):set_hidden()
        subtree:add(fllldp.fields.fllldp_fortilink_trunk,options_range)
        subtree:add(fllldp.fields.fllldp_auto_network,options_range)
        subtree:add(fllldp.fields.fllldp_p2p,options_range)
        subtree:add(fllldp.fields.fllldp_static_isl,options_range)
        subtree:add(fllldp.fields.fllldp_mrp,options_range)
        local unknown_options = clear_option_bits(options_range:uint(),0x2ff7)
        subtree:add(fllldp.fields.fllldp_unknown_options,options_range,unknown_options)

        tree:add(fllldp.fields.fllldp_isl_port_group,tlv_content(4,1))

        local trunkname_len_range = tlv_content(5,1)
        local trunkname_len = trunkname_len_range:uint()
        local available_len = tlv_content:len() - 6
        local displayed_len = math.min(trunkname_len,available_len)

        local peer_id_len_item = tree:add(fllldp.fields.fllldp_peer_id_len,trunkname_len_range)
        if trunkname_len > available_len then
            peer_id_len_item:add_proto_expert_info(fllldp.experts.peer_id_truncated,
                string.format("Peer switch identifier declares %d bytes; only %d available",trunkname_len,available_len))
        end
        if displayed_len > 0 then
            local peer_id_range = tlv_content(6,displayed_len)
            tree:add(fllldp.fields.fllldp_peer_id,peer_id_range)
        end
        if available_len > trunkname_len then
            tree:add(fllldp.fields.fllldp_trailing_data,
                tlv_content(6 + trunkname_len,available_len - trunkname_len))
        end
    else
        tree:add(fllldp.fields.tlv_content,tlv_content)
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
