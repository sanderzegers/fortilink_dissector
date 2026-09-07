-- SPDX-License-Identifier: GPL-2.0-or-later
--
--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 2 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <https://www.gnu.org/licenses/>.

local fortilink_info =
{
    version = "0.4",
    author = "Sander Zegers",
    description = "This plugin parses Fortinet FortiLink packets",
    repository = "https://github.com/"
}

set_plugin_info(fortilink_info)

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

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


local packet_type =
{
    [0x00] = "flp_send_disc_pkt",
    [0x01] = "flp_send_discovery_response",
    [0x02] = "flp_send_join_request",
    [0x03] = "flp_send_join_response",
    [0x04] = "flp_send_echo",
    [0x05] = "flp_send_echo_reply",
    [0x06] = "flp_send_update",
}

local join_response_status =
{
    [0x0000] = "Success",
    [0x0003] = "Error",
}


local tlv_type =
{
    [0x000069] = "flp_fill_faceplate_tv",
    [0x000066] = "flp_fill_port_properties_tlv",
    [0x000064] = "flp_fill_switch_info_tlv",
    [0x000065] = "flp_fill_port_prefix_tlv",
    [0x000067] = "flp_fill_port_properties_with_portname_tlv",
    [0x000068] = "flp_fill_port_properties_with_portname_tlv",
    [0x001234] = "flp_fill_start_tlv",
    [0x005678] = "flp_fill_marker_tlv",
    [0x00cdef] = "flp_fill_marker_tlv",
    [0x00006a] = "flp_fill_port_isl_properties_with_portname_tlv",
    [0x00006b] = "flp_fill_port_fgt_properties_with_portname_tlv",
}

local port_speed =
{
    [0x00000001] = "10half",
    [0x00000002] = "10full",
    [0x00000004] = "100half",
    [0x00000008] = "100full",
    [0x00000010] = "1000full",
    [0x00000020] = "10000full",
    [0x00000040] = "auto",
    [0x00000080] = "1000auto",
    [0x00000100] = "1000full-fiber",
    [0x00000200] = "40000full",
    [0x00000400] = "auto-module",
    [0x00000800] = "100FX-half",
    [0x00001000] = "100FX-full",
    [0x00002000] = "100000full",
    [0x00004000] = "2500auto",
    [0x00008000] = "25000full",
    [0x00010000] = "50000full",
    [0x00020000] = "10000cr",
    [0x00040000] = "10000sr",
    [0x00080000] = "100000sr4",
    [0x00100000] = "100000cr4",
    [0x00200000] = "40000sr4",
    [0x00400000] = "40000cr4",
    [0x02000000] = "25000cr",
    [0x04000000] = "25000sr",
    [0x08000000] = "50000cr",
    [0x10000000] = "50000sr",
    [0x20000000] = "5000auto",
}

--- FortiLink fields

local fortilink = Proto("fortilink", "FortiLink")

fortilink.fields.flversion = ProtoField.uint24("FortiLink.version", "Fortilink Version")
fortilink.fields.flpackettype = ProtoField.uint8("FortiLink.packettype", "Fortilink Packet Type", base.HEX,packet_type)
fortilink.fields.flcontentlength = ProtoField.uint16("FortiLink.contentlength", "Fortilink Packet Content Length")
fortilink.fields.flpacketreserved = ProtoField.uint16("FortiLink.packetreserved", "FortiLink Header Control Word", base.HEX)
fortilink.fields.fsw_header_control = ProtoField.string("FortiLink.header_control.fortiswitch", "FortiSwitch Header Control Interpretation")
-- FortiGate generates this per fortilinkd init from /dev/urandom; FortiSwitch builds observed fixed 0xf1dc.
fortilink.fields.flendpointnonce = ProtoField.uint16("FortiLink.endpoint_nonce", "Endpoint Nonce", base.HEX)

local fortiswitch_header_control = {
    [0x0110] = "ordinary node (controller-connected state)",
    [0x0114] = "ordinary node; ISL-controller condition present",
    [0x0190] = "internal fallback node (controller-disconnected state)",
    [0x0194] = "internal fallback node; ISL-controller condition present",
}



fortilink.fields.send_echo = ProtoField.bytes('FortiLink.send_echo', 'Echo')
fortilink.fields.flp_src_serial = ProtoField.string("FortiLink.src_serial", "Source Serial")
fortilink.fields.flp_src_interface  = ProtoField.string("FortiLink.src_interface", "Source Interface")
fortilink.fields.flp_dst_serial = ProtoField.string("FortiLink.dst_serial", "Destination Serial")
fortilink.fields.flp_dst_interface = ProtoField.string("FortiLink.dst_interface", "Destination Interface")

fortilink.fields.send_echo_reply = ProtoField.bytes('FortiLink.send_echo_reply', 'Echo Reply')
fortilink.fields.join_response_status = ProtoField.uint16("FortiLink.join_response.status", "Join Response Status", base.DEC, join_response_status)
fortilink.fields.message_data = ProtoField.bytes("FortiLink.message_data", "Undecoded Message Data")
fortilink.fields.trailing_data = ProtoField.bytes("FortiLink.trailing_data", "Trailing Protocol Data")
fortilink.fields.padding = ProtoField.bytes("FortiLink.padding", "Ethernet Padding")

fortilink.fields.flp_send_update_src_serial = ProtoField.string("FortiLink.send_update.src_serial", "Source Serial")
fortilink.fields.flp_send_update_src_interface  = ProtoField.string("FortiLink.send_update.src_interface", "Source Interface")

fortilink.fields.flp_send_disc_resp_static  = ProtoField.uint32("FortiLink.send_discover_response.static1","Static Value?")


-- TLVs

fortilink.fields.flp_tlv_type  = ProtoField.uint16("FortiLink.tlv_type", "TLV Type", base.HEX, tlv_type)
fortilink.fields.flp_tlv_length  = ProtoField.uint16("FortiLink.tlv_length", "TLV Length", base.DEC)

fortilink.fields.flp_start_tlv_data  = ProtoField.bytes("FortiLink.start_tlv.data", "Data")
fortilink.fields.faceplate_data  = ProtoField.string("FortiLink.faceplate_data", "Faceplate XML")

fortilink.fields.tlv = ProtoField.bytes('FortiLink.tlv', 'TLV')
fortilink.fields.tlv_value = ProtoField.bytes("FortiLink.tlv_value", "TLV Value")

fortilink.fields.tlv_portname  = ProtoField.string("FortiLink.tlv_portname", "Portname")
fortilink.fields.tlv_portid  = ProtoField.uint16("FortiLink.tlv_portid", "Port ID")
fortilink.fields.tlv_portproperties  = ProtoField.uint32("FortiLink.tlv_portproperties", "Port Properties", base.HEX)
fortilink.fields.tlv_portproperties_fortilink = ProtoField.bool("FortiLink.tlv_portproperties.fortilink", "FortiLink", 32, nil, 0x00000001)
fortilink.fields.tlv_portproperties_isl = ProtoField.bool("FortiLink.tlv_portproperties.isl", "ISL", 32, nil, 0x00000010)
fortilink.fields.tlv_portproperties_icl = ProtoField.bool("FortiLink.tlv_portproperties.icl", "ICL", 32, nil, 0x00000020)
fortilink.fields.tlv_portproperty_byte  = ProtoField.uint8("FortiLink.tlv_portproperty_byte", "Port Property Byte", base.HEX)
fortilink.fields.tlv_port_default_speed  = ProtoField.uint32("FortiLink.tlv_port_default_speed", "Default Speed", base.HEX, port_speed)
fortilink.fields.tlv_port_available_speeds  = ProtoField.uint32("FortiLink.tlv_port_available_speeds", "Available Speeds", base.HEX)
fortilink.fields.tlv_port_speed_10half = ProtoField.bool("FortiLink.tlv_port_available_speeds.10half", "10 Mbps Half-Duplex", 32, nil, 0x00000001)
fortilink.fields.tlv_port_speed_10full = ProtoField.bool("FortiLink.tlv_port_available_speeds.10full", "10 Mbps Full-Duplex", 32, nil, 0x00000002)
fortilink.fields.tlv_port_speed_100half = ProtoField.bool("FortiLink.tlv_port_available_speeds.100half", "100 Mbps Half-Duplex", 32, nil, 0x00000004)
fortilink.fields.tlv_port_speed_100full = ProtoField.bool("FortiLink.tlv_port_available_speeds.100full", "100 Mbps Full-Duplex", 32, nil, 0x00000008)
fortilink.fields.tlv_port_speed_1000full = ProtoField.bool("FortiLink.tlv_port_available_speeds.1000full", "1 Gbps Full-Duplex", 32, nil, 0x00000010)
fortilink.fields.tlv_port_speed_10000full = ProtoField.bool("FortiLink.tlv_port_available_speeds.10000full", "10 Gbps Full-Duplex", 32, nil, 0x00000020)
fortilink.fields.tlv_port_speed_auto = ProtoField.bool("FortiLink.tlv_port_available_speeds.auto", "Auto-Negotiation", 32, nil, 0x00000040)
fortilink.fields.tlv_port_speed_1000auto = ProtoField.bool("FortiLink.tlv_port_available_speeds.1000auto", "1 Gbps Auto-Negotiation", 32, nil, 0x00000080)
fortilink.fields.tlv_port_speed_1000full_fiber = ProtoField.bool("FortiLink.tlv_port_available_speeds.1000full_fiber", "1 Gbps Full-Duplex (Fiber)", 32, nil, 0x00000100)
fortilink.fields.tlv_port_speed_40000full = ProtoField.bool("FortiLink.tlv_port_available_speeds.40000full", "40 Gbps Full-Duplex", 32, nil, 0x00000200)
fortilink.fields.tlv_port_speed_auto_module = ProtoField.bool("FortiLink.tlv_port_available_speeds.auto_module", "Module Maximum Speed", 32, nil, 0x00000400)
fortilink.fields.tlv_port_speed_100fx_half = ProtoField.bool("FortiLink.tlv_port_available_speeds.100fx_half", "100BASE-FX Half-Duplex", 32, nil, 0x00000800)
fortilink.fields.tlv_port_speed_100fx_full = ProtoField.bool("FortiLink.tlv_port_available_speeds.100fx_full", "100BASE-FX Full-Duplex", 32, nil, 0x00001000)
fortilink.fields.tlv_port_speed_100000full = ProtoField.bool("FortiLink.tlv_port_available_speeds.100000full", "100 Gbps Full-Duplex", 32, nil, 0x00002000)
fortilink.fields.tlv_port_speed_2500auto = ProtoField.bool("FortiLink.tlv_port_available_speeds.2500auto", "2.5 Gbps Auto-Negotiation", 32, nil, 0x00004000)
fortilink.fields.tlv_port_speed_25000full = ProtoField.bool("FortiLink.tlv_port_available_speeds.25000full", "25 Gbps Full-Duplex", 32, nil, 0x00008000)
fortilink.fields.tlv_port_speed_50000full = ProtoField.bool("FortiLink.tlv_port_available_speeds.50000full", "50 Gbps Full-Duplex", 32, nil, 0x00010000)
fortilink.fields.tlv_port_speed_10000cr = ProtoField.bool("FortiLink.tlv_port_available_speeds.10000cr", "10 Gbps CR", 32, nil, 0x00020000)
fortilink.fields.tlv_port_speed_10000sr = ProtoField.bool("FortiLink.tlv_port_available_speeds.10000sr", "10 Gbps SR", 32, nil, 0x00040000)
fortilink.fields.tlv_port_speed_100000sr4 = ProtoField.bool("FortiLink.tlv_port_available_speeds.100000sr4", "100 Gbps SR4", 32, nil, 0x00080000)
fortilink.fields.tlv_port_speed_100000cr4 = ProtoField.bool("FortiLink.tlv_port_available_speeds.100000cr4", "100 Gbps CR4", 32, nil, 0x00100000)
fortilink.fields.tlv_port_speed_40000sr4 = ProtoField.bool("FortiLink.tlv_port_available_speeds.40000sr4", "40 Gbps SR4", 32, nil, 0x00200000)
fortilink.fields.tlv_port_speed_40000cr4 = ProtoField.bool("FortiLink.tlv_port_available_speeds.40000cr4", "40 Gbps CR4", 32, nil, 0x00400000)
fortilink.fields.tlv_port_speed_25000cr = ProtoField.bool("FortiLink.tlv_port_available_speeds.25000cr", "25 Gbps CR", 32, nil, 0x02000000)
fortilink.fields.tlv_port_speed_25000sr = ProtoField.bool("FortiLink.tlv_port_available_speeds.25000sr", "25 Gbps SR", 32, nil, 0x04000000)
fortilink.fields.tlv_port_speed_50000cr = ProtoField.bool("FortiLink.tlv_port_available_speeds.50000cr", "50 Gbps CR", 32, nil, 0x08000000)
fortilink.fields.tlv_port_speed_50000sr = ProtoField.bool("FortiLink.tlv_port_available_speeds.50000sr", "50 Gbps SR", 32, nil, 0x10000000)
fortilink.fields.tlv_port_speed_5000auto = ProtoField.bool("FortiLink.tlv_port_available_speeds.5000auto", "5 Gbps Auto-Negotiation", 32, nil, 0x20000000)
fortilink.fields.tlv_port_extension  = ProtoField.bytes("FortiLink.tlv_port_extension", "Unresolved Port Properties Extension")
fortilink.fields.tlv_port_extension_class = ProtoField.uint32("FortiLink.tlv_port_extension.class", "Extended Port Class (Unresolved)", base.HEX)
fortilink.fields.tlv_port_extension_speed_mask = ProtoField.uint64("FortiLink.tlv_port_extension.speed_mask", "Extended Available Speeds (Inferred)", base.HEX)

local port_available_speed_fields =
{
    fortilink.fields.tlv_port_speed_10half,
    fortilink.fields.tlv_port_speed_10full,
    fortilink.fields.tlv_port_speed_100half,
    fortilink.fields.tlv_port_speed_100full,
    fortilink.fields.tlv_port_speed_1000full,
    fortilink.fields.tlv_port_speed_10000full,
    fortilink.fields.tlv_port_speed_auto,
    fortilink.fields.tlv_port_speed_1000auto,
    fortilink.fields.tlv_port_speed_1000full_fiber,
    fortilink.fields.tlv_port_speed_40000full,
    fortilink.fields.tlv_port_speed_auto_module,
    fortilink.fields.tlv_port_speed_100fx_half,
    fortilink.fields.tlv_port_speed_100fx_full,
    fortilink.fields.tlv_port_speed_100000full,
    fortilink.fields.tlv_port_speed_2500auto,
    fortilink.fields.tlv_port_speed_25000full,
    fortilink.fields.tlv_port_speed_50000full,
    fortilink.fields.tlv_port_speed_10000cr,
    fortilink.fields.tlv_port_speed_10000sr,
    fortilink.fields.tlv_port_speed_100000sr4,
    fortilink.fields.tlv_port_speed_100000cr4,
    fortilink.fields.tlv_port_speed_40000sr4,
    fortilink.fields.tlv_port_speed_40000cr4,
    fortilink.fields.tlv_port_speed_25000cr,
    fortilink.fields.tlv_port_speed_25000sr,
    fortilink.fields.tlv_port_speed_50000cr,
    fortilink.fields.tlv_port_speed_50000sr,
    fortilink.fields.tlv_port_speed_5000auto,
}

local port_property_fields =
{
    fortilink.fields.tlv_portproperties_fortilink,
    fortilink.fields.tlv_portproperties_isl,
    fortilink.fields.tlv_portproperties_icl,
}


fortilink.fields.tlv_magicinfo  = ProtoField.uint16("FortiLink.magicinfo", "Magic Info", base.HEX)
fortilink.fields.tlv_capabillity_flag  = ProtoField.uint32("FortiLink.capabillity_flag", "Capability Flags", base.HEX)
fortilink.fields.tlv_maxports  = ProtoField.uint16("FortiLink.maxports", "Max ports")
fortilink.fields.tlv_multiuplink  = ProtoField.uint8("FortiLink.multiuplink", "Multiuplink")
fortilink.fields.tlv_uplink1  = ProtoField.string("FortiLink.uplink1", "Uplink 1")
fortilink.fields.tlv_uplink2  = ProtoField.string("FortiLink.uplink2", "Uplink 2")

fortilink.fields.tlv_isl_properties  = ProtoField.uint32("FortiLink.tlv_isl.properties", "Trunk Properties",base.HEX)
fortilink.fields.tlv_isl_properties_fortilink = ProtoField.bool("FortiLink.tlv_isl.properties.fortilink","FortiLink",32,nil,0x1)
fortilink.fields.tlv_isl_properties_auto_isl = ProtoField.bool("FortiLink.tlv_isl.properties.auto-isl","Auto-ISL",32,nil,0x10)
fortilink.fields.tlv_isl_properties_mclag_icl = ProtoField.bool("FortiLink.tlv_isl.properties.mclag-icl","MCLAG ICL",32,nil,0x20)


fortilink.fields.tlv_isl_port  = ProtoField.string("FortiLink.tlv_isl.port", "Port")
fortilink.fields.tlv_isl_trunk  = ProtoField.string("FortiLink.tlv_isl.trunk", "Trunk")
fortilink.fields.tlv_isl_peer_port  = ProtoField.string("FortiLink.tlv_isl.peer_port", "Peer Port")
fortilink.fields.tlv_isl_peer_device  = ProtoField.string("FortiLink.tlv_isl.peer_device", "Peer Device")

fortilink.fields.tlv_fgt_port_properties  = ProtoField.uint32("FortiLink.tlv_fgt_prop.properties", "Properties", base.HEX)
fortilink.fields.tlv_fgt_port_port  = ProtoField.string("FortiLink.tlv_fgt_prop.port", "Port")
fortilink.fields.tlv_fgt_port_fgt_port  = ProtoField.string("FortiLink.tlv_fgt_prop.fgt_port", "FortiGate Port")
fortilink.fields.tlv_fgt_port_fgt_device  = ProtoField.string("FortiLink.tlv_fgt_prop.fgt_device", "FortiGate Device")

fortilink.experts.malformed = ProtoExpert.new("fortilink.malformed", "Malformed FortiLink data", expert.group.MALFORMED, expert.severity.ERROR)
fortilink.experts.length_mismatch = ProtoExpert.new("fortilink.length_mismatch", "FortiLink length mismatch", expert.group.MALFORMED, expert.severity.WARN)



--- TLVs for Update Packets

local function add_malformed(tree, message)
    tree:add_proto_expert_info(fortilink.experts.malformed, message)
end

local function add_tlv_tree(buffer, tree, label, minimum_length, show_raw_value)
    local subtree = tree:add(fortilink.fields.tlv, buffer(), label)
    subtree:set_text(label)
    subtree:add(fortilink.fields.flp_tlv_type, buffer(0,2))
    subtree:add(fortilink.fields.flp_tlv_length, buffer(2,2))
    if show_raw_value and buffer:len() > 4 then
        subtree:add(fortilink.fields.tlv_value, buffer(4,buffer:len()-4))
    end
    if minimum_length and buffer:len() < minimum_length then
        add_malformed(subtree, string.format("%s needs at least %d bytes; only %d available", label, minimum_length, buffer:len()))
        return subtree, false
    end
    return subtree, true
end

local function dissect_faceplate_tlv(buffer, tree)
    local subtree = add_tlv_tree(buffer, tree, "Faceplate TLV")
    if buffer:len() > 4 then
        subtree:add(fortilink.fields.faceplate_data, buffer(4,buffer:len()-4))
    end
end

local function dissect_port_properties_tlv(buffer, tree)
    local subtree = add_tlv_tree(buffer, tree, "Port Properties TLV")
    if buffer:len() > 4 then
        subtree:add(fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
    end
end

local function dissect_switch_info_tlv(buffer, tree)
    local subtree, complete = add_tlv_tree(buffer, tree, "Switch Info TLV", 90)
    if not complete then return end
    subtree:add(fortilink.fields.tlv_magicinfo, buffer(4,2))
    subtree:add(fortilink.fields.tlv_maxports, buffer(6,2))
    subtree:add(fortilink.fields.tlv_multiuplink, buffer(8,1))
    subtree:add(fortilink.fields.tlv_uplink1, buffer(9,37))
    subtree:add(fortilink.fields.tlv_uplink2, buffer(46,37))
    subtree:add(fortilink.fields.tlv_capabillity_flag, buffer(86,4))
end

local function dissect_data_tlv(buffer, tree, label)
    local subtree = add_tlv_tree(buffer, tree, label)
    if buffer:len() > 4 then
        subtree:add(fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
    end
end

local function dissect_port_prefix_tlv(buffer, tree)
    dissect_data_tlv(buffer, tree, "Port Prefix TLV")
end

local function dissect_start_tlv(buffer, tree)
    dissect_data_tlv(buffer, tree, "Start TLV")
end

local function dissect_marker_tlv(buffer, tree)
    add_tlv_tree(buffer, tree, "Marker TLV")
end

local function dissect_named_port_properties_tlv(buffer, tree)
    local subtree, complete = add_tlv_tree(buffer, tree, "Named Port Properties TLV", 36)
    if not complete then return end
    local properties = subtree:add(fortilink.fields.tlv_portproperties, buffer(4,4))
    for _, property_field in ipairs(port_property_fields) do
        properties:add(property_field, buffer(4,4))
    end
    subtree:add(fortilink.fields.tlv_portproperty_byte, buffer(8,1))
    subtree:add(fortilink.fields.tlv_portid, buffer(9,2))
    subtree:add(fortilink.fields.tlv_portname, buffer(11,17))
    subtree:add(fortilink.fields.tlv_port_default_speed, buffer(28,4))
    local available_speeds = subtree:add(fortilink.fields.tlv_port_available_speeds, buffer(32,4))
    for _, speed_field in ipairs(port_available_speed_fields) do
        available_speeds:add(speed_field, buffer(32,4))
    end
    if buffer:len() > 36 then
        local extension = subtree:add(fortilink.fields.tlv_port_extension, buffer(36,buffer:len()-36))
        if buffer:len() >= 48 then
            extension:add(fortilink.fields.tlv_port_extension_class, buffer(36,4))
            extension:add(fortilink.fields.tlv_port_extension_speed_mask, buffer(40,8))
        end
    end
end

local function dissect_isl_properties_tlv(buffer, tree)
    local subtree, complete = add_tlv_tree(buffer, tree, "ISL Properties TLV", 76)
    if not complete then return end
    local properties = subtree:add(fortilink.fields.tlv_isl_properties, buffer(4,4))
    properties:add(fortilink.fields.tlv_isl_properties_fortilink, buffer(4,4))
    properties:add(fortilink.fields.tlv_isl_properties_auto_isl, buffer(4,4))
    properties:add(fortilink.fields.tlv_isl_properties_mclag_icl, buffer(4,4))
    subtree:add(fortilink.fields.tlv_isl_port, buffer(8,17))
    subtree:add(fortilink.fields.tlv_isl_trunk, buffer(25,17))
    subtree:add(fortilink.fields.tlv_isl_peer_port, buffer(42,17))
    subtree:add(fortilink.fields.tlv_isl_peer_device, buffer(59,17))
end

local function dissect_fgt_properties_tlv(buffer, tree)
    local subtree, complete = add_tlv_tree(buffer, tree, "FortiGate Properties TLV", 59)
    if not complete then return end
    subtree:add(fortilink.fields.tlv_fgt_port_properties, buffer(4,4))
    subtree:add(fortilink.fields.tlv_fgt_port_port, buffer(8,17))
    subtree:add(fortilink.fields.tlv_fgt_port_fgt_port, buffer(25,17))
    subtree:add(fortilink.fields.tlv_fgt_port_fgt_device, buffer(42,17))
end

local tlv_type_function =
{
    [0x000069] = dissect_faceplate_tlv,
    [0x000066] = dissect_port_properties_tlv,
    [0x000064] = dissect_switch_info_tlv,
    [0x000065] = dissect_port_prefix_tlv,
    [0x000067] = dissect_named_port_properties_tlv,
    [0x000068] = dissect_named_port_properties_tlv,
    [0x001234] = dissect_start_tlv,
    [0x005678] = dissect_marker_tlv,
    [0x00cdef] = dissect_marker_tlv,
    [0x00006a] = dissect_isl_properties_tlv,
    [0x00006b] = dissect_fgt_properties_tlv,
}



local function add_message_bytes(buffer, protocol_end, offset, field, tree)
    if protocol_end > offset then
        tree:add(field, buffer(offset,protocol_end-offset))
    end
end

local function add_fixed_string(buffer, protocol_end, offset, length, field, tree, label)
    if protocol_end <= offset then
        add_malformed(tree, string.format("%s is missing", label))
        return false
    end
    local available = math.min(length, protocol_end-offset)
    tree:add(field, buffer(offset,available))
    if available < length then
        add_malformed(tree, string.format("%s needs %d bytes; only %d available", label, length, available))
        return false
    end
    return true
end

local function dissect_tlvs(buffer, offset, protocol_end, tree)
    local counter = offset
    while counter < protocol_end do
        local remaining = protocol_end-counter
        if remaining < 4 then
            tree:add(fortilink.fields.trailing_data, buffer(counter,remaining))
            add_malformed(tree, string.format("TLV header needs 4 bytes; only %d available", remaining))
            return
        end

        local tlv_id = buffer(counter,2):uint()
        local tlv_length = buffer(counter+2,2):uint()
        local total_length = 4+tlv_length
        dprint2(string.format("tlv_id: %04x length: %d", tlv_id, tlv_length))

        if total_length > remaining then
            local truncated = buffer(counter,remaining)
            local subtree = add_tlv_tree(truncated, tree, string.format("Truncated TLV 0x%04x", tlv_id), nil, true)
            add_malformed(subtree, string.format("TLV 0x%04x declares %d value bytes; only %d available", tlv_id, tlv_length, remaining-4))
            return
        end

        local tlv_buffer = buffer(counter,total_length)
        local decoder = tlv_type_function[tlv_id]
        if decoder then
            decoder(tlv_buffer, tree)
        else
            add_tlv_tree(tlv_buffer, tree, string.format("Unknown TLV 0x%04x", tlv_id), nil, true)
        end
        counter = counter+total_length
    end
end

local function dissect_tlv_message(buffer, pinfo, tree, protocol_end, info)
    pinfo.cols.info = info
    local serial_ok = add_fixed_string(buffer, protocol_end, 10, 32, fortilink.fields.flp_src_serial, tree, "Source serial")
    local interface_ok = add_fixed_string(buffer, protocol_end, 42, 32, fortilink.fields.flp_src_interface, tree, "Source interface")
    if serial_ok and interface_ok then
        dissect_tlvs(buffer, 74, protocol_end, tree)
    end
end

local function dissect_send_discovery(buffer, pinfo, tree, protocol_end)
    dissect_tlv_message(buffer, pinfo, tree, protocol_end, "Discovery")
end

local function dissect_send_update(buffer, pinfo, tree, protocol_end)
    dissect_tlv_message(buffer, pinfo, tree, protocol_end, "Update")
end

local function dissect_send_echo(buffer, pinfo, tree, protocol_end)
    pinfo.cols.info = "Echo Request"
    if protocol_end > 10 then
        tree:add(fortilink.fields.message_data, buffer(10,math.min(2,protocol_end-10)))
    end
    add_fixed_string(buffer, protocol_end, 12, 32, fortilink.fields.flp_src_serial, tree, "Source serial")
    add_fixed_string(buffer, protocol_end, 44, 32, fortilink.fields.flp_src_interface, tree, "Source interface")
    add_fixed_string(buffer, protocol_end, 76, 32, fortilink.fields.flp_dst_serial, tree, "Destination serial")
    add_fixed_string(buffer, protocol_end, 108, 32, fortilink.fields.flp_dst_interface, tree, "Destination interface")
end

local function dissect_send_echo_reply(buffer, pinfo, tree, protocol_end)
    pinfo.cols.info = "Echo Reply"
    add_message_bytes(buffer, protocol_end, 10, fortilink.fields.send_echo_reply, tree)
end

local function dissect_send_join_request(buffer, pinfo, tree, protocol_end)
    pinfo.cols.info = "Join Request"
    add_fixed_string(buffer, protocol_end, 10, 32, fortilink.fields.flp_src_serial, tree, "Source serial")
    add_fixed_string(buffer, protocol_end, 42, 32, fortilink.fields.flp_src_interface, tree, "Source interface")
    add_fixed_string(buffer, protocol_end, 74, 32, fortilink.fields.flp_dst_serial, tree, "Destination serial")
    add_fixed_string(buffer, protocol_end, 106, 32, fortilink.fields.flp_dst_interface, tree, "Destination interface")
    add_message_bytes(buffer, protocol_end, 138, fortilink.fields.trailing_data, tree)
end

local function dissect_send_join_response(buffer, pinfo, tree, protocol_end)
    pinfo.cols.info = "Join Response"
    if protocol_end >= 12 then
        tree:add(fortilink.fields.join_response_status, buffer(10,2))
        add_message_bytes(buffer, protocol_end, 12, fortilink.fields.trailing_data, tree)
    else
        add_message_bytes(buffer, protocol_end, 10, fortilink.fields.message_data, tree)
        add_malformed(tree, string.format("Join response status needs 2 bytes; only %d available", math.max(0,protocol_end-10)))
    end
end

local function dissect_send_discovery_response(buffer, pinfo, tree, protocol_end)
    pinfo.cols.info = "Discovery Response"
    if protocol_end > 10 then
        tree:add(fortilink.fields.message_data, buffer(10,math.min(2,protocol_end-10)))
    end
    add_fixed_string(buffer, protocol_end, 12, 32, fortilink.fields.flp_src_serial, tree, "Source serial")
    add_fixed_string(buffer, protocol_end, 44, 32, fortilink.fields.flp_src_interface, tree, "Source interface")
    add_fixed_string(buffer, protocol_end, 76, 32, fortilink.fields.flp_dst_serial, tree, "Destination serial")
    add_fixed_string(buffer, protocol_end, 108, 32, fortilink.fields.flp_dst_interface, tree, "Destination interface")
    if protocol_end >= 144 then
        tree:add(fortilink.fields.flp_send_disc_resp_static, buffer(140,4))
    else
        add_malformed(tree, string.format("Discovery response needs 144 bytes; only %d available", protocol_end))
    end
end

local packet_dissectors = {
    [0x00] = dissect_send_discovery,
    [0x01] = dissect_send_discovery_response,
    [0x02] = dissect_send_join_request,
    [0x03] = dissect_send_join_response,
    [0x04] = dissect_send_echo,
    [0x05] = dissect_send_echo_reply,
    [0x06] = dissect_send_update,
}

function fortilink.dissector(buffer, pinfo, root)
    local captured_length = buffer:len()
    pinfo.cols.protocol = fortilink.name

    if captured_length < 8 then
        local short_tree = root:add(fortilink, buffer(), "FortiLink - Truncated Header")
        if captured_length > 0 then
            short_tree:add(fortilink.fields.message_data, buffer())
        end
        add_malformed(short_tree, string.format("FortiLink header needs 8 bytes; only %d available", captured_length))
        return
    end

    local content_length = buffer(4,2):uint()
    local declared_end = 8+content_length
    local protocol_end = math.min(captured_length, declared_end)
    local subtree = root:add(fortilink, buffer(0,protocol_end), "FortiLink")
    subtree:add(fortilink.fields.flversion, buffer(0,3))
    subtree:add(fortilink.fields.flpackettype, buffer(3,1))
    subtree:add(fortilink.fields.flcontentlength, buffer(4,2))
    subtree:add(fortilink.fields.flpacketreserved, buffer(6,2))
    local header_control = buffer(6,2):uint()
    local fortiswitch_interpretation = fortiswitch_header_control[header_control]
    if fortiswitch_interpretation then
        subtree:add(fortilink.fields.fsw_header_control, buffer(6,2), fortiswitch_interpretation)
    end

    if captured_length < declared_end then
        subtree:add_proto_expert_info(fortilink.experts.length_mismatch,
            string.format("FortiLink content declares %d bytes through offset %d; only %d bytes were captured", content_length, declared_end, captured_length))
    end

    if protocol_end < 10 then
        add_malformed(subtree, string.format("FortiLink content must contain the 2-byte endpoint nonce; only %d content bytes available", math.max(0,protocol_end-8)))
        if captured_length > declared_end then
            subtree:add(fortilink.fields.padding, buffer(declared_end,captured_length-declared_end))
        end
        return
    end
    subtree:add(fortilink.fields.flendpointnonce, buffer(8,2))

    local packet_id = buffer(3,1):uint()
    local decoder = packet_dissectors[packet_id]
    if decoder then
        decoder(buffer, pinfo, subtree, protocol_end)
    else
        pinfo.cols.info = string.format("Unknown FortiLink Packet Type 0x%02x", packet_id)
        add_message_bytes(buffer, protocol_end, 10, fortilink.fields.message_data, subtree)
    end

    if captured_length > declared_end then
        subtree:add(fortilink.fields.padding, buffer(declared_end,captured_length-declared_end))
    end
end

local ether_table = DissectorTable.get("ethertype")
ether_table:add(0x88ff, fortilink)


local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences

fortilink.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function fortilink.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = fortilink.prefs.debug
    reset_debug_level()

end

dprint2("pcapfile Prefs registered")
