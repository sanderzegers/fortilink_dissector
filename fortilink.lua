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

local fortilink_info =
{
    version = "0.3",
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

--- FortiLink fields

local fortilink = Proto("fortilink", "FortiLink")

fortilink.fields.flversion = ProtoField.uint24("FortiLink.version", "Fortilink Version")
fortilink.fields.flpackettype = ProtoField.uint8("FortiLink.packettype", "Fortilink Packet Type", base.HEX,packet_type)
fortilink.fields.flcontentlength = ProtoField.uint16("FortiLink.contentlength", "Fortilink Packet Content Length")
fortilink.fields.flpacketreserved = ProtoField.uint16("FortiLink.packetreserved", "Fortilink Packet Reserved", base.HEX)
-- FortiGate generates this per fortilinkd init from /dev/urandom; FortiSwitch builds observed fixed 0xf1dc.
fortilink.fields.flendpointnonce = ProtoField.uint16("FortiLink.endpoint_nonce", "Endpoint Nonce", base.HEX)



fortilink.fields.send_echo = ProtoField.bytes('FortiLink.send_echo', 'Echo')
fortilink.fields.flp_src_serial = ProtoField.string("FortiLink.src_serial", "Source Serial")
fortilink.fields.flp_src_interface  = ProtoField.string("FortiLink.src_interface", "Source Interface")
fortilink.fields.flp_dst_serial = ProtoField.string("FortiLink.dst_serial", "Destination Serial")
fortilink.fields.flp_dst_interface = ProtoField.string("FortiLink.dst_interface", "Destination Interface")

fortilink.fields.send_echo_reply = ProtoField.bytes('FortiLink.send_echo_reply', 'Echo Reply')
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
fortilink.fields.tlv_portproperties  = ProtoField.uint32("FortiLink.tlv_portproperties", "Port Properties")
fortilink.fields.tlv_portunknown1  = ProtoField.uint32("FortiLink.tlv_portunknown1", "Port Unknown")


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

local function add_tlv_tree(buffer, tree, label, minimum_length)
    local subtree = tree:add(fortilink.fields.tlv, buffer(), label)
    subtree:add(fortilink.fields.flp_tlv_type, buffer(0,2))
    subtree:add(fortilink.fields.flp_tlv_length, buffer(2,2))
    if buffer:len() > 4 then
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
    subtree:add(fortilink.fields.tlv_portid, buffer(9,2))
    subtree:add(fortilink.fields.tlv_portname, buffer(11,17))
    subtree:add(fortilink.fields.tlv_portproperties, buffer(28,4))
    subtree:add(fortilink.fields.tlv_portunknown1, buffer(32,4))
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
            local subtree = add_tlv_tree(truncated, tree, string.format("Truncated TLV 0x%04x", tlv_id))
            add_malformed(subtree, string.format("TLV 0x%04x declares %d value bytes; only %d available", tlv_id, tlv_length, remaining-4))
            return
        end

        local tlv_buffer = buffer(counter,total_length)
        local decoder = tlv_type_function[tlv_id]
        if decoder then
            decoder(tlv_buffer, tree)
        else
            add_tlv_tree(tlv_buffer, tree, string.format("Unknown TLV 0x%04x", tlv_id))
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
    add_message_bytes(buffer, protocol_end, 10, fortilink.fields.message_data, tree)
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

    if captured_length < declared_end then
        subtree:add_proto_expert_info(fortilink.experts.length_mismatch,
            string.format("FortiLink content declares %d bytes through offset %d; only %d bytes were captured", content_length, declared_end, captured_length))
    elseif captured_length > declared_end then
        subtree:add(fortilink.fields.padding, buffer(declared_end,captured_length-declared_end))
    end

    if protocol_end < 10 then
        add_malformed(subtree, string.format("FortiLink content must contain the 2-byte endpoint nonce; only %d content bytes available", math.max(0,protocol_end-8)))
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
