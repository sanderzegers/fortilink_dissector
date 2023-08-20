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
    version = "0.1",
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

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = debug_level.DISABLED,
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            dprint2(...)
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
    [0x000066] = "flp_fill_port_properties_with_portname_tlv",
    [0x000067] = "flp_fill_port_properties_with_portname_tlv", -- ?
    [0x000068] = "flp_fill_port_properties_with_portname_tlv", -- ?
    [0x001234] = "flp_fill_start_tlv",
    [0x005678] = "flp_fill_marker_tlv",
    [0x00cdef] = "flp_fill_marker_tlv",
    [0x00006a] = "flp_fill_port_isl_properties_with_portname_tlv",
    [0x00006b] = "flp_fill_port_fgt_properties_with_portname_tlv",
}

local tlv_port_speed =
-- maybe port properties in flp_fill_port_properties_with_portname_tlv
{

    [64] = "1GB"; --         0100 0000
    [1024] = "10GB"; --  100 0000 0000
    [512] = "40GB"; --    10 0000 0000

}

--- FortiLink fields

fortilink = Proto("fortilink", "FortiLink") 

fortilink.fields.flversion = ProtoField.uint32("FortiLink.version", "Fortilink Version")
fortilink.fields.flpackettype = ProtoField.uint8("FortiLink.packettype", "Fortilink Packet Type", base.HEX,packet_type)
fortilink.fields.flcontentlength = ProtoField.uint16("FortiLink.contentlength", "Fortilink Packet Content Length")
fortilink.fields.flpacketreserved = ProtoField.uint16("FortiLink.packetreserved", "Fortilink Packet Reserved", base.HEX)
fortilink.fields.flstaticvalue1 = ProtoField.uint16("FortiLink.staticvalue1", "Fortilink Static Value?", base.HEX)



fortilink.fields.send_echo = ProtoField.bytes('FortiLink.send_echo', 'Echo')
fortilink.fields.flp_src_serial = ProtoField.string("FortiLink.src_serial", "Source Serial")
fortilink.fields.flp_src_interface  = ProtoField.string("FortiLink.src_interface", "Source Interface")
fortilink.fields.flp_dst_serial = ProtoField.string("FortiLink.dst_serial", "Destination Serial")
fortilink.fields.flp_dst_interface = ProtoField.string("FortiLink.dst_interface", "Destination Interface")

fortilink.fields.send_echo_reply = ProtoField.bytes('FortiLink.send_echo_reply', 'Echo Reply')

fortilink.fields.flp_send_update_src_serial = ProtoField.string("FortiLink.send_update.src_serial", "Source Serial")
fortilink.fields.flp_send_update_src_interface  = ProtoField.string("FortiLink.send_update.src_interface", "Source Interface")

fortilink.fields.flp_send_disc_resp_static  = ProtoField.uint32("FortiLink.send_discover_response.static1","Static Value?")


-- TLVs

fortilink.fields.flp_tlv_type  = ProtoField.uint32("FortiLink.tlv_type", "TLV Type", base.HEX, tlv_type)
fortilink.fields.flp_tlv_length  = ProtoField.uint32("FortiLink.tlv_length", "TLV Length", base.DEC)

fortilink.fields.flp_start_tlv_data  = ProtoField.bytes("FortiLink.start_tlv.data", "Data")
fortilink.fields.faceplate_data  = ProtoField.string("FortiLink.faceplate_data", "Faceplate XML")

fortilink.fields.tlv = ProtoField.bytes('FortiLink.tlv', 'TLV')

fortilink.fields.tlv_portname  = ProtoField.string("FortiLink.tlv_portname", "Portname")
fortilink.fields.tlv_portid  = ProtoField.uint16("FortiLink.tlv_portid", "Port ID")
fortilink.fields.tlv_portproperties  = ProtoField.uint32("FortiLink.tlv_portproperties", "Port Properties")
fortilink.fields.tlv_portunknown1  = ProtoField.uint32("FortiLink.tlv_portunknown1", "Port Unknown")


fortilink.fields.tlv_magicinfo  = ProtoField.uint16("FortiLink.magicinfo", "Magic Info", base.HEX)
fortilink.fields.tlv_capabillity_flag  = ProtoField.uint32("FortiLink.capabillity_flag", "Capabillity flag", base.HEX)
fortilink.fields.tlv_maxports  = ProtoField.uint16("FortiLink.maxports", "Max ports")
fortilink.fields.tlv_multiuplink  = ProtoField.uint8("FortiLink.multiuplink", "Multiuplink")
fortilink.fields.tlv_uplink1  = ProtoField.string("FortiLink.multiuplink", "Uplink 1")
fortilink.fields.tlv_uplink2  = ProtoField.string("FortiLink.multiuplink", "Uplink 2")

fortilink.fields.tlv_isl_properties  = ProtoField.uint32("FortiLink.tlv_isl.properties", "Trunk Properties",base.HEX)
fortilink.fields.tlv_isl_properties_fortilink = ProtoField.uint8("FortiLink.tlv_isl.properties.fortilink","Fortilink",base.DEC,nil,0x1)
fortilink.fields.tlv_isl_properties_auto_isl = ProtoField.uint8("FortiLink.tlv_isl.properties.auto-isl","auto-isl",base.DEC,nil,0x10)
fortilink.fields.tlv_isl_properties_mclag_icl = ProtoField.uint8("FortiLink.tlv_isl.properties.mclag-icl","mclag-icl",base.DEC,nil,0x20)


fortilink.fields.tlv_isl_port  = ProtoField.string("FortiLink.tlv_isl.port", "Port")
fortilink.fields.tlv_isl_trunk  = ProtoField.string("FortiLink.tlv_isl.trunk", "Trunk")
fortilink.fields.tlv_isl_peer_port  = ProtoField.string("FortiLink.tlv_isl.peer_port", "Peer Port")
fortilink.fields.tlv_isl_peer_device  = ProtoField.string("FortiLink.tlv_isl.peer_device", "Peer Device")

fortilink.fields.tlv_fgt_port_properties  = ProtoField.uint32("FortiLink.tlv_fgt_prop.properties", "properties?")
fortilink.fields.tlv_fgt_port_port  = ProtoField.string("FortiLink.tlv_fgt_prop.port", "Port")
fortilink.fields.tlv_fgt_port_fgt_port  = ProtoField.string("FortiLink.tlv_fgt_prop.fgt_port", "Fortigate Port")
fortilink.fields.tlv_fgt_port_fgt_device  = ProtoField.string("FortiLink.tlv_fgt_prop.fgt_device", "Fortigate Device")



--- TLVs for Update Packets

function dissectFaceplate_ltv(buffer, pinfo, tree)
    -- pinfo.cols.info = "isl_properties_with_portname_tlv"
    local subtree = tree:add(buffer(0,buffer:len()),"dissectFaceplate_ltv")
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    subtree:add( fortilink.fields.faceplate_data, buffer(4,buffer:len()-4))
end

function dissectPort_properties_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_properties_tlv")
    local subtree = tree:add(buffer(0,buffer:len()),"Port_properties_tlv")
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    subtree:add( fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
end

function dissectPort_switch_info_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_switch_info_tlv")
    local subtree = tree:add(buffer(0,buffer:len()),"Port_switch_info_tlv")
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    -- subtree:add( fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
    subtree:add( fortilink.fields.tlv_magicinfo, buffer(4,2))
    subtree:add( fortilink.fields.tlv_maxports, buffer(6,2))
    subtree:add( fortilink.fields.tlv_multiuplink, buffer(8,1))
    subtree:add( fortilink.fields.tlv_uplink1, buffer(9,37))
    subtree:add( fortilink.fields.tlv_uplink2, buffer(46,37))

    subtree:add( fortilink.fields.tlv_capabillity_flag, buffer(86,4))
end

function dissectPort_port_prefix_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_port_prefix_tlv")
    local subtree = tree:add(buffer(0,buffer:len()),"Port_port_prefix_tlv")
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    subtree:add( fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
end


function dissectPort_start_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_start_tlv")
    -- pinfo.cols.info = "Start TLV"
    local subtree = tree:add(buffer(0,buffer:len()),"start_tlv")
    dprint2("buffer 2: " .. buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    subtree:add( fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
end

function dissectPort_marker_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_marker_tlv")
    local subtree = tree:add(buffer(0,buffer:len()),"marker_tlv")
    dprint2("buffer 2: " .. buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    -- subtree:add( fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
end

function dissectPort_port_properties_with_portname_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_port_properties_with_portname_tlv")
    -- pinfo.cols.info = "Port Properties"
    local subtree = tree:add(buffer(0,buffer:len()),"port_properties")
    dprint2("buffer 2: " .. buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))

    subtree:add( fortilink.fields.tlv_portid , buffer(9,2))
    subtree:add( fortilink.fields.tlv_portname , buffer(11,17))

    subtree:add( fortilink.fields.tlv_portproperties , buffer(28,4))
    subtree:add( fortilink.fields.tlv_portunknown1 , buffer(32,4))
end

function dissectPort_port_isl_properties_with_portname_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_port_isl_properties_with_portname_tlv")
    -- pinfo.cols.info = "isl_properties_with_portname_tlv"
    local subtree = tree:add(buffer(0,buffer:len()),"isl_properties_with_portname_tlv")
    dprint2("buffer 2: " .. buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))
    
    -- subtree:add( fortilink.fields.flp_start_tlv_data, buffer(4,buffer:len()-4))
    local islportsub = subtree:add( fortilink.fields.tlv_isl_properties, buffer(4,4))
    islportsub:add(fortilink.fields.tlv_isl_properties_fortilink,buffer(4,4))
    islportsub:add(fortilink.fields.tlv_isl_properties_auto_isl,buffer(4,4))
    islportsub:add(fortilink.fields.tlv_isl_properties_mclag_icl,buffer(4,4))

    

    subtree:add( fortilink.fields.tlv_isl_port, buffer(8,17))
    subtree:add( fortilink.fields.tlv_isl_trunk, buffer(25,17))
    subtree:add( fortilink.fields.tlv_isl_peer_port, buffer(42,17))
    subtree:add( fortilink.fields.tlv_isl_peer_device, buffer(59,17))
end

function dissectPort_port_fgt_properties_with_portname_tlv(buffer, pinfo, tree)
    dprint2("dissectPort_port_fgt_properties_with_portname_tlv")

    local subtree = tree:add(buffer(0,buffer:len()),"fgt_properties_with_portname_tlv")
    dprint2("buffer 2: " .. buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_type , buffer(0,2))
    subtree:add( fortilink.fields.flp_tlv_length, buffer(2,2))

    local islportsub = subtree:add( fortilink.fields.tlv_isl_properties, buffer(4,4))
    islportsub:add(fortilink.fields.tlv_isl_properties_fortilink,buffer(4,4))
    subtree:add( fortilink.fields.tlv_fgt_port_port, buffer(8,17))
    subtree:add( fortilink.fields.tlv_fgt_port_fgt_port, buffer(25,17))
    subtree:add( fortilink.fields.tlv_fgt_port_fgt_device, buffer(42,17))

end




local tlv_type_function = 
{
    [0x000069] = dissectFaceplate_ltv,
    [0x000066] = dissectPort_properties_tlv,
    [0x000064] = dissectPort_switch_info_tlv,
    [0x000065] = dissectPort_port_prefix_tlv,
    [0x000066] = dissectPort_port_properties_with_portname_tlv,
    [0x000067] = dissectPort_port_properties_with_portname_tlv, -- ?
    [0x000068] = dissectPort_port_properties_with_portname_tlv, -- ?
    [0x001234] = dissectPort_start_tlv,
    [0x005678] = dissectPort_marker_tlv,
    [0x00cdef] = dissectPort_marker_tlv,
    [0x00006a] = dissectPort_port_isl_properties_with_portname_tlv,
    [0x00006b] = dissectPort_port_fgt_properties_with_portname_tlv,
}



-- Main


function fortilink.dissector(buffer, pinfo, tree)
    length = buffer:len();
    pinfo.cols.protocol = fortilink.name
    
    local subtree = tree:add(fortilink,buffer(), "FortiLink")
    subtree:add( fortilink.fields.flversion, buffer(0,3))
    subtree:add( fortilink.fields.flpackettype, buffer(3,1))    
    subtree:add( fortilink.fields.flcontentlength, buffer(4,2))
    subtree:add( fortilink.fields.flpacketreserved, buffer(6,2))
    subtree:add( fortilink.fields.flstaticvalue1, buffer(8,2))

    local pkt_type_str = packet_type[buffer(3,1):uint()]



    if pkt_type_str == "flp_send_echo" then
        dissectSendEcho(buffer,pinfo,subtree)
    elseif pkt_type_str == "flp_send_echo_reply" then
        dissectSendEcho_Reply(buffer,pinfo,subtree)
    elseif pkt_type_str == "flp_send_update" then
        dissectSendUpdate(buffer,pinfo,subtree)
    elseif pkt_type_str == "flp_send_disc_pkt" then
        dissectSendDiscovery(buffer,pinfo,subtree)
    elseif pkt_type_str == "flp_send_discovery_response" then
        disscectSendDiscovery_Response(buffer,pinfo,subtree)
    elseif pkt_type_str == "flp_send_join_request" then
        disscectSendJoinRequest(buffer,pinfo,subtree)
    elseif pkt_type_str == "flp_send_join_response" then
        disscectSendJoinResponse(buffer,pinfo,subtree)
    end

end



--- Dissector for each packet type

function dissectSendEcho(buffer, pinfo, tree)
    pinfo.cols.info = "Echo Request Packet"
    
    tree:add( fortilink.fields.flp_src_serial, buffer(12,32))
    tree:add( fortilink.fields.flp_src_interface, buffer(44,32))
    tree:add( fortilink.fields.flp_dst_serial, buffer(76,32))
    tree:add( fortilink.fields.flp_dst_interface, buffer(108,buffer:len()-108))
end

function dissectSendEcho_Reply(buffer, pinfo, tree)
    pinfo.cols.info = "Echo Reply Packet"
    tree:add(fortilink.fields.send_echo_reply,buffer(10,buffer:len()-10))
end

function disscectSendJoinRequest(buffer, pinfo, tree)
    pinfo.cols.info = "Join Request"
    -- local src_serial = buffer(10,32)
    -- pinfo.cols.info = "Join Request, src_serial=" .. src_serial:string()

    tree:add( fortilink.fields.flp_src_serial, buffer(10,32))
    tree:add( fortilink.fields.flp_src_interface, buffer(42,32))
    tree:add( fortilink.fields.flp_dst_serial, buffer(74,32))
    tree:add( fortilink.fields.flp_dst_interface, buffer(106,32))

end

function disscectSendJoinResponse(buffer, pinfo, tree)
    pinfo.cols.info = "Join Response"

end


function dissectSendUpdate(buffer, pinfo, tree)
    pinfo.cols.info = "Send Update packet"
    
    tree:add( fortilink.fields.flp_src_serial, buffer(10,32))
    tree:add( fortilink.fields.flp_src_interface, buffer(42,32))

    -- local subtree = tree:add(fortilink.fields.tlv,buffer(74,buffer:len()-74))

    local counter = 74
    
    while counter < buffer:len() do
        -- local func = byte_to_func[buffer(counter,2):uint()]
        local test = string.format("%02x", buffer(counter,2):uint())
        -- dprint2(test)
        local func = tlv_type_function[buffer(counter,2):uint()]
        local name = tlv_type[buffer(counter,2):uint()]
        -- dprint2("name: " .. name)
        
        local len = buffer(counter+2,2):uint()
        dprint2("tlv_id: " .. test .. " length: " .. len)
        if func then
            -- dprint2("Calling " .. name)
            dprint2(buffer(counter,len+4))
            func(buffer(counter,len+4),pinfo,tree)  -- Call the function
        else
            dprint2("No function found for " .. test)
        end
        counter = counter + 4 + len
    end


end


function dissectSendDiscovery(buffer, pinfo, tree)
    pinfo.cols.info = "Send Discovery packet"
    
    tree:add( fortilink.fields.flp_src_serial, buffer(10,32))
    tree:add( fortilink.fields.flp_src_interface, buffer(42,32))

    local counter = 74
    
    while counter < buffer:len() do

        local test = string.format("%02x", buffer(counter,2):uint())

        local func = tlv_type_function[buffer(counter,2):uint()]
        local name = tlv_type[buffer(counter,2):uint()]

        
        local len = buffer(counter+2,2):uint()
        dprint2("tlv_id: " .. test .. " length: " .. len)
        if func then

            dprint2(buffer(counter,len+4))
            func(buffer(counter,len+4),pinfo,tree)  -- Call the function
        else
            dprint2("No function found for " .. test)
        end
        counter = counter + 4 + len
    end


end

function disscectSendDiscovery_Response(buffer, pinfo, tree)
    pinfo.cols.info = "Discovery Response"
    
    tree:add( fortilink.fields.flp_src_serial, buffer(12,32))
    tree:add( fortilink.fields.flp_src_interface, buffer(44,32))
    tree:add( fortilink.fields.flp_dst_serial, buffer(76,32))
    tree:add( fortilink.fields.flp_dst_interface, buffer(108,32))
    tree:add( fortilink.fields.flp_send_disc_resp_static, buffer(140,4))
    
end

function dissectSendEcho_Reply(buffer, pinfo, tree)
    pinfo.cols.info = "Echo Reply Packet"
    tree:add(fortilink.fields.send_echo_reply,buffer(10,buffer:len()-10))
end


ether_table = DissectorTable.get("ethertype")
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