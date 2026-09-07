#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lua_script="$repo_dir/fortilink.lua"
capture="$repo_dir/pcaps/FOS7.4.12-FSW7.4.9-fortilink.pcapng"
older_capture="$repo_dir/pcaps/FOS6.4.8-FSW7.4.9-fortilink.pcapng"
edge_cases="$repo_dir/tests/fixtures/fortilink_edge_cases.txt"
edge_capture=$(mktemp "${TMPDIR:-/tmp}/fortilink-edge-cases.XXXXXX.pcapng")
field_registry=$(mktemp "${TMPDIR:-/tmp}/fortilink-fields.XXXXXX.txt")
trap 'rm -f "$edge_capture" "$field_registry"' EXIT HUP INT TERM

luac -p "$lua_script"
tshark -G fields -X "lua_script:$lua_script" > "$field_registry"

for field in \
    FortiLink.message_data \
    FortiLink.join_response.status \
    FortiLink.padding \
    FortiLink.tlv_value \
    FortiLink.tlv_trailing_data \
    FortiLink.tlv_portproperties \
    FortiLink.tlv_portproperties.fortilink \
    FortiLink.tlv_portproperties.isl \
    FortiLink.tlv_portproperties.icl \
    FortiLink.tlv_portproperty_byte \
    FortiLink.tlv_port_default_speed \
    FortiLink.tlv_port_available_speeds \
    FortiLink.tlv_port_extension \
    FortiLink.tlv_port_extension.class \
    FortiLink.tlv_port_extension.speed_mask \
    FortiLink.uplink1 \
    FortiLink.uplink2 \
    fortilink.malformed \
    fortilink.length_mismatch
do
    awk -F '\t' -v wanted="$field" \
        '$3 == wanted { found = 1 } END { exit !found }' "$field_registry"
done

multiuplink_count=$(awk -F '\t' '$3 == "FortiLink.multiuplink" { count++ } END { print count+0 }' "$field_registry")
if [ "$multiuplink_count" -ne 1 ]; then
    printf '%s\n' 'FortiLink.multiuplink must identify exactly one field.' >&2
    exit 1
fi

for field in \
    FortiLink.tlv_isl.properties.fortilink \
    FortiLink.tlv_isl.properties.auto-isl \
    FortiLink.tlv_isl.properties.mclag-icl \
    FortiLink.tlv_portproperties.fortilink \
    FortiLink.tlv_portproperties.isl \
    FortiLink.tlv_portproperties.icl \
    FortiLink.tlv_port_available_speeds.10half \
    FortiLink.tlv_port_available_speeds.10000full \
    FortiLink.tlv_port_available_speeds.25000full \
    FortiLink.tlv_port_available_speeds.40000full \
    FortiLink.tlv_port_available_speeds.50000full \
    FortiLink.tlv_port_available_speeds.100000full
do
    awk -F '\t' -v wanted="$field" \
        '$3 == wanted && $4 == "FT_BOOLEAN" { found = 1 } END { exit !found }' "$field_registry"
done

for sample in "$capture" "$older_capture"; do
    unexpected=$(tshark -r "$sample" -X "lua_script:$lua_script" \
        -Y 'fortilink.malformed || fortilink.length_mismatch' \
        -T fields -e frame.number -e _ws.expert.message)
    if [ -n "$unexpected" ]; then
        printf '%s\n' "Unexpected FortiLink expert information in $sample:" "$unexpected" >&2
        exit 1
    fi
done

named_port=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 1' -T fields -E occurrence=f \
    -e FortiLink.tlv_portproperties \
    -e FortiLink.tlv_portproperties.fortilink \
    -e FortiLink.tlv_portproperties.isl \
    -e FortiLink.tlv_portproperties.icl \
    -e FortiLink.tlv_portproperty_byte \
    -e FortiLink.tlv_portid \
    -e FortiLink.tlv_portname \
    -e FortiLink.tlv_port_default_speed \
    -e FortiLink.tlv_port_available_speeds \
    -e FortiLink.tlv_port_available_speeds.auto \
    -e FortiLink.tlv_port_available_speeds.1000auto \
    -e FortiLink.tlv_port_available_speeds.10000full \
    -e FortiLink.tlv_port_extension.class \
    -e FortiLink.tlv_port_extension.speed_mask \
    -e FortiLink.tlv_port_extension)
named_port_expected=$(printf '0x00000000\t0\t0\t0\t0x00\t1\tport1\t0x00000040\t0x000000cf\t1\t1\t0\t0x00000006\t0x00000000000000cf\t0000000600000000000000cf')
if [ "$named_port" != "$named_port_expected" ]; then
    printf '%s\n' 'Unexpected named-port-properties decode:' "$named_port" >&2
    exit 1
fi

known_tlv_raw_value=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 1' -T fields -e FortiLink.tlv_value)
if [ -n "$known_tlv_raw_value" ]; then
    printf '%s\n' 'Known TLVs must not duplicate decoded data as FortiLink.tlv_value:' "$known_tlv_raw_value" >&2
    exit 1
fi

named_port_last=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 1' -T fields -E occurrence=l \
    -e FortiLink.tlv_port_default_speed \
    -e FortiLink.tlv_port_available_speeds)
named_port_last_expected=$(printf '0x00000010\t0x000000d8')
if [ "$named_port_last" != "$named_port_last_expected" ]; then
    printf '%s\n' 'Unexpected final named-port speed decode:' "$named_port_last" >&2
    exit 1
fi

named_port_tree=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 1' -V)
if ! printf '%s\n' "$named_port_tree" | grep -q '^    Named Port Properties TLV$'; then
    printf '%s\n' 'Named port properties TLVs must have a descriptive packet-tree label.' >&2
    exit 1
fi

join_statuses=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'FortiLink.packettype == 0x03' -T fields \
    -e frame.number -e FortiLink.join_response.status)
join_statuses_expected=$(printf '15\t3\n42\t3\n72\t3\n102\t3\n129\t0')
if [ "$join_statuses" != "$join_statuses_expected" ]; then
    printf '%s\n' 'Unexpected Join Response status decode:' "$join_statuses" >&2
    exit 1
fi

sample_echo=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 132' -T fields \
    -e FortiLink.contentlength -e FortiLink.endpoint_nonce \
    -e FortiLink.send_echo_reply -e FortiLink.padding)
sample_content=$(printf '%s\n' "$sample_echo" | cut -f1-3)
sample_padding=$(printf '%s\n' "$sample_echo" | cut -f4)
if [ "$sample_content" != "$(printf '4\t0x631b\t0000')" ] || [ "${#sample_padding}" -ne 68 ]; then
    printf '%s\n' 'Echo Reply protocol data was not separated from Ethernet padding:' "$sample_echo" >&2
    exit 1
fi

text2pcap -q "$edge_cases" "$edge_capture"

edge_echo=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 2' -T fields \
    -e FortiLink.send_echo_reply -e FortiLink.padding)
edge_echo_data=$(printf '%s\n' "$edge_echo" | cut -f1)
edge_echo_padding=$(printf '%s\n' "$edge_echo" | cut -f2)
if [ "$edge_echo_data" != 'ccdd' ] || [ "${#edge_echo_padding}" -ne 68 ]; then
    printf '%s\n' 'Synthetic Echo Reply padding boundary is incorrect:' "$edge_echo" >&2
    exit 1
fi

unknown_packet=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 3' -T fields -e FortiLink.packettype -e FortiLink.message_data)
if [ "$unknown_packet" != "$(printf '0x7f\tccdd')" ]; then
    printf '%s\n' 'Unknown packet type was not preserved:' "$unknown_packet" >&2
    exit 1
fi

unknown_tlv=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 4' -T fields -e FortiLink.tlv_type -e FortiLink.tlv_value)
if [ "$unknown_tlv" != "$(printf '0x9999\tdead')" ]; then
    printf '%s\n' 'Unknown TLV was not preserved:' "$unknown_tlv" >&2
    exit 1
fi

partial_known_tlv=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 7' -T fields -e FortiLink.tlv_type -e FortiLink.tlv_value)
if [ "$partial_known_tlv" != "$(printf '0x0064\tc0de')" ]; then
    printf '%s\n' 'Malformed known TLV value bytes were not preserved:' "$partial_known_tlv" >&2
    exit 1
fi

marker_tlv=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'frame.number == 9' -T fields -e FortiLink.tlv_type -e FortiLink.tlv_value)
if [ "$marker_tlv" != "$(printf '0x5678\tbeef')" ]; then
    printf '%s\n' 'Known marker TLV value bytes were not preserved:' "$marker_tlv" >&2
    exit 1
fi

malformed=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fortilink.malformed' -T fields -e frame.number)
if [ "$malformed" != "$(printf '1\n5\n6\n7')" ]; then
    printf '%s\n' 'Unexpected malformed-frame classification:' "$malformed" >&2
    exit 1
fi

length_mismatch=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fortilink.length_mismatch' -T fields -e frame.number)
if [ "$length_mismatch" != '8' ]; then
    printf '%s\n' 'Expected a declared-length mismatch in edge-case frame 8.' >&2
    exit 1
fi

lua_errors=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -T fields -e _ws.expert.message | awk '/Lua Error/ { print }')
if [ -n "$lua_errors" ]; then
    printf '%s\n' 'FortiLink edge cases raised a Lua exception:' "$lua_errors" >&2
    exit 1
fi

printf '%s\n' 'FortiLink regression checks passed.'
