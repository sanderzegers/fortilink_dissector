#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lua_script="$repo_dir/fortilink_lldp.lua"
capture="$repo_dir/pcaps/FSW7.4.9-Access-Port-Default-lldp-isl.pcapng"
edge_cases="$repo_dir/tests/fixtures/fortilink_lldp_edge_cases.txt"
edge_capture=$(mktemp "${TMPDIR:-/tmp}/fortilink-lldp-edge-cases.XXXXXX.pcapng")
trap 'rm -f "$edge_capture"' EXIT HUP INT TERM

luac -p "$lua_script"

fields=$(tshark -G fields -X "lua_script:$lua_script")
for field in \
    fllldp.tlv.type \
    fllldp.tlv.len \
    fllldp.oui \
    fllldp.subtype \
    fllldp.content \
    fllldp.peer_id_len \
    fllldp.peer_id \
    fllldp.unknown_options \
    fllldp.trunk_mode_selector \
    fllldp.loop_guard \
    fllldp.trailing_data
do
    printf '%s\n' "$fields" | awk -F '\t' -v wanted="$field" \
        '$3 == wanted { found = 1 } END { exit !found }'
done

actual=$(tshark -r "$capture" -X "lua_script:$lua_script" \
    -Y 'fllldp.auto_isl_port_options' -T fields \
    -e frame.number \
    -e fllldp.auto_isl_port_options \
    -e fllldp.auto_network \
    -e fllldp.auto_isl_port_group \
    -e fllldp.peer_id_len \
    -e fllldp.peer_id \
    -e fllldp.unknown_options)

expected=$(printf '%s\n' \
    '3|0x00000200|1|0|16|S124ENTQ12345678|0x00000000' \
    '6|0x00000200|1|0|16|S124ENTQ12345678|0x00000000' \
    '9|0x00000200|1|0|16|S124ENTQ12345678|0x00000000' \
    '12|0x00000200|1|0|16|S124ENTQ12345678|0x00000000' | tr '|' '\t')

if [ "$actual" != "$expected" ]; then
    printf '%s\n' 'Unexpected FortiLink LLDP decode:' "$actual" >&2
    exit 1
fi

text2pcap -q "$edge_cases" "$edge_capture"

truncated=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fllldp.peer_id_truncated' -T fields -e frame.number)
if [ "$truncated" != '1' ]; then
    printf '%s\n' 'Expected a truncated peer identifier in edge-case frame 1.' >&2
    exit 1
fi

trailing=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fllldp.trailing_data' -T fields \
    -e frame.number -e fllldp.peer_id -e fllldp.trailing_data -e fllldp.unknown_options)
trailing_expected=$(printf '2\tA\t42\t0x00001008')
if [ "$trailing" != "$trailing_expected" ]; then
    printf '%s\n' 'Unexpected trailing-data/unknown-bit decode:' "$trailing" >&2
    exit 1
fi

too_short=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fllldp.too_short' -T fields -e frame.number)
if [ "$too_short" != '3' ]; then
    printf '%s\n' 'Expected a short link-properties payload in edge-case frame 3.' >&2
    exit 1
fi

selectors=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fllldp.trunk_mode_selector == 1 || fllldp.trunk_mode_selector == 2' \
    -T fields -e frame.number -e fllldp.trunk_mode_selector)
selectors_expected=$(printf '4\t1\n5\t2')
if [ "$selectors" != "$selectors_expected" ]; then
    printf '%s\n' 'Unexpected LACP trunk-mode selectors:' "$selectors" >&2
    exit 1
fi

unknown_subtype=$(tshark -r "$edge_capture" -X "lua_script:$lua_script" \
    -Y 'fllldp.subtype == 0x7f' -T fields \
    -e frame.number -e fllldp.content)
unknown_subtype_expected=$(printf '6\tdead')
if [ "$unknown_subtype" != "$unknown_subtype_expected" ]; then
    printf '%s\n' 'Unknown subtype was not decoded safely as raw content:' "$unknown_subtype" >&2
    exit 1
fi

printf '%s\n' 'FortiLink LLDP regression checks passed.'
