# FortiLink protocol reference

The FortiLink protocol decoded here is a proprietary, publicly undocumented Ethernet protocol used between FortiGate and FortiSwitch devices. This document records the wire formats decoded by this project and distinguishes independently validated behavior, implementation-derived mappings, and provisional interpretations. It is a protocol reference for the dissector, not a complete vendor specification.

This reference is based primarily on traffic from FortiOS 6.4.8 and 7.4.12 with FortiSwitchOS 7.4.9, plus the captures and observations documented in this repository. Other firmware versions may use additional or changed fields.

## Confidence

| Label | Meaning |
| --- | --- |
| Confirmed | The layout and stated meaning have been independently validated from observable protocol behavior or controlled testing. |
| Strongly observed | Repeated observable behavior supports the interpretation, but the complete conditions or public name remain open. |
| Implementation-derived | The meaning or bit assignment was obtained from analysis of the software implementation. It may be consistent with observed traffic but has not necessarily been independently validated across all hardware, firmware versions, or conditions. |
| Inferred | The label is plausible and useful, but provisional. |
| Unknown | The bytes are preserved and displayed without assigning a semantic meaning. |

A matching value in a capture establishes that the value occurs; it does not by itself validate the field's meaning. Where layout and interpretation have different levels of support, the status distinguishes them.

## Two distinct protocols

This project decodes two different protocol families. They do not share a TLV format, even though both use the term "TLV".

| Protocol | Where it appears | Framing | What this project decodes |
| --- | --- | --- | --- |
| FortiLink | Ethernet EtherType `0x88ff` | FortiLink message header followed, for Discovery and Update, by FortiLink TLVs with a 16-bit type and 16-bit length. | Discovery, authorization/join, echo, update, and FortiLink configuration TLVs. |
| Fortinet LLDP extension | Standard LLDP organizational TLV with OUI `08:5b:0e` | Standard LLDP TLV header, then OUI, one-byte FortiLink subtype, and subtype-specific content. | Hostname, serial number, and link-properties extension data. |

Fortinet LLDP extension traffic can describe link and switch properties, while FortiLink traffic carries the separate `0x88ff` control and configuration exchange. A FortiLink TLV type is not meaningful inside an LLDP frame, and an LLDP subtype is not a FortiLink `0x88ff` message type.

## FortiLink (`0x88ff`)

FortiLink messages cover discovery, joining a controller, exchanging switch properties, and echo traffic. The reference captures include discovery and join exchanges before and after switch authorization. See the [capture guide](../pcaps/README.md) for topology, firmware combinations, and authorization markers.

### Message types

Message offsets are measured in bytes from the start of the FortiLink payload, immediately after the Ethernet header. Multi-byte numeric fields described here use network byte order (big-endian).

| Type | Message | Layout and decoded fields | Open details |
| ---: | --- | --- | --- |
| `0x00` | Discovery | Source serial at `0x0a` (32 bytes), source interface at `0x2a` (32 bytes), then TLVs at `0x4a`. | Individual TLV contents remain partly understood. |
| `0x01` | Discovery response | Selector at `0x0a`; selectors 0 and 1 use the full layout: source serial/interface, destination serial/interface, then a 32-bit value at `0x8c`. Other selectors can use a short form. The selector-to-layout rule is implementation-derived. | Meaning/unit of final value and additional selectors. |
| `0x02` | Join request | Four 32-byte strings: source serial `0x0a`, source interface `0x2a`, destination serial `0x4a`, destination interface `0x6a`; 32-bit node index at `0x8a`. | Public meaning of node index. |
| `0x03` | Join response | 16-bit status at `0x0a`; 0 is displayed as Success and 3 as Error. | Other status values. |
| `0x04` | Echo | Two-byte message data, then fixed source/destination serial and interface strings. | Remaining body semantics. |
| `0x05` | Echo reply | Raw message body after the endpoint nonce. | Complete body layout. |
| `0x06` | Update | Source serial/interface followed by TLVs, using the Discovery layout. | Individual TLV contents remain partly understood. |

Unknown message types retain the packet-type value and body as undecoded message data. Trailing bytes are shown separately where a known message layout ends, and Ethernet bytes beyond the declared content length are shown as padding. This is deliberate forward-compatible behavior.

### FortiLink TLVs

Discovery and Update messages contain TLVs: type-length-value records that describe switch and port properties. Each record has a 16-bit type and a 16-bit length counting only its value bytes. The dissector checks each record against the remaining message length. If a record declares more bytes than remain, it reports the truncation, displays the available value, and stops parsing that sequence.

| Type | Label | Decoded coverage |
| ---: | --- | --- |
| `0x0064` | Switch Info | Magic value, maximum ports, multi-uplink, uplink strings, PoE fields, version, maximum trunk members, capability data, and raw tail. |
| `0x0065` | Port Prefix | Raw value. |
| `0x0066` | Port Properties | Raw port-property data. |
| `0x0067`, `0x0068` | Named Port Properties | Property mask, port number, port name, default speed, available speeds, and optional extension. |
| `0x0069` | Faceplate | Value displayed as Faceplate XML. |
| `0x006a` | ISL Properties | Property mask plus local port, trunk, peer port, and peer device strings. The FortiLink, Auto-ISL, and MCLAG ICL bit mappings are implementation-derived; remaining bits are unknown. |
| `0x006b` | FortiGate Properties | Property mask plus port, FortiGate port, and FortiGate device strings. |
| `0x1234` | Start | Raw value. |
| `0x5678`, `0xcdef` | Marker | Raw value. |

#### Switch Info TLV (`0x0064`)

All TLV field offsets below are relative to the value, excluding the four-byte TLV header. Sizes are in bytes.

| Offset | Size | Field | Status |
| ---: | ---: | --- | --- |
| `0x00` | 2 | Magic info | Confirmed |
| `0x02` | 2 | Maximum ports | Confirmed |
| `0x04` | 1 | Multi-uplink | Implementation-derived |
| `0x05` | 36 | Uplink 1 | Confirmed |
| `0x29` | 36 | Uplink 2 | Confirmed |
| `0x4d` | 2 | Maximum PoE budget | Implementation-derived |
| `0x4f` | 1 | PoE detection type | Implementation-derived |
| `0x50` | 1 | Switch Info version | Implementation-derived |
| `0x51` | 1 | Maximum trunk members | Implementation-derived |
| `0x52` | 12 | Capability data | Grouping is implementation-derived; individual capability bits unknown |
| `0x5e` | variable | Trailing bytes | Unknown; 34 bytes in the reference captures |

The 12-byte capability area is preserved in full. Its first four bytes are also displayed as Capability Flags; individual capability-bit meanings remain unresolved.

#### Named Port Properties TLVs (`0x0067` and `0x0068`)

These records associate a port number and name with its role and speed options. The base value is 32 bytes; a complete extended value adds a four-byte configured-speed number and an eight-byte available-speed mask.

| Offset | Size | Field | Status |
| ---: | ---: | --- | --- |
| `0x00` | 4 | Port properties | FortiLink (bit 0) and ISL (bit 4) mappings are implementation-derived; the ICL-associated label (bit 5) is inferred; remaining bits are unknown. |
| `0x04` | 1 | Port-property byte | Unknown semantics. |
| `0x05` | 2 | Port number | Confirmed layout. |
| `0x07` | 17 | Port name | Confirmed. |
| `0x18` | 4 | Default speed mask | Implementation-derived meaning and option mapping. |
| `0x1c` | 4 | Available-speed mask | Implementation-derived meaning and bit assignments. |
| `0x20` | 4 | Configured speed number | Implementation-derived meaning in extended form. |
| `0x24` | 8 | 64-bit available-speed mask | Implementation-derived interpretation; unassigned high bits remain unknown. |

All mappings in the speed table below are **Implementation-derived**. An available-speed mask can contain several options at once. The configured-speed number in the extension is an option index, so it should not be read as a bitmask. Capture values corroborate some entries, but the complete mapping has not been independently tested across all listed speed modes.

| Bit | Mask | Speed option |
| ---: | --- | --- |
| 0 | `0x00000001` | `10half` |
| 1 | `0x00000002` | `10full` |
| 2 | `0x00000004` | `100half` |
| 3 | `0x00000008` | `100full` |
| 4 | `0x00000010` | `1000full` |
| 5 | `0x00000020` | `10000full` |
| 6 | `0x00000040` | `auto` |
| 7 | `0x00000080` | `1000auto` |
| 8 | `0x00000100` | `1000full-fiber` |
| 9 | `0x00000200` | `40000full` |
| 10 | `0x00000400` | `auto-module` |
| 11 | `0x00000800` | `100FX-half` |
| 12 | `0x00001000` | `100FX-full` |
| 13 | `0x00002000` | `100000full` |
| 14 | `0x00004000` | `2500auto` |
| 15 | `0x00008000` | `25000full` |
| 16 | `0x00010000` | `50000full` |
| 17 | `0x00020000` | `10000cr` |
| 18 | `0x00040000` | `10000sr` |
| 19 | `0x00080000` | `100000sr4` |
| 20 | `0x00100000` | `100000cr4` |
| 21 | `0x00200000` | `40000sr4` |
| 22 | `0x00400000` | `40000cr4` |
| 23 | `0x00800000` | `40000auto` |
| 24 | `0x01000000` | `25000cr` |
| 25 | `0x02000000` | `25000sr` |
| 26 | `0x04000000` | `50000cr` |
| 27 | `0x08000000` | `50000sr` |
| 28 | `0x10000000` | `5000auto` |
| 29 | `0x20000000` | `2500full` |

In the extended mask, bits 30 and 31 have separate unknown-bit fields, and bits 32-63 are displayed together as an unknown upper word. The extension bytes are also retained as raw data, including incomplete extensions.

## Fortinet LLDP extensions

The LLDP dissector handles Fortinet organizational TLVs using OUI `08:5b:0e`. For every handled organizational TLV, it displays the LLDP TLV type and length, OUI, FortiLink subtype, and raw content when no specialized layout applies.

| Subtype | Contents | Status |
| ---: | --- | --- |
| `0x01` | Switch hostname string. | Confirmed |
| `0x02` | Switch serial-number string. | Confirmed |
| `0x03` | Link Properties. | Confirmed layout |

### Link Properties (`0x03`)

This subtype describes the sender's link options and peer identifier. Offsets below start immediately after the subtype byte; sizes are in bytes. The identifier can represent a trunk or switch, depending on the topology.

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x00` | 4 | Options word, in network byte order |
| `0x04` | 1 | Port-group identifier |
| `0x05` | 1 | Peer-identifier length |
| `0x06` | variable | Peer identifier, bounded by the declared length |

The options word contains individual flags and a two-bit trunk-mode selector:

| Bit or bits | Field | Status |
| --- | --- | --- |
| 0 | Auto-ISL request | Strongly observed |
| 1 | Auto-MCLAG/ICL request | Implementation-derived; consistent with observed MCLAG transitions |
| 2 | MCLAG switch/trunk request | Implementation-derived; consistent with observed MCLAG transitions |
| 3 | MCLAG peer link | Inferred |
| 4 | ISL-FortiLink request | Strongly observed |
| 5-6 | Trunk-mode selector; values listed below | Implementation-derived |
| 7 | Loop guard | Implementation-derived |
| 8 | FortiLink trunk mode | Implementation-derived |
| 9 | Auto-network enabled | Implementation-derived; consistent with observed default behavior |
| 10 | P2P mode | Implementation-derived |
| 11 | Static ISL | Implementation-derived |
| 12 | Unassigned | Unknown |
| 13 | MRP mode | Implementation-derived |
| all others | Unassigned | Unknown |

All four trunk-mode mappings below are **Implementation-derived**.

| Selector value | Masked options value | Trunk mode |
| ---: | --- | --- |
| 0 | `0x00` | Static/non-LACP |
| 1 | `0x20` | LACP active, slow |
| 2 | `0x40` | LACP active, fast |
| 3 | `0x60` | Static/non-LACP, alternate encoding |

Unknown LLDP subtypes are displayed with their subtype number and raw content. Short Link Properties payloads and truncated peer identifiers are explicitly reported. Bytes after a complete peer identifier are displayed as trailing data.

## Open protocol areas

Some structures are known more precisely than their meaning. The main gaps are:

| Area | What remains open |
| --- | --- |
| FortiLink control information | Complete meaning of the header-control word |
| Discovery and join | Additional selectors and statuses, the discovery-response final value's unit, and the public meaning of the node index |
| Echo and Echo Reply | Meaning of the undecoded body bytes |
| FortiLink TLVs | Raw-only values, unassigned property and capability bits, and trailing bytes |
| Extended speed options | Names for bits 30-63 |
| LLDP link options | Inferred MCLAG peer-link meaning and unassigned option bits |
| Firmware coverage | Additional or changed messages, TLVs, and subtypes outside the documented observations |

When a field is open, the dissector displays raw data instead of applying a speculative name. The regression tests exercise both the sanitized captures and malformed, truncated, and unknown inputs; see [`tests/test_fortilink.sh`](../tests/test_fortilink.sh) and [`tests/test_fortilink_lldp.sh`](../tests/test_fortilink_lldp.sh).
