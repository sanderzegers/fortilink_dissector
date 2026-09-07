# Fortinet FortiLink Wireshark Dissector

[![License](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)

## Description

FortiSwitches operating in FortiLink mode utilize a range of protocols—including LLDP, CAPWAP, HTTPS-based API calls, and the FortiLink protocol (Ethernet 0x88ff)—for management and configuration.
This repository contains a Wireshark dissector for the Fortinet FortiLink protocol and FortiLink LLDP extensions. 
The dissector enables Wireshark to decode and display FortiLink messages, making it easier to analyze and troubleshoot network communication between these devices.

![Wireshark Screenshot](/images/wireshark.png)

## Features

- Decode FortiLink protocol messages and display packet details in Wireshark.
- Decode FortiLink LLDP messages and display packet details in Wireshark.
- Detailed information about message types, fields, and values.
- Automatic recognition of FortiLink packets within capture files.

## Sample Captures

The [`pcaps`](pcaps/README.md) folder contains sanitized packet captures of FortiLink discovery and authorization, along with FortiLink LLDP traffic from different access-port profiles.

The captures contain only LLDP and FortiLink (`0x88ff`) traffic. CAPWAP/DTLS and HTTPS management traffic is not included. See the capture README for the topology, device versions, capture points, and individual file descriptions.

## Display Filters

FortiLink LLDP extension fields use the `fllldp` namespace. Useful structural filters include `fllldp.tlv.type`, `fllldp.tlv.len`, `fllldp.oui`, `fllldp.subtype`, and `fllldp.content`.

Payload filters such as `fllldp.auto_isl_port_options`, `fllldp.auto_network`, `fllldp.peer_id`, and `fllldp.trailing_data` expose decoded link-property values.

## Installation

1. Launch Wireshark.
2. Go to "Help" -> "About Wireshark" -> "Folders" -> "Personal Lua Plugins".
3. Copy the `fortilink.lua` and `fortilink_lldp.lua` files from this repository into the "Personal Lua Plugins" folder.
4. Restart Wireshark to enable the custom dissector.

## Known limitations

This dissector is still under development. Some fields are still missing, and some may be incorrect.

## Disclaimers

This dissector is provided for educational and troubleshooting purposes only. No guarantees are provided.

## License

This project is licensed under the [GNU General Public License v2.0 or later](LICENSE).
