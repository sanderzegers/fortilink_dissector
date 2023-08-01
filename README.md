# Fortinet FortiLink Wireshark Dissector

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

## Description

This repository contains a custom Wireshark dissector for the Fortinet FortiLink protocol. FortiLink is a proprietary protocol used by Fortinet FortiSwitches to communicate with FortiGate devices and other FortiSwitches. The dissector enables Wireshark to decode and display FortiLink messages, making it easier to analyze and troubleshoot network communication between these devices.
The FortiLink protocol uses Ethernet type 0x88ff for communication.

![Wireshark Screenshot](/images/wireshark.png)

## Features

- Decode FortiLink protocol messages and display packet details in Wireshark.
- Detailed information about message types, fields, and values.
- Automatic recognition of FortiLink packets within capture files.

## Installation

1. Launch Wireshark.
2. Go to "Help" -> "About Wireshark" -> "Folders" -> "Personal Lua Plugins".
3. Copy the `fortilink.lua` file from this repository into the "Personal Lua Plugins" folder.
4. Restart Wireshark to enable the custom dissector.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

