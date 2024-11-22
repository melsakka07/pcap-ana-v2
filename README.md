# SIP Message Analyzer

A Python script that analyzes SIP (Session Initiation Protocol) messages from PCAP files, extracting key information such as REGISTER and INVITE messages along with their network parameters.

## Features

- Processes multiple PCAP files from a designated folder
- Extracts SIP messages (REGISTER and INVITE)
- Parses important headers including:
  - To/From headers with parameters
  - P-Access-Network-Info
  - Cellular-Network-Info
- Generates detailed analysis reports in text format
- Provides summary statistics for each PCAP file

## Requirements

- Python 3.x
- pyshark
- Wireshark/TShark (must be installed on your system)

## Installation

1. Ensure you have Python 3.x installed
2. Install Wireshark/TShark on your system
3. Install required Python packages: 