# 📞 SIP Message Analyzer

A Python script that analyzes SIP (Session Initiation Protocol) messages from PCAP files, extracting key information such as REGISTER and INVITE messages along with their network parameters.

## ✨ Features

- 📁 Processes multiple PCAP files from a designated folder
- 🔍 Extracts SIP messages (REGISTER and INVITE)
- 📋 Parses important headers including:
  - To/From headers with parameters
  - P-Access-Network-Info
  - Cellular-Network-Info
- 📊 Generates detailed analysis reports in text format
- 📈 Provides summary statistics for each PCAP file

## 🔧 Requirements

- Python 3.x
- pyshark
- Wireshark/TShark (must be installed on your system)

## 🚀 Installation

1. Ensure you have Python 3.x installed
2. Install Wireshark/TShark on your system
3. Install required Python packages:
```

## ⚠️ Error Handling

The script includes error handling for:
- Missing traces directory
- No PCAP files found
- TShark crashes
- Missing packet attributes
- General exceptions

## 🔍 Supported SIP Headers

The script extracts and parses:
- Message Type (REGISTER/INVITE)
- Timestamp
- To Header
- From Header
- P-Access-Network-Info
- Cellular-Network-Info

## 📄 License

MIT License

## 🤝 Contributing

1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 🐛 Known Issues

- Large PCAP files may require significant processing time
- Memory usage increases with file size
- TShark must be installed and accessible in system PATH

## 📚 Additional Resources

- [SIP Protocol RFC 3261](https://tools.ietf.org/html/rfc3261)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [pyshark Documentation](https://kiminewt.github.io/pyshark/)

---
Created with ❤️ by M. ElSakka