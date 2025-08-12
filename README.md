# 🌐 Hybrid Packet Analyzer

A high-performance network packet sniffer and analyzer that combines the speed of C++ (libpcap) for packet capture with the power of Python (Scapy) for analysis and visualization.

## ✨ Features

### 🔧 **Core Functionality**
- **Hybrid Architecture**: C++ for high-performance packet capture, Python for analysis
- **Real-time Packet Capture**: Live network traffic monitoring
- **Multi-Protocol Support**: TCP, UDP, ICMP, and other IP protocols
- **Cross-Platform**: Windows, Linux, and macOS support
- **Interactive Mode**: User-friendly command-line interface
- **Command-Line Mode**: Scriptable operation with arguments

### 📊 **Analysis & Visualization**
- **Statistical Analysis**: Packet counts, protocol distribution, IP addresses, ports
- **Data Visualization**: Charts and graphs using Matplotlib
- **Service Identification**: Automatic port-to-service mapping
- **Packet Size Analysis**: Min, max, average, and median calculations
- **Top Talkers**: Most active IP addresses and ports

### 🛠️ **Advanced Features**
- **Smart Interface Detection**: Automatic selection of working network interfaces
- **Windows Optimization**: Special handling for Windows interface names
- **Error Recovery**: Graceful fallbacks and informative error messages
- **Performance Monitoring**: Real-time capture statistics
- **Export Capabilities**: Save analysis results and visualizations

## 🎬 Live Demonstration
<video controls src="File Explorer - Hybrid-Packet-Analyzer - File Explorer - 12 August 2025.mp4" title="Title"></video>

[![Hybrid Packet Analyzer Demo](https://img.youtube.com/vi/FzPl5CWcp8/maxresdefault.jpg)](https://www.youtube.com/watch?v=-FzPl5CWcp8)

*Click the image above to watch the full demo*

**Demo Highlights:**
- ⚡ Real-time packet capture and analysis
- 🖥️ Windows interface auto-detection
- 📊 Live statistical analysis
- 📈 Data visualization generation
- 🔄 C++ and Python hybrid architecture
- 🛠️ Interactive command-line interface

---

## 🚀 Quick Start

### **Prerequisites**
- Python 3.7+
- CMake 3.10+
- Visual Studio Build Tools (Windows) or GCC/Clang (Linux/macOS)
- Npcap (Windows) or libpcap-dev (Linux/macOS)

### **Installation**

1. **Clone the repository:**
```bash
git clone <repository-url>
cd Hybrid-Packet-Analyzer
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Build the project:**
```bash
python build.py
```

### **Usage**

#### **Interactive Mode (Recommended)**
```bash
python src/python/packet_analyzer.py
```

#### **Command Line Mode**
```bash
# Basic capture
python src/python/packet_analyzer.py --interface "Wi-Fi" --count 100

# With analysis and visualization
python src/python/packet_analyzer.py --interface "Ethernet" --count 50 --analyze --visualize

# C++ mode (if available)
python src/python/packet_analyzer.py --mode cpp --interface "any" --count 100
```

#### **Windows-Specific Helper**
```bash
# List and test network interfaces
python windows_interface_helper.py
```
## 📖 **Detailed Usage Guide**

### **Interactive Mode Options**

1. **Capture packets with Scapy** - Real packet capture using Scapy
2. **Capture packets with C++** - High-performance capture (if C++ library available)
3. **Analyze captured packets** - Generate statistical analysis
4. **Generate visualizations** - Create charts and graphs
5. **Clear captured packets** - Reset analysis data
6. **List network interfaces** - Show available interfaces
7. **Exit** - Close the application

### **Interface Selection**

#### **Windows**
- Use `"any"` for automatic interface detection
- Specific interfaces: `"Wi-Fi"`, `"Ethernet"`, `"Local Area Connection"`
- Use option 6 to list working interfaces
- The tool automatically filters out problematic interfaces

#### **Linux/macOS**
- Use `"any"` for all interfaces
- Specific interfaces: `"eth0"`, `"wlan0"`, `"lo"`
- Run with `sudo` for packet capture privileges

### **Output Examples**

#### **Packet Capture Output**
```
📡 Starting Scapy packet capture...
⚠ Using interface: Ethernet
   Description: Realtek PCIe GbE Family Controller
   IP: fe80::a7f0:d836:c7f1:92b2
📡 Capturing 20 packets on interface 0 (Ethernet)...
[TCP] 10.0.0.87:51285 → 104.18.19.125:443 (Length: 614, Flags: PA)
[TCP] 10.0.0.87:51285 → 104.18.19.125:443 (Length: 85, Flags: PA)
[UDP] 10.0.0.87:5353 → 224.0.0.251:5353 (Length: 32)
```

#### **Analysis Report**
```
📊 Packet Analysis Report
==================================================
Total Packets Captured: 100
TCP Packets: 85 (85.0%)
UDP Packets: 12 (12.0%)
ICMP Packets: 2 (2.0%)
Other Packets: 1 (1.0%)

🌐 Top IP Addresses:
  10.0.0.87: 45 packets
  104.18.19.125: 38 packets
  8.8.8.8: 12 packets

🔌 Top Ports:
  Port 443 (HTTPS): 42 packets
  Port 80 (HTTP): 18 packets
  Port 53 (DNS): 12 packets

📏 Packet Size Statistics:
  Average: 156.7 bytes
  Median: 142.0 bytes
  Min: 60 bytes
  Max: 1514 bytes
```

## 🏗️ **Architecture**

### **Components**

```
Hybrid Packet Analyzer
├── src/
│   ├── python/
│   │   └── packet_analyzer.py      # Main Python frontend
│   └── cpp/
│       ├── packet_capture.cpp      # Standalone C++ capture
│       ├── packet_capture_lib.cpp  # C++ library for Python integration
│       └── simple_packet_lib.cpp   # Fallback simulation library
├── build.py                        # Build automation script
├── windows_interface_helper.py     # Windows interface helper
└── CMakeLists.txt                  # C++ build configuration
```

### **Data Flow**

1. **Packet Capture**: C++ (libpcap) or Python (Scapy)
2. **Data Processing**: Python analysis and statistics
3. **Visualization**: Matplotlib charts and graphs
4. **Output**: Console display and file exports

## 🔧 **Development**

### **Building from Source**

1. **Install build dependencies:**
```bash
# Windows
# Install Visual Studio Build Tools and CMake

# Linux
sudo apt-get install build-essential cmake libpcap-dev pkg-config

# macOS
brew install cmake libpcap pkg-config
```

2. **Build the project:**
```bash
python build.py
```

### **Testing**

```bash
# Test installation
python test_installation.py

# Test packet capture
python src/python/packet_analyzer.py --mode scapy --count 10
```

## 🐛 **Troubleshooting**

### **Common Issues**

#### **Windows**
- **"Access Denied"**: Run Command Prompt as Administrator
- **"Interface not found"**: Use `windows_interface_helper.py` to list interfaces
- **"C++ library not found"**: Run `python build.py` to build C++ components
- **"No packets captured"**: Ensure network activity and try different interfaces

#### **Linux/macOS**
- **"Permission denied"**: Run with `sudo`
- **"libpcap not found"**: Install `libpcap-dev` package
- **"Interface not found"**: Use `ip addr` to list interfaces

### **Performance Tips**

- Use C++ mode for high-performance capture
- Limit packet count for real-time analysis
- Use specific interfaces instead of "any"
- Clear captured packets periodically

## 📊 **Performance**

### **Benchmarks**
- **C++ Mode**: ~10,000 packets/second
- **Scapy Mode**: ~1,000 packets/second
- **Memory Usage**: ~50MB for 10,000 packets
- **Analysis Time**: <1 second for 1,000 packets

### **Resource Requirements**
- **CPU**: Minimal (single-threaded)
- **Memory**: 50-100MB typical usage
- **Network**: No additional bandwidth usage
- **Storage**: Minimal (analysis results only)

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### **Development Guidelines**
- Follow PEP 8 for Python code
- Use meaningful commit messages
- Test on multiple platforms
- Update documentation for new features

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **Scapy**: Network packet manipulation library
- **libpcap**: Packet capture library
- **Npcap**: Windows packet capture driver
- **Matplotlib**: Data visualization library
- **Colorama**: Cross-platform colored terminal output

## 📚 **Learning Resources**

### **Network Protocols**
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)
- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [RFC Standards](https://www.rfc-editor.org/)

### **Packet Analysis**
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [libpcap Tutorial](https://www.tcpdump.org/pcap.html)
- [Network Security Monitoring](https://www.sans.org/cyber-security-courses/network-security-monitoring/)

---

**📖 For detailed Windows instructions, see [WINDOWS_GUIDE.md](WINDOWS_GUIDE.md)**

**🛠️ For Windows interface troubleshooting, use:**
```cmd
python windows_interface_helper.py
```

**🚀 Ready to start capturing packets? Run:**
```cmd
python src/python/packet_analyzer.py
```
