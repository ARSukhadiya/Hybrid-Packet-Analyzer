# Hybrid Packet Analyzer - Windows Guide

This guide provides step-by-step instructions for setting up and using the Hybrid Packet Analyzer on Windows.

## 🖥️ System Requirements

- **Windows 10/11** (64-bit recommended)
- **Python 3.8 or higher**
- **Visual Studio Build Tools 2019/2022** (for C++ compilation)
- **CMake 3.10 or higher**
- **Administrator privileges** (required for packet capture)

## 📋 Prerequisites Installation

### Step 1: Install Python
1. Download Python from [python.org](https://www.python.org/downloads/)
2. **IMPORTANT**: Check "Add Python to PATH" during installation
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

### Step 2: Install Visual Studio Build Tools
1. Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)
2. Run the installer and select:
   - **C++ build tools**
   - **Windows 10/11 SDK**
   - **CMake tools for Visual Studio**
3. Install (this may take 10-20 minutes)

### Step 3: Install CMake
1. Download CMake from [cmake.org](https://cmake.org/download/)
2. Choose "Windows x64 Installer"
3. **IMPORTANT**: Select "Add CMake to the system PATH"
4. Verify installation:
   ```cmd
   cmake --version
   ```

### Step 4: Install Npcap (for packet capture)
1. Download [Npcap](https://npcap.com/) (recommended) or [WinPcap](https://www.winpcap.org/)
2. Run installer with default settings
3. This provides the libpcap functionality for Windows

## 🚀 Installation Steps

### Step 1: Clone/Download the Project
```cmd
# If you have Git installed:
git clone https://github.com/yourusername/Hybrid-Packet-Analyzer.git
cd Hybrid-Packet-Analyzer

# Or download and extract the ZIP file
```

### Step 2: Open Command Prompt as Administrator
1. Press `Win + X`
2. Select "Windows PowerShell (Admin)" or "Command Prompt (Admin)"
3. Navigate to your project directory:
   ```cmd
   cd "C:\path\to\Hybrid-Packet-Analyzer"
   ```

### Step 3: Run the Build Script
```cmd
python build.py
```

**Expected Output:**
```
🚀 Hybrid Packet Analyzer - Build Script
==================================================
🔍 Checking dependencies...
✓ cmake --version
✓ All dependencies found!
🔨 Building C++ components...
✓ cmake ..
✓ cmake --build .
✓ C++ components built successfully!
📦 Installing Python dependencies...
✓ pip install -r requirements.txt
✓ Python dependencies installed!
🚀 Creating launcher scripts...
✓ Created run_analyzer.bat

🎉 Build completed successfully!

📋 Usage:
  run_analyzer.bat                    # Run in interactive mode
  run_analyzer.bat --help             # Show help
  run_analyzer.bat --mode scapy -c 50 # Capture 50 packets with Scapy

⚠️  Note: Packet capture requires administrator/root privileges
```

### Step 4: Test the Installation
```cmd
python test_installation.py
```

## 🎯 How to Use

### Method 1: Interactive Mode (Recommended for Beginners)

1. **Open Command Prompt as Administrator**
   ```cmd
   # Press Win + X, then select "Windows PowerShell (Admin)"
   ```

2. **Navigate to the project directory**
   ```cmd
   cd "C:\path\to\Hybrid-Packet-Analyzer"
   ```

3. **Run the analyzer**
   ```cmd
   run_analyzer.bat
   ```

4. **Follow the interactive menu:**
   ```
   🚀 Hybrid Packet Analyzer - Interactive Mode
   ==================================================

   Options:
   1. Capture packets with Scapy
   2. Capture packets with C++ (if available)
   3. Analyze captured packets
   4. Generate visualizations
   5. Clear captured packets
   6. Exit

   Enter your choice (1-6): 1
   ```

5. **Example session:**
   ```
   Enter your choice (1-6): 1
   Enter interface (default: any): any
   Enter number of packets to capture (default: 100): 50
   
   📡 Starting Scapy packet capture on any...
   [TCP] 192.168.1.100:52431 → 8.8.8.8:443 (Length: 66, Flags: S)
   [UDP] 192.168.1.100:52432 → 8.8.8.8:53 (Length: 45)
   [ICMP] 192.168.1.100 → 8.8.8.8 (Type: 8, Code: 0)
   ...
   ```

### Method 2: Command Line Mode

#### Basic Packet Capture
```cmd
# Capture 100 packets using Scapy
run_analyzer.bat --mode scapy --count 100

# Capture 50 packets using C++ (if available)
run_analyzer.bat --mode cpp --count 50

# Capture on specific interface
run_analyzer.bat --interface "Wi-Fi" --count 200
```

#### Analysis and Visualization
```cmd
# Capture and analyze packets
run_analyzer.bat --mode scapy --count 100 --analyze

# Capture, analyze, and generate visualizations
run_analyzer.bat --mode scapy --count 100 --analyze --visualize
```

#### Advanced Options
```cmd
# Show all available options
run_analyzer.bat --help

# Capture with custom timeout
run_analyzer.bat --mode scapy --count 50 --timeout 30

# Capture on specific interface with analysis
run_analyzer.bat --interface "Ethernet" --count 200 --analyze --visualize
```

## 📊 Understanding the Output

### Packet Capture Output
```
[TCP] 192.168.1.100:52431 → 8.8.8.8:443 (Length: 66, Flags: S)
[UDP] 192.168.1.100:52432 → 8.8.8.8:53 (Length: 45)
[ICMP] 192.168.1.100 → 8.8.8.8 (Type: 8, Code: 0)
```

**What this means:**
- `[TCP]` - Protocol type
- `192.168.1.100:52431` - Source IP and port
- `8.8.8.8:443` - Destination IP and port (443 = HTTPS)
- `Length: 66` - Packet size in bytes
- `Flags: S` - TCP flags (S = SYN)

### Analysis Report
```
📊 Packet Analysis Report
==================================================
Total Packets Captured: 100
TCP Packets: 45 (45.0%)
UDP Packets: 35 (35.0%)
ICMP Packets: 15 (15.0%)
Other Packets: 5 (5.0%)

🌐 Top IP Addresses:
  192.168.1.100: 50 packets
  8.8.8.8: 30 packets
  10.0.0.1: 20 packets

🔌 Top Ports:
  Port 443 (HTTPS): 25 packets
  Port 53 (DNS): 20 packets
  Port 80 (HTTP): 15 packets

📏 Packet Size Statistics:
  Average: 512.3 bytes
  Median: 450.0 bytes
  Min: 60 bytes
  Max: 1500 bytes
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. "Access Denied" Error
**Problem:** `PermissionError: [WinError 5] Access is denied`

**Solution:**
- Always run Command Prompt as Administrator
- Right-click Command Prompt → "Run as administrator"

#### 2. "CMake not found" Error
**Problem:** `'cmake' is not recognized as an internal or external command`

**Solution:**
- Reinstall CMake and ensure "Add to PATH" is selected
- Restart Command Prompt after installation
- Or add CMake manually to PATH

#### 3. "Visual Studio Build Tools not found" Error
**Problem:** `LINK : fatal error LNK1104: cannot open file 'kernel32.lib'`

**Solution:**
- Install Visual Studio Build Tools with C++ components
- Ensure Windows SDK is installed
- Restart Command Prompt after installation

#### 4. "No packets captured" Issue
**Problem:** No packets are being captured

**Solutions:**
- Ensure you're running as Administrator
- Try different interfaces: `--interface "Wi-Fi"` or `--interface "Ethernet"`
- Generate network traffic (browse web, ping google.com)
- Check Windows Firewall settings

#### 5. "C++ library not found" Warning
**Problem:** `Warning: C++ library not found. Using Scapy-only mode.`

**Solution:**
- This is normal if C++ compilation failed
- The tool will still work with Scapy-only mode
- Check build errors in the build.py output

#### 6. "Interface not found" Error
**Problem:** `Couldn't open device` or `Error opening adapter`

**Solution:**
- **Use the Windows Interface Helper:**
  ```cmd
  python windows_interface_helper.py
  ```
- **Or manually list interfaces:**
  ```cmd
  ipconfig
  ```
- **Use correct interface name:** `--interface "Wi-Fi"` or `--interface "Ethernet"`
- **Try auto-detection:** The tool now automatically detects available interfaces

### Getting Help

#### Check Available Interfaces
```cmd
# Use the Windows Interface Helper (recommended)
python windows_interface_helper.py

# Or use system command
ipconfig
```

#### Test Basic Functionality
```cmd
python test_installation.py
```

#### Run with Verbose Output
```cmd
run_analyzer.bat --mode scapy --count 10 --verbose
```

## 🎓 Learning Examples

### Example 1: Basic Network Monitoring
```cmd
# Monitor your network for 1 minute
run_analyzer.bat --mode scapy --count 1000 --timeout 60 --analyze
```

### Example 2: Web Traffic Analysis
```cmd
# Capture while browsing the web
run_analyzer.bat --mode scapy --count 200 --analyze --visualize
```

### Example 3: DNS Traffic Monitoring
```cmd
# Monitor DNS queries (port 53)
run_analyzer.bat --mode scapy --count 50 --analyze
```

### Example 4: HTTPS Traffic Analysis
```cmd
# Monitor HTTPS traffic (port 443)
run_analyzer.bat --mode scapy --count 100 --analyze
```

## 🔒 Security and Privacy

### Important Notes:
- **Always run as Administrator** - Required for packet capture
- **Respect privacy** - Only capture on your own network
- **Educational use only** - Don't capture others' traffic without permission
- **Firewall settings** - Windows Firewall may block some captures

### Safe Testing:
- Test on your own computer
- Use `localhost` or your own network
- Avoid capturing on public networks
- Be aware of your organization's policies

## 📈 Performance Tips

### For Better Performance:
1. **Use C++ mode** when available (faster capture)
2. **Limit packet count** for quick tests
3. **Use specific interfaces** instead of "any"
4. **Close unnecessary applications** to reduce background traffic

### Memory Usage:
- 1000 packets ≈ 50MB memory
- Large captures may use significant RAM
- Clear captured packets when done

## 🎯 Next Steps

After mastering basic usage:

1. **Learn about protocols**: Study TCP, UDP, ICMP
2. **Explore filters**: Learn BPF syntax for targeted capture
3. **Analyze patterns**: Look for traffic patterns and anomalies
4. **Customize analysis**: Modify the Python code for specific needs
5. **Network security**: Learn about intrusion detection and monitoring

## 📞 Support

If you encounter issues:

1. **Check this guide** for common solutions
2. **Run the test script**: `python test_installation.py`
3. **Check system requirements** are met
4. **Ensure Administrator privileges**
5. **Review build output** for error messages

---

**Happy Packet Analyzing! 🚀**

