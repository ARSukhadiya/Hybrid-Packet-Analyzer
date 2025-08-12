#!/usr/bin/env python3
"""
Hybrid Packet Analyzer - Python Frontend
Integrates C++ packet capture with Python Scapy analysis
"""

import ctypes
import os
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict, Counter
import argparse

# Scapy imports
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

# Colorama for colored output
from colorama import init, Fore, Back, Style
import matplotlib.pyplot as plt
import numpy as np
from tabulate import tabulate

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class HybridPacketAnalyzer:
    def __init__(self):
        self.cpp_lib = None
        self.captured_packets = []
        self.packet_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'ip_addresses': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'protocols': Counter()
        }
        self.capture_thread = None
        self.is_capturing = False
        
        # Try to load C++ library
        self._load_cpp_library()
    
    def _load_cpp_library(self):
        """Load the C++ packet capture library"""
        try:
            # Try different library names for different platforms
            lib_names = [
                'libpacket_capture_lib.so',  # Linux
                'packet_capture_lib.dll',    # Windows
                'libpacket_capture_lib.dylib' # macOS
            ]
            
            for lib_name in lib_names:
                try:
                    # Try different possible paths
                    possible_paths = [
                        os.path.join(os.path.dirname(__file__), '..', '..', 'build', lib_name),
                        os.path.join(os.path.dirname(__file__), '..', '..', 'build', 'Release', lib_name),
                        os.path.join(os.path.dirname(__file__), '..', '..', 'build', 'Debug', lib_name)
                    ]
                    
                    for lib_path in possible_paths:
                        if os.path.exists(lib_path):
                            self.cpp_lib = ctypes.CDLL(lib_path)
                            print(f"{Fore.GREEN}✓ Loaded C++ library: {lib_name}")
                            self._setup_cpp_functions()
                            return
                except Exception as e:
                    continue
            
            print(f"{Fore.YELLOW}⚠ C++ library not found. Using Scapy-only mode.")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to load C++ library: {e}")
            print(f"{Fore.YELLOW}⚠ Using Scapy-only mode.")
    
    def _setup_cpp_functions(self):
        """Setup function signatures for C++ library"""
        if not self.cpp_lib:
            return
            
        # Function signatures
        self.cpp_lib.start_capture.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.cpp_lib.start_capture.restype = ctypes.c_int
        
        self.cpp_lib.capture_packets.argtypes = [ctypes.c_int]
        self.cpp_lib.capture_packets.restype = ctypes.c_int
        
        self.cpp_lib.get_packet_count.restype = ctypes.c_int
        self.cpp_lib.get_packet.argtypes = [ctypes.c_int]
        self.cpp_lib.get_packet.restype = ctypes.c_char_p
    
    def start_capture_cpp(self, interface="any", timeout=1000):
        """Start packet capture using C++ library"""
        if not self.cpp_lib:
            print(f"{Fore.RED}✗ C++ library not available")
            return False
        
        try:
            result = self.cpp_lib.start_capture(interface.encode('utf-8'), timeout)
            if result == 0:
                print(f"{Fore.GREEN}✓ Started C++ packet capture on {interface}")
                return True
            else:
                print(f"{Fore.RED}✗ Failed to start C++ capture")
                return False
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting C++ capture: {e}")
            return False
    
    def capture_packets_cpp(self, count=100):
        """Capture packets using C++ library"""
        if not self.cpp_lib:
            return []
        
        try:
            packets_captured = self.cpp_lib.capture_packets(count)
            packets = []
            
            for i in range(self.cpp_lib.get_packet_count()):
                packet_str = self.cpp_lib.get_packet(i)
                if packet_str:
                    packets.append(packet_str.decode('utf-8'))
            
            return packets
        except Exception as e:
            print(f"{Fore.RED}✗ Error capturing packets with C++: {e}")
            return []
    
    def stop_capture_cpp(self):
        """Stop C++ packet capture"""
        if self.cpp_lib:
            self.cpp_lib.stop_capture()
    
    def get_working_interfaces(self):
        """Get list of interfaces that can actually be used for capture"""
        try:
            if os.name == 'nt':  # Windows
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                working_interfaces = []
                
                for i, iface in enumerate(interfaces):
                    name = iface['name']
                    description = iface.get('description', 'No description')
                    
                    # Skip interfaces that are likely to fail
                    if any(skip in name.lower() for skip in ['loopback', 'teredo', '6to4', 'hyper-v', 'virtual']):
                        continue
                    
                    # Prefer interfaces with IP addresses
                    if iface.get('ips'):
                        working_interfaces.append({
                            'index': i,
                            'name': name,
                            'description': description,
                            'ips': iface.get('ips', [])
                        })
                
                return working_interfaces
            else:
                # Linux/macOS
                from scapy.all import get_if_list
                interfaces = get_if_list()
                return [{'index': i, 'name': iface, 'description': iface} for i, iface in enumerate(interfaces)]
                
        except Exception as e:
            print(f"{Fore.RED}✗ Error getting working interfaces: {e}")
            return []

    def capture_with_scapy(self, interface="any", count=100, timeout=60):
        """Capture packets using Scapy"""
        print(f"{Fore.CYAN}📡 Starting Scapy packet capture...")
        
        try:
            if os.name == 'nt':  # Windows
                # Get working interfaces
                working_interfaces = self.get_working_interfaces()
                
                if not working_interfaces:
                    print(f"{Fore.RED}✗ No working interfaces found")
                    return []
                
                # If "any" is specified, use the first working interface
                if interface == "any":
                    selected_iface = working_interfaces[0]
                    interface = selected_iface['name']
                    print(f"{Fore.YELLOW}⚠ Using interface: {interface}")
                    print(f"{Fore.CYAN}   Description: {selected_iface['description']}")
                    if selected_iface.get('ips'):
                        print(f"{Fore.CYAN}   IP: {selected_iface['ips'][0]}")
                else:
                    # Try to find the specified interface
                    selected_iface = None
                    for iface in working_interfaces:
                        if iface['name'] == interface or iface['description'] == interface:
                            selected_iface = iface
                            interface = iface['name']
                            break
                    
                    if not selected_iface:
                        print(f"{Fore.RED}✗ Interface '{interface}' not found or not suitable for capture")
                        print(f"{Fore.YELLOW}💡 Available working interfaces:")
                        for i, iface in enumerate(working_interfaces[:5]):
                            print(f"    {i+1}. {iface['name']} - {iface['description']}")
                        return []
                
                # Use interface index for capture (more reliable on Windows)
                iface_index = selected_iface['index']
                print(f"{Fore.CYAN}📡 Capturing {count} packets on interface {iface_index} ({interface})...")
                
                # Capture using interface index
                packets = sniff(iface=iface_index, count=count, timeout=timeout, prn=self._process_packet_scapy)
                
            else:
                # Linux/macOS - use interface name directly
                packets = sniff(iface=interface, count=count, timeout=timeout, prn=self._process_packet_scapy)
            
            return packets
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error in Scapy capture: {e}")
            
            # Provide helpful error information
            if "Error opening adapter" in str(e) or "123" in str(e):
                print(f"{Fore.YELLOW}💡 This interface may not be suitable for packet capture")
                print(f"{Fore.YELLOW}💡 Try using option 6 to list available interfaces")
                
                # Show working interfaces
                working_interfaces = self.get_working_interfaces()
                if working_interfaces:
                    print(f"{Fore.CYAN}💡 Working interfaces:")
                    for i, iface in enumerate(working_interfaces[:3]):
                        print(f"    {i+1}. {iface['name']} - {iface['description']}")
            
            return []
    
    def _process_packet_scapy(self, packet):
        """Process a single packet from Scapy"""
        try:
            # Extract basic information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                length = len(packet)
                
                # Update statistics
                self.packet_stats['total_packets'] += 1
                self.packet_stats['ip_addresses'][src_ip] += 1
                self.packet_stats['ip_addresses'][dst_ip] += 1
                self.packet_stats['packet_sizes'].append(length)
                
                # Protocol-specific processing
                if TCP in packet:
                    self.packet_stats['tcp_packets'] += 1
                    self.packet_stats['ports'][packet[TCP].sport] += 1
                    self.packet_stats['ports'][packet[TCP].dport] += 1
                    self.packet_stats['protocols']['TCP'] += 1
                    
                    # Print TCP packet info
                    print(f"{Fore.GREEN}[TCP] {src_ip}:{packet[TCP].sport} → {dst_ip}:{packet[TCP].dport} "
                          f"(Length: {length}, Flags: {packet[TCP].flags})")
                    
                elif UDP in packet:
                    self.packet_stats['udp_packets'] += 1
                    self.packet_stats['ports'][packet[UDP].sport] += 1
                    self.packet_stats['ports'][packet[UDP].dport] += 1
                    self.packet_stats['protocols']['UDP'] += 1
                    
                    print(f"{Fore.BLUE}[UDP] {src_ip}:{packet[UDP].sport} → {dst_ip}:{packet[UDP].dport} "
                          f"(Length: {length})")
                    
                elif ICMP in packet:
                    self.packet_stats['icmp_packets'] += 1
                    self.packet_stats['protocols']['ICMP'] += 1
                    
                    print(f"{Fore.YELLOW}[ICMP] {src_ip} → {dst_ip} "
                          f"(Type: {packet[ICMP].type}, Code: {packet[ICMP].code})")
                    
                else:
                    self.packet_stats['other_packets'] += 1
                    self.packet_stats['protocols'][f'Protocol_{protocol}'] += 1
                    
                    print(f"{Fore.MAGENTA}[Other] {src_ip} → {dst_ip} "
                          f"(Protocol: {protocol}, Length: {length})")
                
                # Store packet for analysis
                self.captured_packets.append(packet)
                
        except Exception as e:
            print(f"{Fore.RED}✗ Error processing packet: {e}")
    
    def analyze_packets(self):
        """Analyze captured packets and generate statistics"""
        if not self.captured_packets:
            print(f"{Fore.YELLOW}⚠ No packets to analyze")
            return
        
        print(f"\n{Fore.CYAN}📊 Packet Analysis Report")
        print("=" * 50)
        
        # Basic statistics
        total = self.packet_stats['total_packets']
        print(f"{Fore.WHITE}Total Packets Captured: {total}")
        print(f"{Fore.GREEN}TCP Packets: {self.packet_stats['tcp_packets']} ({self.packet_stats['tcp_packets']/total*100:.1f}%)")
        print(f"{Fore.BLUE}UDP Packets: {self.packet_stats['udp_packets']} ({self.packet_stats['udp_packets']/total*100:.1f}%)")
        print(f"{Fore.YELLOW}ICMP Packets: {self.packet_stats['icmp_packets']} ({self.packet_stats['icmp_packets']/total*100:.1f}%)")
        print(f"{Fore.MAGENTA}Other Packets: {self.packet_stats['other_packets']} ({self.packet_stats['other_packets']/total*100:.1f}%)")
        
        # Top IP addresses
        print(f"\n{Fore.CYAN}🌐 Top IP Addresses:")
        top_ips = self.packet_stats['ip_addresses'].most_common(10)
        for ip, count in top_ips:
            print(f"  {ip}: {count} packets")
        
        # Top ports
        print(f"\n{Fore.CYAN}🔌 Top Ports:")
        top_ports = self.packet_stats['ports'].most_common(10)
        for port, count in top_ports:
            service = self._get_service_name(port)
            print(f"  Port {port} ({service}): {count} packets")
        
        # Packet size statistics
        if self.packet_stats['packet_sizes']:
            sizes = self.packet_stats['packet_sizes']
            print(f"\n{Fore.CYAN}📏 Packet Size Statistics:")
            print(f"  Average: {np.mean(sizes):.1f} bytes")
            print(f"  Median: {np.median(sizes):.1f} bytes")
            print(f"  Min: {min(sizes)} bytes")
            print(f"  Max: {max(sizes)} bytes")
    
    def _get_service_name(self, port):
        """Get service name for common ports"""
        common_ports = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP-SUB', 465: 'SMTPS'
        }
        return common_ports.get(port, 'Unknown')
    
    def list_interfaces(self):
        """List available network interfaces"""
        try:
            if os.name == 'nt':  # Windows
                # Show working interfaces (recommended for capture)
                working_interfaces = self.get_working_interfaces()
                print(f"{Fore.CYAN}🌐 Working Network Interfaces (Recommended for Capture):")
                for i, iface in enumerate(working_interfaces):
                    ip_info = f" - {iface['ips'][0]}" if iface.get('ips') else ""
                    print(f"  {i+1}. {iface['name']} - {iface['description']}{ip_info}")
                
                # Also show all interfaces
                from scapy.arch.windows import get_windows_if_list
                all_interfaces = get_windows_if_list()
                print(f"\n{Fore.YELLOW}📋 All Available Interfaces:")
                for i, iface in enumerate(all_interfaces):
                    ip_info = f" - {iface['ips'][0]}" if iface.get('ips') else ""
                    print(f"  {i+1}. {iface['name']} - {iface.get('description', 'No description')}{ip_info}")
                
                return working_interfaces
            else:  # Linux/macOS
                from scapy.all import get_if_list
                interfaces = get_if_list()
                print(f"{Fore.CYAN}🌐 Available Network Interfaces:")
                for i, iface in enumerate(interfaces):
                    print(f"  {i+1}. {iface}")
                return interfaces
        except Exception as e:
            print(f"{Fore.RED}✗ Error listing interfaces: {e}")
            return []
    
    def generate_visualizations(self):
        """Generate visualizations of packet data"""
        if not self.captured_packets:
            print(f"{Fore.YELLOW}⚠ No packets to visualize")
            return
        
        try:
            # Create figure with subplots
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Packet Analysis Visualizations', fontsize=16)
            
            # Protocol distribution pie chart
            protocols = ['TCP', 'UDP', 'ICMP', 'Other']
            counts = [
                self.packet_stats['tcp_packets'],
                self.packet_stats['udp_packets'],
                self.packet_stats['icmp_packets'],
                self.packet_stats['other_packets']
            ]
            
            ax1.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
            ax1.set_title('Protocol Distribution')
            
            # Packet size histogram
            if self.packet_stats['packet_sizes']:
                ax2.hist(self.packet_stats['packet_sizes'], bins=50, alpha=0.7, color='skyblue')
                ax2.set_xlabel('Packet Size (bytes)')
                ax2.set_ylabel('Frequency')
                ax2.set_title('Packet Size Distribution')
            
            # Top IP addresses bar chart
            top_ips = self.packet_stats['ip_addresses'].most_common(10)
            if top_ips:
                ips, counts = zip(*top_ips)
                ax3.bar(range(len(ips)), counts, color='lightgreen')
                ax3.set_xlabel('IP Addresses')
                ax3.set_ylabel('Packet Count')
                ax3.set_title('Top IP Addresses')
                ax3.set_xticks(range(len(ips)))
                ax3.set_xticklabels(ips, rotation=45, ha='right')
            
            # Top ports bar chart
            top_ports = self.packet_stats['ports'].most_common(10)
            if top_ports:
                ports, counts = zip(*top_ports)
                ax4.bar(range(len(ports)), counts, color='lightcoral')
                ax4.set_xlabel('Port Numbers')
                ax4.set_ylabel('Packet Count')
                ax4.set_title('Top Ports')
                ax4.set_xticks(range(len(ports)))
                ax4.set_xticklabels(ports, rotation=45, ha='right')
            
            plt.tight_layout()
            plt.savefig('packet_analysis.png', dpi=300, bbox_inches='tight')
            print(f"{Fore.GREEN}✓ Visualization saved as 'packet_analysis.png'")
            plt.show()
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error generating visualizations: {e}")
    
    def run_interactive_mode(self):
        """Run the packet analyzer in interactive mode"""
        print(f"{Fore.CYAN}🚀 Hybrid Packet Analyzer - Interactive Mode")
        print("=" * 50)
        
        while True:
            print(f"\n{Fore.WHITE}Options:")
            print("1. Capture packets with Scapy")
            print("2. Capture packets with C++ (if available)")
            print("3. Analyze captured packets")
            print("4. Generate visualizations")
            print("5. Clear captured packets")
            print("6. List network interfaces")
            print("7. Exit")
            
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-7): ").strip()
            
            if choice == '1':
                print(f"{Fore.CYAN}💡 Tip: Use 'any' for auto-detection or specify an interface name")
                print(f"{Fore.CYAN}💡 Use option 6 to list working interfaces")
                interface = input("Enter interface (default: auto-detect): ").strip() or "any"
                count = int(input("Enter number of packets to capture (default: 100): ") or "100")
                self.capture_with_scapy(interface, count)
                
            elif choice == '2':
                if not self.cpp_lib:
                    print(f"{Fore.RED}✗ C++ library not available")
                    continue
                print(f"{Fore.CYAN}💡 Tip: Use 'any' for auto-detection or specify an interface name")
                print(f"{Fore.CYAN}💡 Use option 6 to list working interfaces")
                interface = input("Enter interface (default: auto-detect): ").strip() or "any"
                count = int(input("Enter number of packets to capture (default: 100): ") or "100")
                if self.start_capture_cpp(interface):
                    packets = self.capture_packets_cpp(count)
                    for packet in packets:
                        print(packet)
                    self.stop_capture_cpp()
                
            elif choice == '3':
                self.analyze_packets()
                
            elif choice == '4':
                self.generate_visualizations()
                
            elif choice == '5':
                self.captured_packets.clear()
                self.packet_stats = {
                    'total_packets': 0,
                    'tcp_packets': 0,
                    'udp_packets': 0,
                    'icmp_packets': 0,
                    'other_packets': 0,
                    'ip_addresses': Counter(),
                    'ports': Counter(),
                    'packet_sizes': [],
                    'protocols': Counter()
                }
                print(f"{Fore.GREEN}✓ Cleared captured packets")
                
            elif choice == '6':
                self.list_interfaces()
                
            elif choice == '7':
                print(f"{Fore.GREEN}👋 Goodbye!")
                break
                
            else:
                print(f"{Fore.RED}✗ Invalid choice. Please try again.")

def main():
    parser = argparse.ArgumentParser(description='Hybrid Packet Analyzer')
    parser.add_argument('--interface', '-i', default='any', help='Network interface to capture on')
    parser.add_argument('--count', '-c', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('--timeout', '-t', type=int, default=60, help='Capture timeout in seconds')
    parser.add_argument('--mode', '-m', choices=['scapy', 'cpp', 'interactive'], default='interactive',
                       help='Capture mode: scapy, cpp, or interactive')
    parser.add_argument('--analyze', '-a', action='store_true', help='Analyze packets after capture')
    parser.add_argument('--visualize', '-v', action='store_true', help='Generate visualizations')
    
    args = parser.parse_args()
    
    # Check for root/admin privileges
    if os.name == 'posix' and os.geteuid() != 0:
        print(f"{Fore.RED}✗ This program requires root privileges for packet capture")
        print(f"{Fore.YELLOW}⚠ Run with: sudo python3 packet_analyzer.py")
        return
    
    analyzer = HybridPacketAnalyzer()
    
    if args.mode == 'interactive':
        analyzer.run_interactive_mode()
    else:
        if args.mode == 'scapy':
            analyzer.capture_with_scapy(args.interface, args.count, args.timeout)
        elif args.mode == 'cpp':
            if analyzer.start_capture_cpp(args.interface):
                packets = analyzer.capture_packets_cpp(args.count)
                for packet in packets:
                    print(packet)
                analyzer.stop_capture_cpp()
        
        if args.analyze:
            analyzer.analyze_packets()
        
        if args.visualize:
            analyzer.generate_visualizations()

if __name__ == "__main__":
    main()

