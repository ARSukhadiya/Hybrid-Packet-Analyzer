#!/usr/bin/env python3
"""
Windows Network Interface Helper
Helps identify and test network interfaces for packet capture
"""

import os
import sys
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

def list_windows_interfaces():
    """List all available network interfaces on Windows"""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        
        # Filter working interfaces
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
        
        print(f"{Fore.CYAN}🌐 Working Network Interfaces (Recommended for Capture):")
        print("=" * 60)
        
        for i, iface in enumerate(working_interfaces):
            name = iface['name']
            description = iface['description']
            ip = iface['ips'][0] if iface['ips'] else 'No IP'
            
            print(f"{Fore.GREEN}{i+1:2d}. {Fore.WHITE}{name}")
            print(f"     Description: {description}")
            print(f"     IP Address:  {ip}")
            print(f"     Index:       {iface['index']}")
            print()
        
        print(f"{Fore.YELLOW}📋 All Available Interfaces:")
        print("=" * 60)
        
        for i, iface in enumerate(interfaces):
            name = iface['name']
            description = iface.get('description', 'No description')
            ip = iface.get('ips', ['No IP'])[0] if iface.get('ips') else 'No IP'
            
            print(f"{Fore.GREEN}{i+1:2d}. {Fore.WHITE}{name}")
            print(f"     Description: {description}")
            print(f"     IP Address:  {ip}")
            print()
        
        return working_interfaces
        
    except ImportError:
        print(f"{Fore.RED}✗ Scapy not installed or not available")
        return []
    except Exception as e:
        print(f"{Fore.RED}✗ Error listing interfaces: {e}")
        return []

def test_interface_capture(interface_name, count=5):
    """Test packet capture on a specific interface"""
    try:
        from scapy.all import sniff, IP
        
        print(f"{Fore.YELLOW}🧪 Testing capture on interface: {interface_name}")
        print(f"{Fore.CYAN}📡 Capturing {count} packets... (Press Ctrl+C to stop early)")
        
        # For Windows, use interface index for more reliable capture
        if os.name == 'nt':
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            
            # Find interface by name or description
            iface_index = None
            for i, iface in enumerate(interfaces):
                if iface['name'] == interface_name or iface.get('description') == interface_name:
                    iface_index = i
                    interface_name = iface['name']  # Use exact name
                    break
            
            if iface_index is not None:
                print(f"{Fore.GREEN}✓ Using interface index {iface_index}: {interface_name}")
                # Use interface index for capture
                packets = sniff(iface=iface_index, count=count, timeout=10, store=1)
            else:
                print(f"{Fore.RED}✗ Interface '{interface_name}' not found")
                return False
        else:
            # Linux/macOS - use interface name directly
            packets = sniff(iface=interface_name, count=count, timeout=10, store=1)
        
        if packets:
            print(f"{Fore.GREEN}✓ Successfully captured {len(packets)} packets!")
            
            # Show some packet details
            for i, packet in enumerate(packets[:3]):  # Show first 3
                if IP in packet:
                    print(f"  {i+1}. {packet[IP].src} → {packet[IP].dst} (Length: {len(packet)})")
                else:
                    print(f"  {i+1}. Non-IP packet (Length: {len(packet)})")
            
            if len(packets) > 3:
                print(f"  ... and {len(packets) - 3} more packets")
                
            return True
        else:
            print(f"{Fore.YELLOW}⚠ No packets captured (this is normal if no network activity)")
            return True
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⏹️  Capture stopped by user")
        return True
    except Exception as e:
        print(f"{Fore.RED}✗ Error testing interface: {e}")
        return False

def main():
    """Main function"""
    print(f"{Fore.CYAN}🖥️  Windows Network Interface Helper")
    print("=" * 50)
    
    # Check if running as administrator
    if os.name == 'nt':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}⚠ Warning: Not running as Administrator")
                print(f"{Fore.YELLOW}💡 Packet capture may fail. Run as Administrator for best results.")
                print()
        except:
            pass
    
    # List interfaces
    interfaces = list_windows_interfaces()
    
    if not interfaces:
        print(f"{Fore.RED}✗ No interfaces found or error occurred")
        return
    
    # Interactive testing
    while True:
        print(f"\n{Fore.WHITE}Options:")
        print("1. Test capture on an interface")
        print("2. Show interface details again")
        print("3. Exit")
        
        choice = input(f"\n{Fore.YELLOW}Enter your choice (1-3): ").strip()
        
        if choice == '1':
            try:
                interface_num = int(input(f"Enter interface number (1-{len(interfaces)}): ")) - 1
                if 0 <= interface_num < len(interfaces):
                    interface_name = interfaces[interface_num]['name']
                    count = int(input("Enter number of packets to capture (default: 5): ") or "5")
                    test_interface_capture(interface_name, count)
                else:
                    print(f"{Fore.RED}✗ Invalid interface number")
            except ValueError:
                print(f"{Fore.RED}✗ Please enter a valid number")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}⏹️  Cancelled")
                
        elif choice == '2':
            list_windows_interfaces()
            
        elif choice == '3':
            print(f"{Fore.GREEN}👋 Goodbye!")
            break
            
        else:
            print(f"{Fore.RED}✗ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
