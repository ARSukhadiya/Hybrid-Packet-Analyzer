#!/usr/bin/env python3
"""
Test script for Hybrid Packet Analyzer
Verifies installation and basic functionality
"""

import sys
import os
import importlib
import subprocess
from pathlib import Path

def test_python_dependencies():
    """Test if all Python dependencies are available"""
    print("🔍 Testing Python dependencies...")
    
    dependencies = [
        'scapy',
        'psutil', 
        'colorama',
        'tabulate',
        'matplotlib',
        'numpy'
    ]
    
    missing = []
    for dep in dependencies:
        try:
            importlib.import_module(dep)
            print(f"  ✓ {dep}")
        except ImportError:
            print(f"  ✗ {dep} - NOT FOUND")
            missing.append(dep)
    
    if missing:
        print(f"\n❌ Missing dependencies: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("✓ All Python dependencies found!")
    return True

def test_cpp_library():
    """Test if C++ library is available"""
    print("\n🔍 Testing C++ library...")
    
    try:
        import ctypes
        
        # Try to find the library
        lib_names = [
            'libpacket_capture_lib.so',
            'packet_capture_lib.dll', 
            'libpacket_capture_lib.dylib'
        ]
        
        lib_found = False
        for lib_name in lib_names:
            lib_path = Path("build") / lib_name
            if lib_path.exists():
                try:
                    lib = ctypes.CDLL(str(lib_path))
                    print(f"  ✓ Found C++ library: {lib_name}")
                    lib_found = True
                    break
                except Exception as e:
                    print(f"  ✗ Failed to load {lib_name}: {e}")
        
        if not lib_found:
            print("  ⚠ C++ library not found - will use Scapy-only mode")
            return False
        
        return True
        
    except Exception as e:
        print(f"  ✗ Error testing C++ library: {e}")
        return False

def test_scapy_functionality():
    """Test basic Scapy functionality"""
    print("\n🔍 Testing Scapy functionality...")
    
    try:
        from scapy.all import IP, TCP, UDP
        
        # Create a simple packet
        packet = IP(dst="8.8.8.8")/TCP(dport=80)
        
        # Test packet creation
        if packet.haslayer(IP) and packet.haslayer(TCP):
            print("  ✓ Packet creation works")
        else:
            print("  ✗ Packet creation failed")
            return False
        
        # Test packet parsing
        packet_bytes = bytes(packet)
        parsed_packet = IP(packet_bytes)
        
        if parsed_packet.dst == "8.8.8.8":
            print("  ✓ Packet parsing works")
        else:
            print("  ✗ Packet parsing failed")
            return False
        
        print("✓ Scapy functionality verified!")
        return True
        
    except Exception as e:
        print(f"  ✗ Scapy test failed: {e}")
        return False

def test_network_interfaces():
    """Test if network interfaces are available"""
    print("\n🔍 Testing network interfaces...")
    
    try:
        from scapy.all import get_if_list
        
        interfaces = get_if_list()
        if interfaces:
            print(f"  ✓ Found {len(interfaces)} network interfaces:")
            for iface in interfaces[:5]:  # Show first 5
                print(f"    - {iface}")
            if len(interfaces) > 5:
                print(f"    ... and {len(interfaces) - 5} more")
            return True
        else:
            print("  ✗ No network interfaces found")
            return False
            
    except Exception as e:
        print(f"  ✗ Error getting interfaces: {e}")
        return False

def test_permissions():
    """Test if we have sufficient permissions"""
    print("\n🔍 Testing permissions...")
    
    if os.name == 'posix':  # Linux/macOS
        if os.geteuid() == 0:
            print("  ✓ Running as root (good for packet capture)")
            return True
        else:
            print("  ⚠ Not running as root - packet capture may fail")
            print("  💡 Run with: sudo python3 test_installation.py")
            return False
    else:  # Windows
        print("  ⚠ On Windows - ensure you're running as Administrator")
        return True

def run_basic_capture_test():
    """Run a basic packet capture test"""
    print("\n🔍 Running basic capture test...")
    
    try:
        from scapy.all import sniff, IP
        import threading
        import time
        
        # Set a short timeout
        timeout = 5
        packets_captured = []
        
        def packet_callback(packet):
            if IP in packet:
                packets_captured.append(packet)
        
        print(f"  📡 Starting capture for {timeout} seconds...")
        print("  💡 Try generating some network traffic (browse web, ping, etc.)")
        
        # Start capture in a thread
        capture_thread = threading.Thread(
            target=lambda: sniff(prn=packet_callback, timeout=timeout, store=0)
        )
        capture_thread.start()
        capture_thread.join()
        
        if packets_captured:
            print(f"  ✓ Successfully captured {len(packets_captured)} packets!")
            return True
        else:
            print("  ⚠ No packets captured (this is normal if no network activity)")
            return True
            
    except Exception as e:
        print(f"  ✗ Capture test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 Hybrid Packet Analyzer - Installation Test")
    print("=" * 50)
    
    tests = [
        ("Python Dependencies", test_python_dependencies),
        ("C++ Library", test_cpp_library),
        ("Scapy Functionality", test_scapy_functionality),
        ("Network Interfaces", test_network_interfaces),
        ("Permissions", test_permissions),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  ✗ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n📊 Test Results Summary")
    print("=" * 30)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Installation is complete.")
        print("\n🚀 You can now run the packet analyzer:")
        if os.name == 'posix':
            print("  sudo ./run_analyzer.sh")
        else:
            print("  run_analyzer.bat")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        print("\n💡 Common solutions:")
        print("  - Run: pip install -r requirements.txt")
        print("  - Run: python build.py")
        print("  - Ensure you have root/Administrator privileges")
    
    # Optional capture test
    if passed >= 4:  # At least basic functionality works
        print("\n🔍 Would you like to run a basic packet capture test? (y/n): ", end="")
        try:
            response = input().lower().strip()
            if response in ['y', 'yes']:
                run_basic_capture_test()
        except KeyboardInterrupt:
            print("\n⏹️  Test cancelled by user")

if __name__ == "__main__":
    main()

