#!/usr/bin/env python3
"""
Build script for Hybrid Packet Analyzer
Compiles C++ components and sets up the project
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def run_command(command, cwd=None):
    """Run a command and return success status"""
    try:
        result = subprocess.run(command, shell=True, cwd=cwd, 
                              capture_output=True, text=True, check=True)
        print(f"✓ {command}")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {command}")
        print(f"Error: {e.stderr}")
        return False

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    # Check for CMake
    if not run_command("cmake --version"):
        print("❌ CMake not found. Please install CMake.")
        return False
    
    # Check for pkg-config (Linux/macOS only)
    if platform.system() != "Windows":
        if not run_command("pkg-config --version"):
            print("❌ pkg-config not found. Please install pkg-config.")
            return False
        
        # Check for libpcap (Linux/macOS only)
        if not run_command("pkg-config --exists libpcap"):
            print("❌ libpcap not found. Please install libpcap-dev.")
            return False
    else:
        # Windows - check for Npcap/WinPcap
        print("ℹ️  Windows detected - will check for Npcap/WinPcap during build")
    
    print("✓ All dependencies found!")
    return True

def create_build_directory():
    """Create build directory"""
    build_dir = Path("build")
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir()
    return build_dir

def build_cpp_components(build_dir):
    """Build C++ components using CMake"""
    print("🔨 Building C++ components...")
    
    # Configure with CMake
    if not run_command("cmake ..", cwd=build_dir):
        return False
    
    # Build
    if not run_command("cmake --build .", cwd=build_dir):
        return False
    
    print("✓ C++ components built successfully!")
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    
    if not run_command(f"{sys.executable} -m pip install -r requirements.txt"):
        print("❌ Failed to install Python dependencies")
        return False
    
    print("✓ Python dependencies installed!")
    return True

def create_launcher_scripts():
    """Create launcher scripts for different platforms"""
    print("🚀 Creating launcher scripts...")
    
    # Windows batch file
    if platform.system() == "Windows":
        with open("run_analyzer.bat", "w") as f:
            f.write("@echo off\n")
            f.write("echo Starting Hybrid Packet Analyzer...\n")
            f.write("python src/python/packet_analyzer.py %*\n")
            f.write("pause\n")
        print("✓ Created run_analyzer.bat")
    
    # Unix shell script
    else:
        with open("run_analyzer.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'Starting Hybrid Packet Analyzer...'\n")
            f.write("python3 src/python/packet_analyzer.py \"$@\"\n")
        
        # Make executable
        os.chmod("run_analyzer.sh", 0o755)
        print("✓ Created run_analyzer.sh")

def main():
    """Main build function"""
    print("🚀 Hybrid Packet Analyzer - Build Script")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Build failed due to missing dependencies")
        return False
    
    # Create build directory
    build_dir = create_build_directory()
    
    # Build C++ components
    if not build_cpp_components(build_dir):
        print("❌ Failed to build C++ components")
        return False
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("❌ Failed to install Python dependencies")
        return False
    
    # Create launcher scripts
    create_launcher_scripts()
    
    print("\n🎉 Build completed successfully!")
    print("\n📋 Usage:")
    if platform.system() == "Windows":
        print("  run_analyzer.bat                    # Run in interactive mode")
        print("  run_analyzer.bat --help             # Show help")
        print("  run_analyzer.bat --mode scapy -c 50 # Capture 50 packets with Scapy")
    else:
        print("  ./run_analyzer.sh                   # Run in interactive mode")
        print("  ./run_analyzer.sh --help            # Show help")
        print("  ./run_analyzer.sh --mode scapy -c 50 # Capture 50 packets with Scapy")
    
    print("\n⚠️  Note: Packet capture requires administrator/root privileges")
    if platform.system() != "Windows":
        print("   Run with: sudo ./run_analyzer.sh")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

