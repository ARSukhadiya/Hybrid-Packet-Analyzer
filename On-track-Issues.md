'''
The error "Error opening adapter: The filename, directory name, or volume label syntax is incorrect. (123)" occurs because Windows doesn't support the interface name "any" like Linux/macOS does.

✅ Solutions Implemented
1. Automatic Interface Detection
The tool now automatically detects available Windows interfaces
When you use "any", it automatically selects the first available interface
Provides helpful feedback about which interface is being used
2. Better Error Handling
More informative error messages
Shows available interfaces when errors occur
Provides specific guidance for Windows users
3. New Interface Helper Script
Created windows_interface_helper.py to help identify interfaces
Lists all available network interfaces with descriptions
Allows testing capture on specific interfaces
4. Enhanced Interactive Mode
Added option 6 to list network interfaces
Better guidance for interface selection
Tips for Windows-specific interface names
'''

'''
🔨 Building C++ components...
✗ cmake ..
Error: CMake Error at C:/Program Files/CMake/share/cmake-4.1/Modules/FindPackageHandleStandardArgs.cmake:227 (message):
  Could NOT find PkgConfig (missing: PKG_CONFIG_EXECUTABLE)
Call Stack (most recent call first):
  C:/Program Files/CMake/share/cmake-4.1/Modules/FindPackageHandleStandardArgs.cmake:591 (_FPHSA_FAILURE_MESSAGE)
  C:/Program Files/CMake/share/cmake-4.1/Modules/FindPkgConfig.cmake:108 (find_package_handle_standard_args)
  CMakeLists.txt:8 (find_package)

❌ Failed to build C++ components
'''

'''
Error opening adapter: The filename, directory name, or volume label syntax is incorrect. (123) occurs because Scapy is trying to use interface names that contain special characters that aren't valid for Windows file paths.
🛠️ Solution: Create a Windows-Specific Interface Handler


'''


