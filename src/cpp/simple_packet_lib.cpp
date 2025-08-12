#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {
    // Global variables
    static bool is_capturing = false;
    static std::vector<std::string> captured_packets;
    
    EXPORT int start_capture(const char* interface, int timeout) {
        std::cout << "Starting packet capture simulation on interface: " << interface << std::endl;
        is_capturing = true;
        captured_packets.clear();
        return 0; // Success
    }
    
    EXPORT int capture_packets(int count) {
        if (!is_capturing) {
            return -1;
        }
        
        std::cout << "Simulating capture of " << count << " packets..." << std::endl;
        
        // Simulate packet capture with some delay
        for (int i = 0; i < count && i < 10; i++) {
            std::string packet = "Simulated packet " + std::to_string(i + 1) + 
                               " - TCP 192.168.1.100:" + std::to_string(50000 + i) + 
                               " -> 8.8.8.8:443 (Length: " + std::to_string(100 + i * 10) + ")";
            captured_packets.push_back(packet);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        return captured_packets.size();
    }
    
    EXPORT int stop_capture() {
        std::cout << "Stopping packet capture simulation" << std::endl;
        is_capturing = false;
        return 0;
    }
    
    EXPORT int get_packet_count() {
        return captured_packets.size();
    }
    
    EXPORT const char* get_packet(int index) {
        if (index >= 0 && index < static_cast<int>(captured_packets.size())) {
            return captured_packets[index].c_str();
        }
        return nullptr;
    }
    
    EXPORT void clear_packets() {
        captured_packets.clear();
    }
}
