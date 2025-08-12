#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>
#include <signal.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

// Global variables for packet capture
std::atomic<bool> running(false);
pcap_t *global_handle = nullptr;
std::vector<std::string> captured_packets;

// Packet information structure
struct packet_data {
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t length;
    uint8_t protocol;
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    char payload[1024];
};

// Signal handler
void signal_handler(int signum) {
    running = false;
}

// Convert IP address to string
void ip_to_string(uint32_t ip, char* str) {
    snprintf(str, 16, "%d.%d.%d.%d",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
}

// Packet handler callback
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr->caplen < 14 + 20) return; // Minimum Ethernet + IP header
    
    const u_char *ip_header = packet + 14; // Skip Ethernet header
    uint8_t ip_version = (ip_header[0] >> 4) & 0x0F;
    
    if (ip_version == 4) {
        packet_data pkt;
        pkt.timestamp_sec = pkthdr->ts.tv_sec;
        pkt.timestamp_usec = pkthdr->ts.tv_usec;
        pkt.length = pkthdr->len;
        pkt.protocol = ip_header[9];
        
        // Extract IP addresses
        uint32_t src_ip = (ip_header[12] << 24) | (ip_header[13] << 16) | 
                         (ip_header[14] << 8) | ip_header[15];
        uint32_t dst_ip = (ip_header[16] << 24) | (ip_header[17] << 16) | 
                         (ip_header[18] << 8) | ip_header[19];
        
        ip_to_string(src_ip, pkt.src_ip);
        ip_to_string(dst_ip, pkt.dst_ip);
        
        // Parse TCP/UDP ports
        if (pkt.protocol == 6 || pkt.protocol == 17) { // TCP or UDP
            const u_char *transport_header = ip_header + 20;
            pkt.src_port = (transport_header[0] << 8) | transport_header[1];
            pkt.dst_port = (transport_header[2] << 8) | transport_header[3];
        } else {
            pkt.src_port = 0;
            pkt.dst_port = 0;
        }
        
        // Copy payload (first 1024 bytes)
        size_t payload_size = std::min(pkthdr->caplen - 34, (bpf_u_int32)1024);
        memcpy(pkt.payload, packet + 34, payload_size);
        
        // Store packet info as string
        char packet_str[2048];
        snprintf(packet_str, sizeof(packet_str),
                "Time: %u.%06u | %s:%d -> %s:%d | Protocol: %d | Length: %u",
                pkt.timestamp_sec, pkt.timestamp_usec,
                pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
                pkt.protocol, pkt.length);
        
        captured_packets.push_back(std::string(packet_str));
    }
}

// Exported functions for Python

extern "C" {
    EXPORT int start_capture(const char* device, int timeout_ms) {
        char errbuf[PCAP_ERRBUF_SIZE];
        
        // Stop any existing capture
        if (global_handle) {
            pcap_close(global_handle);
            global_handle = nullptr;
        }
        
        // Clear previous packets
        captured_packets.clear();
        
        // Open device
        global_handle = pcap_open_live(device, BUFSIZ, 1, timeout_ms, errbuf);
        if (!global_handle) {
            std::cerr << "Couldn't open device " << device << ": " << errbuf << std::endl;
            return -1;
        }
        
        // Set filter for IP packets
        struct bpf_program fp;
        char filter_exp[] = "ip";
        if (pcap_compile(global_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter: " << pcap_geterr(global_handle) << std::endl;
            return -1;
        }
        
        if (pcap_setfilter(global_handle, &fp) == -1) {
            std::cerr << "Couldn't install filter: " << pcap_geterr(global_handle) << std::endl;
            return -1;
        }
        
        running = true;
        signal(SIGINT, signal_handler);
        
        std::cout << "Started packet capture on " << device << std::endl;
        return 0;
    }
    
    EXPORT int capture_packets(int count) {
        if (!global_handle || !running) {
            return -1;
        }
        
        int packets_captured = 0;
        while (running && packets_captured < count) {
            int result = pcap_dispatch(global_handle, 1, packet_handler, nullptr);
            if (result > 0) {
                packets_captured += result;
            } else if (result == -1) {
                std::cerr << "Error reading packets: " << pcap_geterr(global_handle) << std::endl;
                break;
            }
        }
        
        return packets_captured;
    }
    
    EXPORT void stop_capture() {
        running = false;
        if (global_handle) {
            pcap_close(global_handle);
            global_handle = nullptr;
        }
        std::cout << "Packet capture stopped." << std::endl;
    }
    
    EXPORT int get_packet_count() {
        return captured_packets.size();
    }
    
    EXPORT const char* get_packet(int index) {
        if (index >= 0 && index < (int)captured_packets.size()) {
            return captured_packets[index].c_str();
        }
        return nullptr;
    }
    
    EXPORT void clear_packets() {
        captured_packets.clear();
    }
}

