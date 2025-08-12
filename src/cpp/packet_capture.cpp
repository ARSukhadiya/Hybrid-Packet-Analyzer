#include <pcap.h>
#include <iostream>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>
#include <signal.h>

// Global flag for graceful shutdown
std::atomic<bool> running(true);

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Shutting down gracefully..." << std::endl;
    running = false;
}

// Packet header structure
struct packet_info {
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t length;
    uint32_t captured_length;
    uint8_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

// Callback function for packet processing
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    packet_info info;
    info.timestamp_sec = pkthdr->ts.tv_sec;
    info.timestamp_usec = pkthdr->ts.tv_usec;
    info.length = pkthdr->len;
    info.captured_length = pkthdr->caplen;
    
    // Parse IP header (assuming Ethernet frame)
    if (info.captured_length < 14 + 20) return; // Minimum Ethernet + IP header
    
    const u_char *ip_header = packet + 14; // Skip Ethernet header
    uint8_t ip_version = (ip_header[0] >> 4) & 0x0F;
    
    if (ip_version == 4) {
        uint8_t protocol = ip_header[9];
        info.protocol = protocol;
        
        // Extract IP addresses
        info.src_ip = (ip_header[12] << 24) | (ip_header[13] << 16) | 
                     (ip_header[14] << 8) | ip_header[15];
        info.dst_ip = (ip_header[16] << 24) | (ip_header[17] << 16) | 
                     (ip_header[18] << 8) | ip_header[19];
        
        // Parse TCP/UDP ports if applicable
        if (protocol == 6 || protocol == 17) { // TCP or UDP
            const u_char *transport_header = ip_header + 20;
            info.src_port = (transport_header[0] << 8) | transport_header[1];
            info.dst_port = (transport_header[2] << 8) | transport_header[3];
        }
        
        // Print packet info
        char src_ip_str[16], dst_ip_str[16];
        snprintf(src_ip_str, sizeof(src_ip_str), "%d.%d.%d.%d",
                (info.src_ip >> 24) & 0xFF, (info.src_ip >> 16) & 0xFF,
                (info.src_ip >> 8) & 0xFF, info.src_ip & 0xFF);
        snprintf(dst_ip_str, sizeof(dst_ip_str), "%d.%d.%d.%d",
                (info.dst_ip >> 24) & 0xFF, (info.dst_ip >> 16) & 0xFF,
                (info.dst_ip >> 8) & 0xFF, info.dst_ip & 0xFF);
        
        std::cout << "[" << info.timestamp_sec << "." << info.timestamp_usec << "] "
                  << src_ip_str << ":" << info.src_port << " -> "
                  << dst_ip_str << ":" << info.dst_port
                  << " (Protocol: " << (int)info.protocol << ", Length: " << info.length << ")" << std::endl;
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    std::string device = "any"; // Default to any interface
    
    // Parse command line arguments
    if (argc > 1) {
        device = argv[1];
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "Starting packet capture on interface: " << device << std::endl;
    std::cout << "Press Ctrl+C to stop..." << std::endl;
    
    // Open the device for packet capture
    handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << device << ": " << errbuf << std::endl;
        return 1;
    }
    
    // Set filter to capture only IP packets
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    
    // Start packet capture loop
    while (running) {
        pcap_dispatch(handle, 1, packet_handler, nullptr);
    }
    
    // Cleanup
    pcap_close(handle);
    std::cout << "Packet capture stopped." << std::endl;
    
    return 0;
}

