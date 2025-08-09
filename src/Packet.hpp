//
// Created by Andres Guerrero on 02-08-25.
//

#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct PacketInfo {
    /// High-resolution timestamp captured when packet parsing begins
    std::chrono::steady_clock::time_point timestamp;

    /// Source IP address in dotted decimal notation (e.g., "192.168.1.1")
    std::string src_ip;

    /// Destination IP address in dotted decimal notation (e.g., "192.168.1.100")
    std::string dst_ip;

    /// Source MAC address in colon-separated hexadecimal format (e.g., "aa:bb:cc:dd:ee:ff")
    std::string src_mac;

    /// Destination MAC address in colon-separated hexadecimal format (e.g., "11:22:33:44:55:66")
    std::string dst_mac;

    /// Human-readable ethernet type name (currently unused but reserved for future enhancement)
    std::string ether_type_name;

    /// Ethernet type value from the ethernet header (e.g., 0x0800 for IPv4)
    uint16_t ether_type;

    /// Source port number in host byte order (0 for protocols without port concept)
    uint16_t src_port;

    /// Destination port number in host byte order (0 for protocols without port concept)
    uint16_t dst_port;

    /// IP version number (currently only IPv4 = 4 is supported)
    uint8_t ip_version;

    /// Protocol name as string ("TCP", "UDP", "ICMP", or "OTHER(N)" where N is protocol number)
    std::string protocol;

    /// Size of the application-layer payload in bytes (excludes all headers)
    size_t payload_size = 0;

    /// Preview of the application payload data (limited to first 64 bytes by default)
    std::vector<uint8_t> payload_preview;
};

class Packet {
public:
    Packet();
    ~Packet() = default;

#ifdef __APPLE__
    void process_bpf_buffer(const uint8_t* buffer, size_t size);
#endif
    void process_packet(const uint8_t* buffer, size_t size);

private:
    /// Internal packet information storage (reused for each parsed packet)
    PacketInfo info;

    /// Maximum number of payload bytes to store in preview (default: 64)
    size_t max_payload_preview = 64;

    std::optional<PacketInfo> parse_packet(const uint8_t* buffer, size_t size);

    void copy_payload_preview(const uint8_t* data, size_t size, std::vector<uint8_t>& preview) const;

    static std::string mac_to_string(const uint8_t* mac);
};