//
// Created by Andres Guerrero on 02-08-25.
//

#pragma once
#include <cstdint>
#include <vector>

struct PacketInfo {
    std::chrono::steady_clock::time_point timestamp;
    std::string src_ip;
    std::string dst_ip;
    std::string src_mac;
    std::string dst_mac;
    std::string ether_type_name;
    uint16_t ether_type;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t ip_version;
    std::string protocol;
    size_t payload_size = 0;
    std::vector<uint8_t> payload_preview;

    // PacketInfo()
    //     : timestamp(std::chrono::steady_clock::now())
    //       , ether_type(0)
    //       , src_port(0)
    //       , dst_port(0)
    //       , ip_version(0) {}
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
    PacketInfo info;
    size_t max_payload_preview = 64;

    std::optional<PacketInfo> parse_packet(const uint8_t* buffer, size_t size);
    void copy_payload_preview(const uint8_t* data, size_t size, std::vector<uint8_t>& preview) const;
    static std::string mac_to_string(const uint8_t* mac);
};