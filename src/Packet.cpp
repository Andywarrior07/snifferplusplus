//
// Created by Andres Guerrero on 02-08-99.
//

#include "Packet.hpp"

#include <arpa/inet.h>
#include <netinet/ip.h>

#ifdef __APPLE__
#include <net/bpf.h>
#endif

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <iostream>

Packet::Packet() : info() {}

#ifdef __APPLE__
void Packet::process_bpf_buffer(const uint8_t* buffer, const size_t size) {
    const uint8_t* ptr = buffer;

    while (ptr < buffer + size) {
        auto bpf_header = reinterpret_cast<const bpf_hdr*>(ptr);

        // Valida que el header sea valido
        if (bpf_header->bh_caplen == 0 || ptr + bpf_header->bh_caplen > buffer + size) {
            break;
        }

        const uint8_t* packet = ptr + bpf_header->bh_hdrlen;
        process_packet(packet, bpf_header->bh_caplen);

        ptr += bpf_header->bh_hdrlen + bpf_header->bh_caplen;
    }
}
#endif

void Packet::process_packet(const uint8_t* buffer, const size_t size) {
    const auto packet_info = parse_packet(buffer, size);

    if (!packet_info) {
        return;
    }

    std::cout << "========== SOCKET INFO ==========" << std::endl;
    std::cout << "src_ip: " << packet_info->src_ip << std::endl;
    std::cout << "dst_ip: " << packet_info->dst_ip << std::endl;
    std::cout << "src_mac: " << packet_info->src_mac << std::endl;
    std::cout << "dst_mac: " << packet_info->dst_mac << std::endl;
    std::cout << "ether_type: " << packet_info->ether_type << std::endl;
    std::cout << "src_port: " << packet_info->src_port << std::endl;
    std::cout << "dst_port: " << packet_info->dst_port << std::endl;
    std::cout << "ip_version: " << packet_info->ip_version << std::endl;
    std::cout << "protocol: " << packet_info->protocol << std::endl;
    std::cout << "payload_size: " << packet_info->payload_size << std::endl;
    std::cout << "timestamp: " << packet_info->timestamp.time_since_epoch().count() << std::endl;
    std::cout << "==================================" << std::endl;
    // std::cout << "payload_preview: " << packet_info->payload_preview << std::endl;
}

std::optional<PacketInfo> Packet::parse_packet(const uint8_t* buffer, size_t size) {
    info.timestamp = std::chrono::steady_clock::now();

    const uint8_t* ip_header = buffer;

    if (size < sizeof(ether_header)) {
        return std::nullopt;
    }

    const auto eth = reinterpret_cast<const struct ether_header*>(buffer);

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return std::nullopt;
    }

    info.src_mac = mac_to_string(eth->ether_shost);
    info.dst_mac = mac_to_string(eth->ether_dhost);

    ip_header = buffer + sizeof(ether_header);

    size -= sizeof(ether_header);

    if (size < sizeof(ip)) {
        return std::nullopt;
    }

    const auto* ip = reinterpret_cast<const struct ip*>(ip_header);

    // As long as only IPv4 is used
    if (ip->ip_v != 4) {
        return std::nullopt;
    }

    info.ip_version = ip->ip_v;

    info.src_ip = inet_ntoa(ip->ip_src);
    info.dst_ip = inet_ntoa(ip->ip_dst);

    size_t ip_header_len = ip->ip_hl * 4;
    if (ip_header_len > size) {
        return std::nullopt;
    }

    const uint8_t* payload = ip_header + ip_header_len;
    size_t payload_size = size - ip_header_len;

    switch (ip->ip_p) {
        case IPPROTO_TCP: {
            if (payload_size < sizeof(tcphdr)) return std::nullopt;

            const auto* tcp = reinterpret_cast<const struct tcphdr*>(payload);
            info.protocol = "TCP";
            info.src_port = ntohs(tcp->th_sport);
            info.dst_port = ntohs(tcp->th_dport);

            if (size_t tcp_header_len = tcp->th_off * 4; payload_size > tcp_header_len) {
                info.payload_size = payload_size - tcp_header_len;
                const uint8_t* app_data = payload + tcp_header_len;
                copy_payload_preview(app_data, info.payload_size, info.payload_preview);
            }
            break;
        }
        case IPPROTO_UDP: {
            if (payload_size < sizeof(udphdr)) return std::nullopt;

            const auto* udp = reinterpret_cast<const struct udphdr*>(payload);
            info.protocol = "UDP";
            info.src_port = ntohs(udp->uh_sport);
            info.dst_port = ntohs(udp->uh_dport);

            if (payload_size > sizeof(udphdr)) {
                info.payload_size = payload_size - sizeof(udphdr);
                const uint8_t* app_data = payload + sizeof(udphdr);
                copy_payload_preview(app_data, info.payload_size, info.payload_preview);
            }
            break;
        }
        case IPPROTO_ICMP:
            info.protocol = "ICMP";
            info.payload_size = payload_size;
            copy_payload_preview(payload, payload_size, info.payload_preview);
            break;
        default:
            info.protocol = "OTHER(" + std::to_string(ip->ip_p) + ")";
            info.payload_size = payload_size;
            break;
    }

    return info;
}

void Packet::copy_payload_preview(const uint8_t* data, const size_t size, std::vector<uint8_t>& preview) const {
    const size_t copy_size = std::min(size, max_payload_preview);
    preview.assign(data, data + copy_size);
}

std::string Packet::mac_to_string(const uint8_t* mac) {
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
