#include <iostream>
#include <unordered_set>
#include <ifaddrs.h>
#include "Packet.hpp"
#include "socket/RawSocket.h"

std::string get_user_input(const std::vector<std::string>& nic_names);
std::vector<std::string> get_network_interfaces();

int main() {
    // Step 1: inspect network interfaces.
    std::vector<std::string> nic_names = get_network_interfaces();

    // Step 2: prompt the user to pick an interface.
    std::string selected_nic = get_user_input(nic_names);

    // Step 3: open a socket

    const RawSocket socket;

    if (!socket.initialize(selected_nic)) {
        return -1;
    }

    const auto packet = std::make_unique<Packet>();
    const auto buffer = std::make_unique<uint8_t[]>(4096);

    while (true) {
        const ssize_t data_size = socket.read_packet(buffer.get());

        if (data_size < 0) {
            std::cerr << "Error reading packet: " << std::strerror(errno) << std::endl;
            break;
        }

        if (data_size == 0) {
            continue; // No hay datos, continuar
        }


        packet->process_bpf_buffer(buffer.get(), static_cast<size_t>(data_size));
    }

    // Step 3: bind to NIC

    // Step 4: recieve packages
    return 0;
}

std::vector<std::string> get_network_interfaces() {
    ifaddrs* ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Error while getting NICs: " << std::strerror(errno) << std::endl;
        exit(1);
    }

    unordered_set<std::string> names;

    for (const ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        names.insert(ifa->ifa_name);
    }
    freeifaddrs(ifaddr);

    std::vector<std::string> unique_names(names.begin(), names.end());
    return unique_names;
}

// Prompts the user to select a NIC.
// Returns a valid name or exits with status 1.
std::string get_user_input(const std::vector<std::string>& nic_names) {
    std::cout << "Select a network interface:\n\n";
    int index = 1;
    for (const auto& name : nic_names) {
        std::cout << index++ << ": " << name << std::endl;
    }
    std::cout << std::endl;

    unsigned long nic_idx;
    std::cin >> nic_idx;

    if (nic_idx < 1 || nic_idx > (unsigned long) nic_names.size()) {
        std::cerr << "unknown network interface\n";
        exit(1);
    }

    return nic_names[nic_idx - 1];
}
