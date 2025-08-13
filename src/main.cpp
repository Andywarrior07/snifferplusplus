#include <ifaddrs.h>
#include <string.h>

#include <iostream>
#include <unordered_set>

// #include "Packet.hpp"
#include "socket/RawSocket.h"

std::string get_user_input(const std::vector<std::string>& nic_names);
std::vector<std::string> get_network_interfaces();

int main() {
    // Step 1: inspect network interfaces.
    vector<string> nic_names = get_network_interfaces();

    // Step 2: prompt the user to pick an interface.
    string selected_nic = get_user_input(nic_names);

    // Step 3: open a socket

    const RawSocket socket;

    if (!socket.initialize(selected_nic)) {
        return -1;
    }

    // Step 4: recieve packages
    return 0;
}

// Inspect Network Interfaces using `getifaddrs()`
vector<string> get_network_interfaces() {
    // Linked list containing a chain of `ifaddrs`
    ifaddrs* interface_address;

    // Use `getifaddrs()` to populate out `interface_address` linker list
    if (getifaddrs(&interface_address) == -1) {
        std::cerr << "Error while getting NICs: " << strerror(errno) << std::endl;
        exit(1);
    }

    // Iterate over linked list and store names of NICs in set to dedupe.
    unordered_set<string> ni_names;
    for (const ifaddrs* ifa = interface_address; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        ni_names.insert(ifa->ifa_name);
    }

    // Call destructor, since we already copied the names
    freeifaddrs(interface_address);

    // Create vector from set for ease of iteration
    vector<string> unique_names(ni_names.begin(), ni_names.end());
    return unique_names;
}

// Prompts the user to select a NIC.
// Returns a valid name or exits with status 1.
string get_user_input(const vector<std::string>& nic_names) {
    std::cout << "Select a network interface:\n\n";

    // Start index at 1 because Lua
    int index = 1;
    for (const auto& name : nic_names) {
        std::cout << index++ << ": " << name << std::endl;
    }
    std::cout << std::endl;

    // Save user selection and cast to uint64
    size_t nic_idx;
    std::cin >> nic_idx;

    if (nic_idx < 1 || nic_idx > nic_names.size()) {
        std::cerr << "unknown network interface\n";
        exit(1);
    }

    // Account for Lua index
    return nic_names[nic_idx - 1];
}
