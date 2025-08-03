#include <ifaddrs.h>

#include <cstdlib>
#include <iostream>
#include <ostream>
#include <string>
#include <unordered_set>
#include <vector>

#include "socket.cpp"

std::string get_user_input(const std::vector<std::string>& nic_names);

int main() {
    // Step 1: open a socket
    Socket socket;

    if (!socket.initialize()) {
        return -1;
    }

    // Step 2: inspect NICs
    std::vector<std::string> nic_names = get_network_interfaces();

    // Step 3: prompt user
    std::string selected_nic = get_user_input(nic_names);

    socket.read_packet();

    // Step 3: bind to NIC

    // Step 4: recieve packages
    return 0;
}

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

    return nic_names[nic_idx];
}
