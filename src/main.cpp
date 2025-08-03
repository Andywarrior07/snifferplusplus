// #include <ifaddrs.h>

// #include <iostream>
// #include <ostream>

#include "socket.cpp"

int main() {
    // Step 1: open a socket
    Socket socket;

    if (!socket.initialize()) {
        return -1;
    }

    const int socket_file_descriptor = socket.get_socket();

    // Step 2: inspect NICs
    ifaddrs* ifaddr = get_network_interfaces();

    socket.read_packet();

    // Step 3: bind to NIC
    // std::string nic_selected;
    //
    // std::cout << "Select a network interface\n";
    // std::cin >> nic_selected;

    // Step 4: recieve packages
    freeifaddrs(ifaddr);
    return 0;
}
