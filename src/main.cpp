#include "socket.cpp"
#include <cerrno>
#include <cstring>
#include <iostream>
#include <ostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    // Step 1: open a socket
    Socket socket;

    if (!socket.initialize()) {
        return -1;
    }

    const int socket_file_descriptor = socket.get_socket();

    if (socket_file_descriptor == -1) {
        std::cerr << "Error while creating file descriptor: "
            << std::strerror(errno) << std::endl;
        return -1;
    }
    // Step 2: inspect NICs
    ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Error while getting NICs: "
            << std::strerror(errno) << std::endl;
        return -1;
    }

    for (const ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        std::cout << "Interface: " << ifa->ifa_name << "\n";

        if (ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            const sockaddr_in *sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
            std::cout << "  IPv4 Address: " << ip << "\n";


        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            char ip[INET6_ADDRSTRLEN];
            const sockaddr_in6 *sa = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            inet_ntop(AF_INET6, &(sa->sin6_addr), ip, INET6_ADDRSTRLEN);
            std::cout << "  IPv6 Address: " << ip << "\n";
        }
    }


    // Step 3: bind to NIC

    // Step 4: recieve packages
    freeifaddrs(ifaddr);
    return 0;
}
