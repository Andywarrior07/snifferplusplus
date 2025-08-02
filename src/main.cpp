#include "socket.cpp"
#include <cerrno>
#include <cstring>
#include <iostream>
#include <ostream>

int main() {
    // Step 1: open a socket
    int socket_file_descriptor = open_socket();

    if (socket_file_descriptor == -1) {
        std::cerr << "Error while creating file descriptor: "
            << std::strerror(errno) << std::endl;
        return -1;
    }
    // Step 2: inspect NICs

    // Step 3: bind to NIC

    // Step 4: recieve packages
    return 0;
}
