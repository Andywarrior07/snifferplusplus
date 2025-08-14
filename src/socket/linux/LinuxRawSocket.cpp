//
// Created by Borislav Castillo on 12-08-25.
//

#ifdef __linux__
#include "LinuxRawSocket.h"

#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

LinuxRawSocket::LinuxRawSocket() : raw_socket(-1), buffer_size(BUFFER_SIZE) {}

LinuxRawSocket::~LinuxRawSocket() {
    close_socket();
}

bool LinuxRawSocket::initialize(const string& nic_name) {
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (raw_socket == -1) {
        cerr << "Error while creating file descriptor: " << strerror(errno) << endl;
        return false;
    }

    if (!bind_socket(nic_name)) {
        cerr << "Error while setting up bpf: " << strerror(errno) << endl;
        raw_socket = -1;
        return false;
    }
    return true;
}

bool LinuxRawSocket::bind_socket(const string& nic_name) {
    size_t if_idx = if_nametoindex(nic_name.c_str());

    sockaddr_ll sll = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = static_cast<int>(if_idx)};

    if (bind(raw_socket, (struct sockaddr*) &sll, sizeof(sll)) == -1) {
        perror("bind");
        close(raw_socket);
        return false;
    }
    return true;
}

ssize_t LinuxRawSocket::read_packet(uint8_t* buffer) {
    ssize_t temp = 0;
    return temp;
}

void LinuxRawSocket::close_socket() {
    close(raw_socket);
}

#endif
