//
// Created by Andres Guerrero on 08-08-25.
//

#include "MacRawSocket.h"

#ifdef __APPLE__
#include <unistd.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

#include <iostream>

using namespace std;

MacRawSocket::MacRawSocket() : raw_socket(-1), buffer_size(BUFFER_SIZE) {}

MacRawSocket::~MacRawSocket() {
    close_socket();
}

bool MacRawSocket::initialize(const string& nic_name) {
    raw_socket = open_bpf_buffer();

    if (raw_socket == -1) {
        cerr << "Error while creating file descriptor: " << strerror(errno) << endl;
        return false;
    }

    if (!setup_bpf(nic_name)) {
        cerr << "Error while setting up bpf: " << strerror(errno) << endl;
        raw_socket = -1;
        return false;
    }
    return true;
}


int MacRawSocket::open_bpf_buffer() {
    int socket = -1;
    char bpf_device[12];

    for (int i = 0; i < 255; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        socket = open(bpf_device, O_RDWR);

        if (socket != -1) {
            std::cout << "Using bpf: " << bpf_device << std::endl;

            return socket;
        }
    }

    return -1;
}

bool MacRawSocket::setup_bpf(const string& nic_name) {
    if (ioctl(raw_socket, BIOCGBLEN, &buffer_size) < 0) {
        std::cerr << "Error while setting up bpf: " << std::strerror(errno) << std::endl;
        return false;
    }
    std::cout << "nic_name: " << nic_name << std::endl;
    ifreq ifr = {};

    strncpy(ifr.ifr_name, nic_name.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(raw_socket, BIOCSETIF, &ifr) < 0) {
        std::cerr << "Error while setting up bpf: " << std::strerror(errno) << std::endl;
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (ioctl(raw_socket, BIOCSRTIMEOUT, &timeout) < 0) {
        std::cerr << "Warning: could not configure timeout" << std::endl;
    }

    return true;
}

ssize_t MacRawSocket::read_packet(uint8_t* buffer) {
    if (raw_socket == -1) {
        return -1;
    }

    const ssize_t data_size = read(raw_socket, buffer, buffer_size);

    if (data_size < 0) {
        std::cerr << "Error while reading: " << std::strerror(errno) << std::endl;
        return -1;
    }

    return data_size;
}

void MacRawSocket::close_socket() {
    if (raw_socket != -1) {
        cout << "Closing socket..." << endl;

        ::close(raw_socket);
        raw_socket = -1;
    }
}

#endif