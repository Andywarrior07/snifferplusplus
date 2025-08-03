#include <arpa/inet.h>
#include <ifaddrs.h>

#include <cstring>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

#include "Packet.hpp"
#ifdef __linux__
#include <linux/if_ether.h>
#include <netinet/in.h>
#elif __APPLE__
#include <fcntl.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#error "unsupported platform: only availabe on linux and macos"
#endif

class Socket {
   public:
    bool initialize() {
#ifdef __linux__
        // [socket manual](https://linux.die.net/man/7/socket)
        // [packet manual](https://linux.die.net/man/7/packet)
        raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif __APPLE__
        raw_socket = open_bpf_socket();
#endif
        if (raw_socket == -1) {
            std::cerr << "Error while creating file descriptor: " << std::strerror(errno) << std::endl;
            return false;
        };

#ifdef __APPLE__
        if (!setup_bpf()) {
            std::cerr << "Error while setting up bpf: " << std::strerror(errno) << std::endl;
            raw_socket = -1;
            return false;
        }
#endif
        return true;
    }

    void read_packet() {
        auto buffer = std::make_unique<char[]>(buffer_size);

        std::cout << "Reading packets..." << std::endl;
        while (true) {
#ifdef __APPLE__
            const ssize_t data_size = read(raw_socket, buffer.get(), buffer_size);

            // std::cout << "Read " << data_size << " bytes" << std::endl;
            if (data_size < 0) {
                std::cerr << "Error while reading: " << std::strerror(errno) << std::endl;
                return;
            }
#else
            ssize_t data_size = recv(raw_socket, buffer.get(), buffer_size, 0);
#endif
            if (data_size > 0) {
#ifdef __APPLE__
                packet.process_bpf_buffer(reinterpret_cast<const uint8_t*>(buffer.get()), data_size);
#else
                packet.process_packet((uint8_t*) (buffer.get()), (size_t) data_size);

#endif
            }
        }
    }

    // Platform dependent. Creates an unbound file descriptor that we will
    // connect to a Network Interface.
    [[nodiscard]] int get_socket() const { return raw_socket; }

   private:
    int raw_socket = -1;
    u_int buffer_size = 4096;
    Packet packet;

#ifdef __APPLE__
    static int open_bpf_socket() {
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

    bool setup_bpf() {
        if (ioctl(raw_socket, BIOCGBLEN, &buffer_size) < 0) {
            std::cerr << "Error while setting up bpf: " << std::strerror(errno) << std::endl;
            return false;
        }

        const std::string interface = "en0";

        ifreq ifr = {};

        strncpy(ifr.ifr_name, interface.c_str(), sizeof(ifr.ifr_name));

        if (ioctl(raw_socket, BIOCSETIF, &ifr) < 0) {
            std::cerr << "Error while setting up bpf: " << std::strerror(errno) << std::endl;
            return false;
        }

        timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (ioctl(raw_socket, BIOCSRTIMEOUT, &timeout) < 0) {
            std::cerr << "Warning: could not configure timeout" << std::endl;
        }

        return true;
    }
#endif
};

ifaddrs* get_network_interfaces() {
    ifaddrs* ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Error while getting NICs: " << std::strerror(errno) << std::endl;
        exit(1);
    }

    std::vector<std::string> nics;
    std::unordered_set<std::string> viewed;

    for (const ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (viewed.insert(ifa->ifa_name).second) {
            nics.push_back(ifa->ifa_name);
        }
    }

    for (const auto& name : nics) {
        std::cout << "Name: " << name << std::endl;
    }

    return ifaddr;
}
