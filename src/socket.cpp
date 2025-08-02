#include <iostream>
#if defined(__linux__)
#include <linux/if_ether.h>
#include <netinet/in.h>
// [socket manual](https://linux.die.net/man/7/socket)
// [packet manual](https://linux.die.net/man/7/packet)
#elif defined(__APPLE__)
#include <fcntl.h>
#include <sys/socket.h>
#else
#error "unsupported platform: only availabe on linux and macos"
#endif

class Socket {
public:
    bool initialize() {
#ifdef __linux__
        raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif __APPLE__
        raw_socket = open_bpf_socket();
#endif
        if (raw_socket == -1) {
            std::cerr << "Error while creating file descriptor: "
                << std::strerror(errno) << std::endl;
            return false;
        };

        return true;
    }

    int get_socket() const { return raw_socket; }

private:
    int raw_socket = -1;

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
#endif
};
