#if defined(__linux__)
#include <linux/if_ether.h>
#include <netinet/in.h>
// [socket manual](https://linux.die.net/man/7/socket)
// [packet manual](https://linux.die.net/man/7/packet)
int open_socket() { return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); }
#elif defined(__APPLE__)
#include <fcntl.h>
#include <sys/socket.h>
int open_socket() { return open("/dev/bpf0", O_RDWR); }
#else
#error "unsupported platform: only availabe on linux and macos"
#endif
