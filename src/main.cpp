#include "socket.cpp"
#include <cstdio>

int main() {
  // Step 1: open a socket
  int socket_file_descriptor = open_socket();

  printf("socket file descriptor: %d", socket_file_descriptor);

  // Step 2: inspect NICs

  // Step 3: bind to NIC

  // Step 4: recieve packages
  return 0;
}
