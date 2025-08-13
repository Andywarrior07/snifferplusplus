#pragma once
#include "../IRawSocket.h"

class LinuxRawSocket : public IRawSocket {
   public:
    LinuxRawSocket();
    ~LinuxRawSocket() override;
    bool initialize(const string& nic_name) override;
    ssize_t read_packet(uint8_t* buffer) override;
    void close_socket() override;

   private:
    int raw_socket;
    u_int buffer_size;
    static constexpr u_int BUFFER_SIZE = 4096;

    bool bind_socket(const std::string& nic_name);
};
