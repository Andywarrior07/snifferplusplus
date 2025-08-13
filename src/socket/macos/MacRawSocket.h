//
// Created by Andres Guerrero on 08-08-25.
//

#pragma once
#include "../IRawSocket.h"

class MacRawSocket : public IRawSocket {
   public:
    MacRawSocket();
    ~MacRawSocket() override;
    bool initialize(const string& nic_name) override;
    ssize_t read_packet(uint8_t* buffer) override;
    void close_socket() override;

   private:
    int raw_socket;
    u_int buffer_size;
    static constexpr u_int BUFFER_SIZE = 4096;

    int open_bpf_buffer();
    bool setup_bpf(const string& nic_name);
};
