//
// Created by Andres Guerrero on 08-08-25.
//

#pragma once
#include <memory>

#include "IRawSocket.h"
#include "RawSocketFactory.h"

using namespace std;

class RawSocket {
public:
    RawSocket(): raw_socket(RawSocketFactory::create()) {}

    [[nodiscard]] bool initialize(const string& nic_name) const {
        return raw_socket->initialize(nic_name);
    }

    [[nodiscard]] ssize_t read_packet(uint8_t* buffer) const {
        return raw_socket->read_packet(buffer);
    }
private:
    unique_ptr<IRawSocket> raw_socket;
};