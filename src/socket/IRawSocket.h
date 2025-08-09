//
// Created by Andres Guerrero on 08-08-25.
//

#pragma once
#include <functional>
#include <string>

using namespace std;

class IRawSocket {
public:
    virtual ~IRawSocket() = default;

    virtual bool initialize(const string& nic_name) = 0;

    virtual ssize_t read_packet(uint8_t* buffer) = 0;

    virtual void close() = 0;
};