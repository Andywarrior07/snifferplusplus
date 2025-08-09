//
// Created by Andres Guerrero on 08-08-25.
//

#pragma once
#include "IRawSocket.h"
#include "macos/MacRawSocket.h"

using namespace std;

class RawSocketFactory {
public:
    static unique_ptr<IRawSocket> create() {
#ifdef __linux__
        return make_unique<LinuxRawSocket>();
#elif __APPLE__
        return make_unique<MacRawSocket>();
#else
        return nullptr;
#endif
    }
};