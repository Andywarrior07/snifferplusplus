cmake_minimum_required(VERSION 3.31)
project(snifferplusplus)

set(CMAKE_CXX_STANDARD 20)

add_executable(snifferplusplus src/main.cpp
        src/Packet.cpp
        src/Packet.hpp
        src/socket/IRawSocket.h
        src/socket/RawSocket.h
        src/socket/RawSocketFactory.h
        src/socket/macos/MacRawSocket.cpp
        src/socket/macos/MacRawSocket.h)
