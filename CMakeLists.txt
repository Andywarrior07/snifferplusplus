cmake_minimum_required(VERSION 3.31)
project(snifferplusplus)

set(CMAKE_CXX_STANDARD 20)

add_executable(snifferplusplus src/main.cpp
        src/Packet.cpp
        src/Packet.hpp)
