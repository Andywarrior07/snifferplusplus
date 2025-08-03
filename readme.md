# **Snifferpusplus**

***A network packet analyzer for Linux and MacOS built in C++.***


## **Project Goals**

- Learn about low-level network-packet transfer on Unix (Linux and MacOS).
- Learn more about the C and C++ languages and their toolchains.
- Understand how packet analyzers work, such as`Wireshark` or `tcpdump`.
- Add journal/wiki to write our notes.


## **Project Checklist**

1. [x] Create a file descriptor to read from.
    - [x] **Linux**: use the `socket()` system call to request a raw socket from the kernel.
    - [x] **macOS:** open a `BPF` device node like `/dev/bpf0` to access raw packets
    - [x] Handle errors for each platform.
2. [x] Inspect available network interfaces.
3. [x] Select and bind/connect to an interface.
4. [ ] Read raw packets.
    - [ ] **To-do**: read ether-type/packet length.
5. [ ] Parse and decode the headers and payload.
