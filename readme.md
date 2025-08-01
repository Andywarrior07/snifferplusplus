# **snifferpusplus**
---


# **Project Goals**
---

- 1. Learn about low-level network-packet transfer on Unix (Linux and MacOS).
- 2. Learn more about the C and C++ languages and their toolchains.
- 3. Understand how packet analyzers work, such as`Wireshark` or `tcpdump`.
- 4. Add journal/wiki to write our notes.


# **Project Checklist**
---

- 1. [ ] Create a file descriptor to read from.
  - [X] On Linux, we use the socket() system call to request a raw socket from the kernel.
  - [X] On macOS, we open a `BPF` device node like `/dev/bpf0` to access raw packets
  - [ ] Handle errors for each platform.
- 2. [ ] Inspect available network interfaces.
- 3. [ ] Select and bind/connect to an interface.
- 4. [ ] Read raw packets.
- 5. [ ] Parse and decode the headers and payload.
