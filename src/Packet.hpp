//
// Created by Andres Guerrero on 02-08-25.
//

#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/**
 * @brief Comprehensive packet information structure containing all parsed network data
 *
 * This structure holds all the essential information extracted from a network packet,
 * including ethernet, IP, and transport layer details. It serves as the primary data
 * container for packet analysis and inspection.
 *
 * @note All string fields use UTF-8 encoding
 * @note Ports are stored in host byte order (converted from network byte order)
 * @note MAC addresses are formatted as colon-separated hexadecimal strings
 *
 * @since Version 1.0
 * @author Andres Guerrero
 */
struct PacketInfo {
    /// High-resolution timestamp captured when packet parsing begins
    std::chrono::steady_clock::time_point timestamp;

    /// Source IP address in dotted decimal notation (e.g., "192.168.1.1")
    std::string src_ip;

    /// Destination IP address in dotted decimal notation (e.g., "192.168.1.100")
    std::string dst_ip;

    /// Source MAC address in colon-separated hexadecimal format (e.g., "aa:bb:cc:dd:ee:ff")
    std::string src_mac;

    /// Destination MAC address in colon-separated hexadecimal format (e.g., "11:22:33:44:55:66")
    std::string dst_mac;

    /// Human-readable ethernet type name (currently unused but reserved for future enhancement)
    std::string ether_type_name;

    /// Ethernet type value from the ethernet header (e.g., 0x0800 for IPv4)
    uint16_t ether_type;

    /// Source port number in host byte order (0 for protocols without port concept)
    uint16_t src_port;

    /// Destination port number in host byte order (0 for protocols without port concept)
    uint16_t dst_port;

    /// IP version number (currently only IPv4 = 4 is supported)
    uint8_t ip_version;

    /// Protocol name as string ("TCP", "UDP", "ICMP", or "OTHER(N)" where N is protocol number)
    std::string protocol;

    /// Size of the application-layer payload in bytes (excludes all headers)
    size_t payload_size = 0;

    /// Preview of the application payload data (limited to first 64 bytes by default)
    std::vector<uint8_t> payload_preview;
};

/**
 * @brief High-performance network packet parser and analyzer
 *
 * The Packet class provides comprehensive network packet parsing capabilities with
 * support for multiple platforms (Linux and macOS). It can handle ethernet frames
 * containing IPv4 packets with TCP, UDP, and ICMP protocols.
 *
 * ## Features:
 * - Cross-platform support (Linux raw sockets, macOS BPF)
 * - Zero-copy parsing where possible for optimal performance
 * - Comprehensive protocol support (Ethernet, IPv4, TCP, UDP, ICMP)
 * - Thread-safe parsing operations
 * - Robust error handling with graceful degradation
 * - Configurable payload preview length
 *
 * ## Thread Safety:
 * - Individual Packet instances are NOT thread-safe
 * - Multiple Packet instances can be used concurrently from different threads
 * - The static mac_to_string() method is thread-safe
 *
 * ## Performance Considerations:
 * - Designed for high-throughput packet processing
 * - Minimal memory allocations during parsing
 * - Efficient string formatting using std::format (C++20)
 * - Optional payload preview limits memory usage
 *
 * ## Usage Example:
 * @code{.cpp}
 * Packet parser;
 * uint8_t raw_data[1500];  // Example packet buffer
 * size_t packet_size = capture_packet(raw_data);  // Your capture mechanism
 *
 * // Process single packet
 * parser.process_packet(raw_data, packet_size);
 *
 * #ifdef __APPLE__
 * // Process BPF buffer containing multiple packets (macOS only)
 * uint8_t bpf_buffer[4096];
 * size_t buffer_size = read_bpf_device(bpf_buffer);
 * parser.process_bpf_buffer(bpf_buffer, buffer_size);
 * #endif
 * @endcode
 *
 * ## Supported Packet Structure:
 * ```
 * [Ethernet Header][IP Header][TCP/UDP/ICMP Header][Application Data]
 * ```
 *
 * @warning This class requires raw socket privileges on Linux and BPF access on macOS
 * @warning Only IPv4 packets are currently supported; IPv6 packets are silently ignored
 * @warning Fragmented IP packets are not reassembled
 *
 * @since Version 1.0
 * @author Andres Guerrero
 */
class Packet {
public:
    /**
     * @brief Default constructor
     *
     * Initializes the packet parser with default settings:
     * - Payload preview limited to 64 bytes
     * - All internal structures initialized to safe defaults
     *
     * @note Constructor is lightweight and does not allocate significant memory
     */
    Packet();

    /**
     * @brief Default destructor
     *
     * Automatically cleans up all internal resources.
     * No explicit cleanup required by the user.
     */
    ~Packet() = default;

#ifdef __APPLE__
    /**
     * @brief Process a BPF (Berkeley Packet Filter) buffer containing multiple packets
     *
     * This method is specific to macOS and processes a buffer received from a BPF device.
     * The buffer may contain multiple packets, each preceded by a BPF header that
     * indicates the packet length and offset to the next packet.
     *
     * @param buffer Pointer to the BPF buffer containing one or more packets
     * @param size Total size of the BPF buffer in bytes
     *
     * @pre buffer must not be nullptr
     * @pre size must be greater than 0
     * @pre buffer must point to a valid BPF-formatted buffer
     *
     * @post Each valid packet in the buffer will be processed and printed to stdout
     * @post Invalid or truncated packets are silently skipped
     *
     * @note This method only compiles on macOS (when __APPLE__ is defined)
     * @note BPF headers are automatically parsed and validated
     * @note Corrupted BPF headers will cause processing to stop safely
     *
     * ## Performance:
     * - Processes packets sequentially without copying
     * - Handles variable-length BPF headers correctly
     * - Optimized for high packet rates
     *
     * @see process_packet() for single packet processing
     * @see https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4 for BPF format details
     */
    void process_bpf_buffer(const uint8_t* buffer, size_t size);
#endif

    /**
     * @brief Process and analyze a single network packet
     *
     * This is the main entry point for packet analysis. It parses a complete
     * ethernet frame, extracts all relevant information, and prints a detailed
     * analysis to stdout.
     *
     * @param buffer Pointer to the raw packet data (must start with ethernet header)
     * @param size Size of the packet data in bytes
     *
     * @pre buffer must not be nullptr
     * @pre size must be at least sizeof(ether_header) bytes
     * @pre buffer must contain a complete, valid ethernet frame
     *
     * @post If parsing succeeds, packet information is printed to stdout
     * @post If parsing fails, the method returns silently without output
     * @post Internal PacketInfo structure is updated with parsed data
     *
     * ## Output Format:
     * The method prints a formatted block containing:
     * - Source and destination IP addresses
     * - Source and destination MAC addresses
     * - Ethernet type and protocol information
     * - Port numbers (for TCP/UDP)
     * - Payload size and timestamp
     *
     * ## Supported Protocols:
     * - **Ethernet**: All standard ethernet frame types
     * - **IPv4**: Complete IPv4 header parsing
     * - **TCP**: Port extraction and payload identification
     * - **UDP**: Port extraction and payload identification
     * - **ICMP**: Basic ICMP packet recognition
     *
     * ## Error Handling:
     * - Malformed packets are silently ignored
     * - Unsupported protocols are logged as "OTHER(N)"
     * - Buffer underruns are detected and handled safely
     * - Non-IPv4 packets are filtered out
     *
     * @note This method is thread-safe when called on different Packet instances
     * @note Output goes directly to stdout; consider redirecting for production use
     * @note Timestamp is captured at the beginning of parsing for accuracy
     *
     * @see parse_packet() for the underlying parsing logic
     * @see PacketInfo for details on extracted information
     */
    void process_packet(const uint8_t* buffer, size_t size);

private:
    /// Internal packet information storage (reused for each parsed packet)
    PacketInfo info;

    /// Maximum number of payload bytes to store in preview (default: 64)
    size_t max_payload_preview = 64;

    /**
     * @brief Core packet parsing engine
     *
     * Performs the actual packet parsing work, extracting information from
     * ethernet, IP, and transport layer headers. This is where the heavy
     * lifting of protocol analysis occurs.
     *
     * @param buffer Pointer to raw packet data
     * @param size Size of packet data in bytes
     * @return std::optional<PacketInfo> Parsed packet info, or std::nullopt if parsing failed
     *
     * @note This method modifies the internal 'info' member variable
     * @note Timestamp is set at the beginning of parsing
     * @note Only IPv4 packets are processed; others return std::nullopt
     */
    std::optional<PacketInfo> parse_packet(const uint8_t* buffer, size_t size);

    /**
     * @brief Safely copy payload data for preview purposes
     *
     * Copies up to max_payload_preview bytes from the packet payload into
     * the preview vector. This allows inspection of application data without
     * storing the entire payload.
     *
     * @param data Pointer to payload data
     * @param size Size of available payload data
     * @param preview Reference to vector that will receive the copied data
     *
     * @post preview vector contains min(size, max_payload_preview) bytes
     * @post preview vector is resized to match copied data length
     *
     * @note Method is const and does not modify object state
     * @note Uses std::vector::assign for efficient copying
     */
    void copy_payload_preview(const uint8_t* data, size_t size, std::vector<uint8_t>& preview) const;

    /**
     * @brief Convert binary MAC address to human-readable string format
     *
     * Transforms a 6-byte MAC address into the standard colon-separated
     * hexadecimal notation (e.g., "aa:bb:cc:dd:ee:ff").
     *
     * @param mac Pointer to 6-byte MAC address array
     * @return std::string MAC address in colon-separated hex format
     *
     * @pre mac must point to exactly 6 bytes of valid data
     * @post Returns string in format "xx:xx:xx:xx:xx:xx" where x is lowercase hex
     *
     * @note This is a static method and can be called without an instance
     * @note Thread-safe implementation
     * @note Uses std::format for efficient string construction (C++20)
     * @note All hex digits are lowercase for consistency
     *
     * ## Performance:
     * - Single allocation for result string
     * - No intermediate string concatenations
     * - Optimized format string for minimal overhead
     */
    static std::string mac_to_string(const uint8_t* mac);
};