#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <sycl/sycl.hpp>
#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include <cstring>
#include <unordered_map>
#include "dpc_common.hpp"
#include <pcap.h>

// Constants
const size_t BURST_SIZE = 32;
const size_t MAX_PACKET_SIZE = 1518;  // Maximum Ethernet packet size
const size_t IP_OFFSET = 14;        // Offset to IP header in Ethernet frame


// Network statistics
struct NetworkStats {
    std::atomic<uint64_t> ipv4_packets{0};
    std::atomic<uint64_t> ipv6_packets{0};
    std::atomic<uint64_t> arp_packets{0};
    std::atomic<uint64_t> icmp_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> routed_packets{0};
};
// Define your Packet structure
struct Packet {
    std::vector<uint8_t> data;
    size_t size;
    bool is_ipv4;
    bool is_ipv6;
    bool is_arp;
    bool is_icmp;
    bool is_tcp;
    bool is_udp;

    Packet() : data(MAX_PACKET_SIZE), size(0), is_ipv4(false), is_ipv6(false),
               is_arp(false), is_icmp(false), is_tcp(false), is_udp(false) {}
};

// PCAP reader class to read packet captures using libpcap
class PCAPReader {
public:
    PCAPReader(const std::string& filename) : filename_(filename), handle_(nullptr) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle_ = pcap_open_offline(filename.c_str(), errbuf);

        if (!handle_) {
            std::cerr << "Failed to open PCAP file: " << errbuf << std::endl;
        } else {
            std::cout << "PCAP file opened successfully: " << filename << std::endl;
        }
    }

    ~PCAPReader() {
        if (handle_) {
            pcap_close(handle_);
        }
    }

    // Read a burst of packets
    int readPacketBurst(std::vector<Packet>& packets, size_t max_packets) {
        if (!handle_) return 0;

        packets.clear();
        struct pcap_pkthdr* header;
        const u_char* data;
        int res;
        int count = 0;

        while (count < static_cast<int>(max_packets) && (res = pcap_next_ex(handle_, &header, &data)) >= 0) {
            if (res == 0) continue; // Timeout or no packet

            Packet packet;
            packet.size = std::min(static_cast<size_t>(header->caplen), MAX_PACKET_SIZE);
            std::memcpy(packet.data.data(), data, packet.size);

            // Set packet type flags (you can implement actual parsing here if needed)
            packet.is_ipv4 = false;
            packet.is_ipv6 = false;
            packet.is_arp = false;
            packet.is_icmp = false;
            packet.is_tcp = false;
            packet.is_udp = false;

            packets.push_back(packet);
            count++;
        }

        if (res == -1) {
            std::cerr << "Error reading packet: " << pcap_geterr(handle_) << std::endl;
        }

        return count;
    }

    bool isOpen() const {
        return handle_ != nullptr;
    }

private:
    std::string filename_;
    pcap_t* handle_;
};

// Routing table entry
struct RoutingEntry {
    uint32_t destination_ip;
    uint32_t subnet_mask;
    uint32_t next_hop;
    int output_interface;
};

// Simple routing table
class RoutingTable {
public:
    RoutingTable() {
        // Add some default routes
        addRoute("192.168.1.0", "255.255.255.0", "192.168.1.1", 0);
        addRoute("10.0.0.0", "255.0.0.0", "10.0.0.1", 1);
    }
    
    void addRoute(const std::string& dest, const std::string& mask, const std::string& next, int iface) {
        RoutingEntry entry;
        entry.destination_ip = ipToUint32(dest);
        entry.subnet_mask = ipToUint32(mask);
        entry.next_hop = ipToUint32(next);
        entry.output_interface = iface;
        routes_.push_back(entry);
    }
    
    int lookupRoute(uint32_t dest_ip) {
        for (const auto& route : routes_) {
            if ((dest_ip & route.subnet_mask) == (route.destination_ip & route.subnet_mask)) {
                return route.output_interface;
            }
        }
        return -1; // No route found
    }
    
private:
    std::vector<RoutingEntry> routes_;
    
    uint32_t ipToUint32(const std::string& ip) {
        uint32_t result = 0;
        int value, a, b, c, d;
        if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            result = (a << 24) | (b << 16) | (c << 8) | d;
        }
        return result;
    }
};

int main(int argc, char* argv[]) {
    // Check command line arguments
    std::string pcap_file = "../../src/capture2.pcap";
    if (argc > 1) {
        pcap_file = argv[1];
    }
    
    // Initialize network statistics
    NetworkStats stats;
    
    // Initialize routing table
    RoutingTable routing_table;
    
    try {
        sycl::queue q;
        std::cout << "Using device: " << q.get_device().get_info<sycl::info::device::name>() << std::endl;
        
        // Set number of threads
        int nth = 10; // number of threads
        auto mp = tbb::global_control::max_allowed_parallelism;
        tbb::global_control gc(mp, nth);
        
        // Create TBB flow graph
        tbb::flow::graph g;
        
        // Initialize PCAP reader
        PCAPReader pcap_reader(pcap_file);
        if (!pcap_reader.isOpen()) {
            std::cerr << "Failed to open PCAP file. Exiting." << std::endl;
            return 1;
        }
        std::cout << "OPENED FILE" << std::endl;
        // Input node: read packets from PCAP file
        tbb::flow::input_node<std::vector<Packet>> in_node{g,
            [&](tbb::flow_control& fc) -> std::vector<Packet> {
                std::vector<Packet> packets;
                int nr_packets = pcap_reader.readPacketBurst(packets, BURST_SIZE);
                
                if (nr_packets == 0) {
                    std::cout << "No more packets" << std::endl;
                    fc.stop();
                    return packets;
                }
                
                stats.total_packets += nr_packets;
                std::cout << "Read " << nr_packets << " packets" << std::endl;
                return packets;
            }
        };
        
        // Packet inspection node
        tbb::flow::function_node<std::vector<Packet>, std::vector<Packet>> inspect_packet_node{
            g, tbb::flow::unlimited, [&](std::vector<Packet> packets) {
                if (packets.empty()) return packets;
                
                // Create GPU buffers
                sycl::queue gpu_queue(sycl::default_selector_v, dpc_common::exception_handler);
                std::cout << "Selected GPU Device: " << 
                    gpu_queue.get_device().get_info<sycl::info::device::name>() << "\n";
                
                size_t packet_count = packets.size();
                
                // Create a SYCL buffer for all packets
                std::vector<uint8_t> packet_data_flat;
                std::vector<size_t> packet_sizes(packet_count);
                
                // Flatten packet data for GPU processing
                for (size_t i = 0; i < packet_count; i++) {
                    packet_sizes[i] = packets[i].size;
                    for (size_t j = 0; j < packets[i].size; j++) {
                        packet_data_flat.push_back(packets[i].data[j]);
                    }
                }
                
                // Calculate offsets for each packet in the flat array
                std::vector<size_t> packet_offsets(packet_count);
                size_t offset = 0;
                for (size_t i = 0; i < packet_count; i++) {
                    packet_offsets[i] = offset;
                    offset += packet_sizes[i];
                }
                
                // Create SYCL buffers
                sycl::buffer<uint8_t> buf_packet_data(packet_data_flat.data(), packet_data_flat.size());
                sycl::buffer<size_t> buf_packet_sizes(packet_sizes.data(), packet_sizes.size());
                sycl::buffer<size_t> buf_packet_offsets(packet_offsets.data(), packet_offsets.size());
                
                // Buffers for packet type flags
                std::vector<uint8_t> is_ipv4(packet_count, 0);
                std::vector<uint8_t> is_ipv6(packet_count, 0);
                std::vector<uint8_t> is_arp(packet_count, 0);
                std::vector<uint8_t> is_icmp(packet_count, 0);
                std::vector<uint8_t> is_tcp(packet_count, 0);
                std::vector<uint8_t> is_udp(packet_count, 0);
                
                sycl::buffer<uint8_t> buf_is_ipv4(is_ipv4.data(), is_ipv4.size());
                sycl::buffer<uint8_t> buf_is_ipv6(is_ipv6.data(), is_ipv6.size());
                sycl::buffer<uint8_t> buf_is_arp(is_arp.data(), is_arp.size());
                sycl::buffer<uint8_t> buf_is_icmp(is_icmp.data(), is_icmp.size());
                sycl::buffer<uint8_t> buf_is_tcp(is_tcp.data(), is_tcp.size());
                sycl::buffer<uint8_t> buf_is_udp(is_udp.data(), is_udp.size());
                
                // Submit GPU kernel for packet inspection
                gpu_queue.submit([&](sycl::handler& h) {
                    auto acc_packet_data = buf_packet_data.get_access<sycl::access::mode::read_write>(h);
                    auto acc_packet_sizes = buf_packet_sizes.get_access<sycl::access::mode::read_write>(h);
                    auto acc_packet_offsets = buf_packet_offsets.get_access<sycl::access::mode::read>(h);
                    auto acc_is_ipv4 = buf_is_ipv4.get_access<sycl::access::mode::write>(h);
                    auto acc_is_ipv6 = buf_is_ipv6.get_access<sycl::access::mode::write>(h);
                    auto acc_is_arp = buf_is_arp.get_access<sycl::access::mode::write>(h);
                    auto acc_is_icmp = buf_is_icmp.get_access<sycl::access::mode::write>(h);
                    auto acc_is_tcp = buf_is_tcp.get_access<sycl::access::mode::write>(h);
                    auto acc_is_udp = buf_is_udp.get_access<sycl::access::mode::write>(h);
                    
                    h.parallel_for(packet_count, [=](auto idx) {
                        size_t offset = acc_packet_offsets[idx];
                        size_t size = acc_packet_sizes[idx];
                        
                        // Need at least 14 bytes for Ethernet header
                        if (size >= 14) {
                            // Check Ethernet type (bytes 12-13)
                            // uint16_t eth_type = (acc_packet_data[offset + 12] << 8) | acc_packet_data[offset + 13];
                            uint8_t hi = acc_packet_data[offset + 12];
                            uint8_t lo = acc_packet_data[offset + 13];

                            uint16_t eth_type = ((uint16_t)hi << 8) | lo;

                            if (eth_type == 0x0800) {  // IPv4
                                acc_is_ipv4[idx] = 1;
                                
                                // Check protocol field if we have enough data
                                if (size >= IP_OFFSET + 10) {
                                    uint8_t protocol = acc_packet_data[offset + IP_OFFSET + 9];
                                    
                                    if (protocol == 1) {  // ICMP
                                        acc_is_icmp[idx] = 1;
                                    } else if (protocol == 6) {  // TCP
                                        acc_is_tcp[idx] = 1;
                                    } else if (protocol == 17) {  // UDP
                                        acc_is_udp[idx] = 1;
                                    }
                                }
                            } else if (eth_type == 0x86DD) {  // IPv6
                                acc_is_ipv6[idx] = 1;

                                // Check next_header field if we have
                                if (size >= IP_OFFSET + 40) {
                                    uint8_t next_header = acc_packet_data[offset + IP_OFFSET + 6];

                                    if (next_header == 58) {  // ICMPv6
                                        acc_is_icmp[idx] = 1;
                                    } else if (next_header == 6) {  // TCP
                                        acc_is_tcp[idx] = 1;
                                    } else if (next_header == 17) {  // UDP
                                        acc_is_udp[idx] = 1;
                                    }
                                }
                            } else if (eth_type == 0x0806) {  // ARP
                                acc_is_arp[idx] = 1;
                            }
                        }
                    });
                }).wait_and_throw();
                
                // Read back the results
                // Read back the results
                auto host_ipv4 = buf_is_ipv4.get_host_access();
                auto host_ipv6 = buf_is_ipv6.get_host_access();
                auto host_arp = buf_is_arp.get_host_access();
                auto host_icmp = buf_is_icmp.get_host_access();
                auto host_tcp = buf_is_tcp.get_host_access();
                auto host_udp = buf_is_udp.get_host_access();
                
                // Update packet metadata and statistics
                for (size_t i = 0; i < packet_count; i++) {
                    packets[i].is_ipv4 = is_ipv4[i];
                    packets[i].is_ipv6 = is_ipv6[i];
                    packets[i].is_arp = is_arp[i];
                    packets[i].is_icmp = is_icmp[i];
                    packets[i].is_tcp = is_tcp[i];
                    packets[i].is_udp = is_udp[i];
                    
                    // Update statistics
                    if (is_ipv4[i]) stats.ipv4_packets++;
                    if (is_ipv6[i]) stats.ipv6_packets++;
                    if (is_arp[i]) stats.arp_packets++;
                    if (is_icmp[i]) stats.icmp_packets++;
                    if (is_tcp[i]) stats.tcp_packets++;
                    if (is_udp[i]) stats.udp_packets++;
                }
                
                std::cout << "Packet inspection completed on GPU" << std::endl;
                return packets;
            }
        };
        
        // Routing node - only process IPv4 packets
        tbb::flow::function_node<std::vector<Packet>, std::vector<Packet>> routing_node{
            g, tbb::flow::unlimited, [&](std::vector<Packet> packets) {
                if (packets.empty()) return packets;
                
                // Get only IPv4 packets
                std::vector<Packet> ipv4_packets;
                for (const auto& packet : packets) {
                    if (packet.is_ipv4) {
                        ipv4_packets.push_back(packet);
                    }
                }
                
                if (ipv4_packets.empty()) return packets;
                
                // Process IPv4 packets on GPU
                sycl::queue gpu_queue(sycl::default_selector_v);
                size_t packet_count = ipv4_packets.size();
                
                // Flatten packet data for GPU processing
                std::vector<uint8_t> packet_data_flat;
                std::vector<size_t> packet_sizes(packet_count);
                std::vector<size_t> packet_offsets(packet_count);
                
                size_t offset = 0;
                for (size_t i = 0; i < packet_count; i++) {
                    packet_sizes[i] = ipv4_packets[i].size;
                    packet_offsets[i] = offset;
                    
                    for (size_t j = 0; j < ipv4_packets[i].size; j++) {
                        packet_data_flat.push_back(ipv4_packets[i].data[j]);
                    }
                    
                    offset += packet_sizes[i];
                }
                
                // Create SYCL buffers
                sycl::buffer<uint8_t> buf_packet_data(packet_data_flat.data(), packet_data_flat.size());
                sycl::buffer<size_t> buf_packet_sizes(packet_sizes.data(), packet_sizes.size());
                sycl::buffer<size_t> buf_packet_offsets(packet_offsets.data(), packet_offsets.size());
                
                // Submit GPU kernel for packet routing
                gpu_queue.submit([&](sycl::handler& h) {
                    auto acc_packet_data = buf_packet_data.get_access<sycl::access::mode::read_write>(h);
                    auto acc_packet_sizes = buf_packet_sizes.get_access<sycl::access::mode::read>(h);
                    auto acc_packet_offsets = buf_packet_offsets.get_access<sycl::access::mode::read>(h);
                    
                    h.parallel_for(packet_count, [=](auto idx) {
                        size_t offset = acc_packet_offsets[idx];
                        size_t size = acc_packet_sizes[idx];
                        
                        if (size >= IP_OFFSET + 20) {  // Make sure we have enough data for IPv4 header
                            // Modify the destination IP address (add 1 to each byte)
                            // IPv4 destination address is at offset 30 in the Ethernet frame
                            acc_packet_data[offset + IP_OFFSET + 16]++;
                            acc_packet_data[offset + IP_OFFSET + 17]++;
                            acc_packet_data[offset + IP_OFFSET + 18]++;
                            acc_packet_data[offset + IP_OFFSET + 19]++;
                            
                            // NOTE: In a real implementation, we would also need to recalculate the IPv4 checksum
                        }
                    });
                }).wait_and_throw();
                
                // Copy back the modified data to the original packets
                auto host_data = buf_packet_data.get_host_access();
                
                for (size_t i = 0; i < packet_count; i++) {
                    size_t offset = packet_offsets[i];
                    size_t size = packet_sizes[i];
                    
                    for (size_t j = 0; j < size; j++) {
                        ipv4_packets[i].data[j] = host_data[offset + j];
                    }
                    
                    // Increment routed packets counter
                    stats.routed_packets++;
                }
                
                std::cout << "IPv4 routing completed on GPU for " << packet_count << " packets" << std::endl;
                
                // Merge back the IPv4 packets with the original packet list
                std::vector<Packet> result;
                size_t ipv4_idx = 0;
                
                for (const auto& packet : packets) {
                    if (packet.is_ipv4 && ipv4_idx < ipv4_packets.size()) {
                        result.push_back(ipv4_packets[ipv4_idx++]);
                    } else {
                        result.push_back(packet);
                    }
                }
                
                return result;
            }
        };
        
        // Send node - would normally send packets to network interfaces
        tbb::flow::function_node<std::vector<Packet>, tbb::flow::continue_msg> send_node{
            g, tbb::flow::unlimited, [&](std::vector<Packet> packets) {
                if (packets.empty()) return tbb::flow::continue_msg();
                
                std::cout << "Send node received " << packets.size() << " packets" << std::endl;
                
                // In a real implementation, we would lookup the routing table and send packets
                // to the correct interface. For now, just simulate this.
                for (const auto& packet : packets) {
                    if (packet.is_ipv4 && packet.size >= IP_OFFSET + 20) {
                        // Extract destination IP
                        uint32_t dest_ip = (packet.data[IP_OFFSET + 16] << 24) | 
                                          (packet.data[IP_OFFSET + 17] << 16) | 
                                          (packet.data[IP_OFFSET + 18] << 8) | 
                                           packet.data[IP_OFFSET + 19];
                        
                        // Lookup routing table
                        int iface = routing_table.lookupRoute(dest_ip);
                        
                        if (iface >= 0) {
                            // In a real implementation, we would send the packet to the correct interface
                            std::cout << "Packet routed to interface " << iface << std::endl;
                        } else {
                            std::cout << "No route found for packet" << std::endl;
                        }
                    }
                }
                
                return tbb::flow::continue_msg();
            }
        };
        
        // Connect the nodes
        tbb::flow::make_edge(in_node, inspect_packet_node);
        tbb::flow::make_edge(inspect_packet_node, routing_node);
        tbb::flow::make_edge(routing_node, send_node);
        
        // Activate the input node
        in_node.activate();
        
        // Wait for completion
        g.wait_for_all();
        
        // Print statistics
        std::cout << "\nNetwork Statistics:" << std::endl;
        std::cout << "Total packets: " << stats.total_packets << std::endl;
        std::cout << "IPv4 packets: " << stats.ipv4_packets << std::endl;
        std::cout << "IPv6 packets: " << stats.ipv6_packets << std::endl;
        std::cout << "ARP packets: " << stats.arp_packets << std::endl;
        std::cout << "ICMP packets: " << stats.icmp_packets << std::endl;
        std::cout << "TCP packets: " << stats.tcp_packets << std::endl;
        std::cout << "UDP packets: " << stats.udp_packets << std::endl;
        std::cout << "Routed packets: " << stats.routed_packets << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "Application completed successfully" << std::endl;
    return 0;
}
