#include <array>
#include <vector>
#include <iostream>
#include <string>

#include <sycl/sycl.hpp>

#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include "dpc_common.hpp"

const size_t burst_size = 32;
#define PACKET_SIZE 64

int main() {
    sycl::queue q;

    std::cout << "Using device: " <<
        q.get_device().get_info<sycl::info::device::name>() << std::endl;

    int nth = 10;  // number of threads
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    // Input node: get packets from the socket or from the packet capture
    tbb::flow::input_node<int> in_node{g,
        [&](tbb::flow_control& fc) -> int {
            int nr_packets = 0;
	    char* packet;

            std::cout << "Input node running " << std::endl;

            // Attempt to read the packets from the packet capture or read
	    // them from a network socket
            packet = NULL;
            if (packet == NULL) {
		    std::cout << "No more packets" << std::endl;
                fc.stop();
                return 0;
            }

            // Return the number of packets read
            return nr_packets;
        }
    };

    // Packet inspection node
    tbb::flow::function_node<int, int> inspect_packet_node {
        g, tbb::flow::unlimited, [&](int nr_packets) {
            // By including all the SYCL work in a {} block, we ensure
            // all SYCL tasks must complete before exiting the block
            {
                sycl::queue gpuQ(sycl::gpu_selector_v, dpc_common::exception_handler);

                std::cout << "Selected GPU Device Name: " <<
                    gpuQ.get_device().get_info<sycl::info::device::name>() << "\n";

                gpuQ.submit([&](sycl::handler& h) {
                            auto compute = [=](auto i) {
                            // Process the packets
                            };

                            h.parallel_for(nr_packets, compute);
                        }
                    ).wait_and_throw();  // end of the commands for the SYCL queue

            }  // End of the scope for SYCL code; the queue has completed the work
 
            // Return the number of packets processed
            return nr_packets;
        }};

    // construct graph
    tbb::flow::make_edge<int>(in_node, inspect_packet_node);

    in_node.activate();
    g.wait_for_all();

    std::cout << "Done waiting" << std::endl;
}
