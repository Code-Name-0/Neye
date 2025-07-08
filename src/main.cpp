#include <neye_lib.hpp>

int main()
{
    load_env_file(".env");

    State global_state;
    const std::string devices_json_filename = "./resources/groupdevicemap.json";

    try
    {
        // Discover network interfaces
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *interface_list;
        if (pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
        {
            throw std::runtime_error("Failed to find network interfaces: " + std::string(errbuf));
        }

        LOG_INFO("Main", "Available network interfaces:");
        int index = 1;
        for (pcap_if_t *iface = interface_list; iface != nullptr; iface = iface->next, ++index)
        {
            std::string iface_info = std::to_string(index) + ". " +
                                     (iface->name ? iface->name : "Unnamed interface");
            if (iface->description)
                iface_info += " (" + std::string(iface->description) + ")";
            LOG_INFO("Main", iface_info);
        }

        // Select interface
        std::cout << std::endl
                  <<    "Select a network interface by index (1 to " << index - 1 << "): ";
        int interface_index = -1;
        std::cin >> interface_index;

        std::cout.flush();
        pcap_if_t *selected_iface = interface_list;
        for (int i = 1; i < interface_index && selected_iface != nullptr; i++)
            selected_iface = selected_iface->next;

        if (!selected_iface || !selected_iface->name)
        {
            throw std::runtime_error("Invalid interface selection.");
        }

        std::string net_interface_str = selected_iface->name;
        LOG_INFO("Main", "Using interface: " + net_interface_str);
        pcap_freealldevs(interface_list);

        // Group devices into K groups, and configure filters
        int K = 0;
        std::vector<std::string> group_filters = group_devices(devices_json_filename, K, net_interface_str, global_state);

        // Clear queues
        for (int i = 0; i < K; i++)
            flows_queues[i].clear();

        // Launch threads
        std::vector<std::thread> capture_threads;
        std::vector<std::thread> feature_threads;
        std::vector<std::thread> aggregation_threads;
        std::vector<std::thread> rate_threads;

        for (int i = 0; i < K; i++)
        {
            capture_threads.emplace_back(capture_thread, i, net_interface_str, group_filters[i], std::ref(global_state));
            feature_threads.emplace_back(feature_extraction_thread, i, std::ref(global_state));
            aggregation_threads.emplace_back(flow_aggregation_thread, i, std::ref(global_state));
            rate_threads.emplace_back(rate_calculation_thread, i, std::ref(global_state));
        }

        std::thread logger(logger_thread, std::ref(global_state));
        std::thread infer(inference_thread, K, std::ref(global_state));
        std::thread interactive(interactive_command_thread, std::ref(global_state));
        std::thread history_saver(history_saving_thread, std::ref(global_state));

        // Join all threads
        for (auto &t : capture_threads)
            t.join();
        for (auto &t : feature_threads)
            t.join();
        for (auto &t : aggregation_threads)
            t.join();
        for (auto &t : rate_threads)
            t.join();
        infer.join();
        logger.join();
        interactive.join();
        history_saver.join();
    }
    catch (const std::exception &e)
    {
        LOG_FATAL("Main", "Application error: " + std::string(e.what()));
        return 1;
    }

    LOG_INFO("Main", "Application shutting down successfully");
    return 0;
}