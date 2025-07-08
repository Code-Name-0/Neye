#include "neye_lib.hpp"

#define epsilon 1e-10
#define ethernet_begin 0
#define ethernet_offset 14
#define ip_begin (ethernet_begin + ethernet_offset) // 14
#define ip_offset (ip_begin + 20)                   // 34
#define protocol_offset (ip_begin + 9)              // 23
#define src_ip_offset (ip_begin + 12)               // 26
#define dst_ip_offset (ip_begin + 16)               // 30
#define src_port_offset (ip_offset)                 // 34
#define dst_port_offset (ip_offset + 2)             // 36
#define mac_buf_size 18
#define max_aggregation_window_size 100000
#define min_aggregation_window_size 30
#define min_packets_for_rate 10
#define aggregation_T 1 // check every x seconds
#define rate_update_frequency aggregation_T / 2

#define FLOW_ACTIVE_TIMEOUT 3600000000ULL // 1 hour
#define FLOW_IDLE_TIMEOUT 15000000ULL     // 15 seconds (reduced for better attack detection)
#define MAX_PACKETS_PER_FLOW 2000         // Higher limit for complex flows
#define ICMP_ACTIVE_TIMEOUT 120000000ULL  // 2 minutes for ICMP
#define ICMP_IDLE_TIMEOUT 10000000ULL     // 10 seconds for ICMP

#define MAX_CONCURRENT_FLOWS 10000        // Limit total flows in memory
#define FLOW_CLEANUP_INTERVAL 60000000ULL // Cleanup every 60 seconds

std::map<int, PacketQueue> packets_queues;
std::map<int, FlowPacketsQueue> flows_queues;
std::map<int, FlowFeaturesQueue> features_queues;
size_t SHM_SIZE = sizeof(FeaturesSHMWrapper);

constexpr int MAX_RETRIES = 5;
struct SharedMemoryWriter
{
    std::string shm_name;
    int fd = -1;
    FeaturesSHMWrapper *shm_ptr = nullptr;

    SharedMemoryWriter(const std::string &name) : shm_name(name)
    {
        open_and_map();
    }

    ~SharedMemoryWriter()
    {
        if (shm_ptr != nullptr)
        {
            munmap(shm_ptr, SHM_SIZE);
        }
        if (fd != -1)
        {
            close(fd);
        }
    }

    void open_and_map()
    {
        for (int retry = 0; retry < MAX_RETRIES; ++retry)
        {
            fd = shm_open(shm_name.c_str(), O_RDWR, 0666);
            if (fd != -1)
                break;
            perror("shm_open retry");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (fd == -1)
        {
            LOG_FATAL("SharedMemory", "Failed to open shared memory after " + std::to_string(MAX_RETRIES) + " retries");
            exit(1);
        }

        void *ptr = mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED)
        {
            LOG_FATAL("SharedMemory", "Memory mapping failed: " + std::string(strerror(errno)));
            close(fd);
            exit(1);
        }

        shm_ptr = reinterpret_cast<FeaturesSHMWrapper *>(ptr);
    }

    void write(const FeaturesSHMWrapper &payload)
    {
        // Wait for any ongoing write to complete
        while (shm_ptr->writing != 0)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        // Set writing flag with memory barrier
        shm_ptr->writing = 1;
        std::atomic_thread_fence(std::memory_order_seq_cst);

        // Copy the features data
        std::memcpy(&shm_ptr->features, &payload.features, sizeof(FlowFeatures));

        // Reset consumed flag
        shm_ptr->consumed = 0;

        // Ensure all writes complete before clearing writing flag
        std::atomic_thread_fence(std::memory_order_seq_cst);
        shm_ptr->writing = 0;
    }
};

std::vector<std::vector<Device>> groups;

int packet_capture_timeout = 5000;
std::atomic<bool> running{true};
using json = nlohmann::json;

#include <sys/stat.h>
#include <ctime>
#include <map>
#include <mutex>
void save_packet_to_pcap(int group_id, pcap_t *handle, const struct pcap_pkthdr *header, const u_char *packet, const std::string &base_filepath)
{
    static std::map<int, pcap_dumper_t *> group_dumpers;
    static std::map<int, std::string> current_files;
    static std::map<int, int> file_counters;
    static std::mutex dumper_mutex;

    const size_t MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

    std::lock_guard<std::mutex> lock(dumper_mutex);

    // Check if we need to rotate the file
    bool need_rotation = false;
    std::string current_file;

    if (current_files.find(group_id) != current_files.end())
    {
        current_file = current_files[group_id];

        // Check file size
        struct stat file_stat;
        if (stat(current_file.c_str(), &file_stat) == 0)
        {
            if (file_stat.st_size >= MAX_FILE_SIZE)
            {
                need_rotation = true;
            }
        }
    }
    else
    {
        need_rotation = true;
    }

    // Rotate file if needed
    if (need_rotation)
    {
        // Close existing dumper
        if (group_dumpers.find(group_id) != group_dumpers.end() && group_dumpers[group_id])
        {
            pcap_dump_close(group_dumpers[group_id]);
            group_dumpers[group_id] = nullptr;
        }

        // Generate new filename
        if (file_counters.find(group_id) == file_counters.end())
        {
            file_counters[group_id] = 0;
        }
        int counter = file_counters[group_id]++;
        std::time_t now = std::time(nullptr);
        current_file = base_filepath + "group-" + std::to_string(group_id) +
                       "_time-" + std::to_string(now) + "_" + std::to_string(counter) + ".pcap";
        current_files[group_id] = current_file;

        // Create directory if it doesn't exist
        std::filesystem::path file_path(current_file);
        std::filesystem::path dir_path = file_path.parent_path();

        if (!dir_path.empty() && !std::filesystem::exists(dir_path))
        {
            std::error_code ec;
            if (!std::filesystem::create_directories(dir_path, ec))
            {
                LOG_ERROR("PcapSaver", "Failed to create directory: " + dir_path.string() + " - " + ec.message());
                return;
            }
            LOG_INFO("PcapSaver", "Created directory: " + dir_path.string());
        }

        // Create new dumper
        group_dumpers[group_id] = pcap_dump_open(handle, current_file.c_str());

        if (!group_dumpers[group_id])
        {
            LOG_ERROR("PcapSaver", "Failed to open pcap dump file: " + current_file);
            return;
        }

        LOG_INFO("PcapSaver", "Created new pcap file for group " + std::to_string(group_id) + ": " + current_file);
    }

    // Write packet to file
    if (group_dumpers[group_id])
    {
        pcap_dump((u_char *)group_dumpers[group_id], header, packet);
        pcap_dump_flush(group_dumpers[group_id]); // Ensure data is written immediately
    }
}

bool FlowKey::operator==(const FlowKey &other) const
{
    return protocol == other.protocol &&
           src_ip == other.src_ip &&
           dst_ip == other.dst_ip &&
           src_port == other.src_port &&
           dst_port == other.dst_port;
}

bool FlowKey::operator<(const FlowKey &other) const
{
    return std::tie(protocol, src_ip, dst_ip, src_port, dst_port) <
           std::tie(other.protocol, other.src_ip, other.dst_ip, other.src_port, other.dst_port);
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    return size * nmemb;
}

//  ! State class methods implementations
// ! ############################################################################################################
// ! ############################################################################################################

std::optional<uint64_t> State::get_last_packet_time(int16_t group_id, std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto group_it = groups_.find(group_id);
    if (group_it == groups_.end())
        return std::nullopt;

    const auto &group = group_it->second;
    std::shared_lock<std::shared_mutex> group_lock(group.mtx);
    std::string mac_str(mac);
    auto it = group.last_packet_timestamps.find(mac_str); // Fixed: use last_packet_timestamps instead of last_packet_times
    if (it != group.last_packet_timestamps.end())
        return it->second;
    return std::nullopt;
}

// void State::update_last_packet_info(int16_t group_id, const std::string &mac, uint64_t timestamp, int new_count)
// {
//     auto &group = get_or_create_group(group_id);
//     std::lock_guard<std::mutex> lock(group.mtx);
//     group.last_packet_times[mac] = timestamp;
//     // You can also update other per-device metrics here, like counts if you want.
// }

std::optional<std::tuple<uint64_t, uint64_t>> State::get_last_packet_info(int16_t g, std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    return it->second.get_last_packet_info(mac);
}

std::tuple<uint64_t, uint64_t> State::GroupStats::get_last_packet_info(std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(mtx);
    std::string mac_str(mac);
    uint64_t count = last_packet_counts.count(mac_str) ? last_packet_counts.at(mac_str) : 0;
    uint64_t ts = last_packet_timestamps.count(mac_str) ? last_packet_timestamps.at(mac_str) : 0;
    return {count, ts};
}

json State::get_stats_as_json() const
{
    json result;

    std::shared_lock<std::shared_mutex> lock(groups_mtx_);

    for (const auto &[group_id, group_stats] : groups_)
    {
        json group_json;

        // Lock this group's mutex
        std::shared_lock<std::shared_mutex> group_lock(group_stats.mtx);

        group_json["total_flows"] = group_stats.total_flows_count;
        group_json["total_processed_flows"] = group_stats.total_processed_flows_count;
        group_json["total_packets"] = group_stats.total_packets_count;

        // Avg window size: use safe access pattern
        auto window_it = group_stats.average_window_size.find(1);
        if (window_it != group_stats.average_window_size.end())
        {
            group_json["avg_window_size"] = window_it->second;
        }
        else
        {
            group_json["avg_window_size"] = 0.0;
        }

        // Compute average packet rate across devices
        long double total_rate = 0;
        int rate_count = 0;
        for (const auto &[mac, rate] : group_stats.packet_rate_device)
        {
            total_rate += rate;
            rate_count++;
        }

        group_json["avg_packet_rate"] = (rate_count > 0) ? (total_rate / rate_count) : 0.0;

        // Per-device packet rates
        json rate_json;
        for (const auto &[mac, rate] : group_stats.packet_rate_device)
        {
            rate_json[mac] = rate;
        }
        group_json["device_rates"] = rate_json;

        // Per-device flow rates
        json flow_rates_json;
        for (const auto &[mac, flow_rate] : group_stats.flow_rate_device)
        {
            flow_rates_json[mac] = flow_rate;
        }
        group_json["device_flow_rates"] = flow_rates_json;

        // Per-device packet counts (merged from shards)
        json count_json;
        std::unordered_map<std::string, int> full_counts = group_stats.get_packet_counts();
        for (const auto &[mac, count] : full_counts)
        {
            count_json[mac] = count;
        }
        group_json["device_counts"] = count_json;

        // Per-device processed flows
        json processed_flows_json;
        for (const auto &[mac, flow_count] : group_stats.processed_flows_device)
        {
            processed_flows_json[mac] = flow_count;
        }
        group_json["device_processed_flows"] = processed_flows_json;

        result["groups"][std::to_string(group_id)] = group_json;
    }

    // Global monitored devices
    {
        std::shared_lock<std::shared_mutex> lock(general_mtx);
        for (const auto &device : monitored_devices)
        {
            json dev_json;
            dev_json["mac"] = device.mac;
            dev_json["ip"] = device.ip;
            dev_json["name"] = device.name;
            result["monitored_devices"].push_back(dev_json);
        }
    }

    return result;
}

State::GroupStats::GroupStats()
    : total_flows_count(0),
      total_packets_count(0),
      packet_rate_device(),
      packet_count_shards(),
      shard_mutexes(),
      total_processed_flows_count(0),
      processed_flows_device(),
      last_flow_times(),
      flow_rate_device(),
      last_flow_counts(),
      last_flow_timestamps()
{
    average_window_size[0] = 0;   // count of windows
    average_window_size[1] = 0.0; // running average

    avg_packet_rate[0] = 0;
    avg_packet_rate[1] = 0.0;
}

std::string State::get_all_details(bool print) const
{
    std::ostringstream out;
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);

    out << "=========== State Summary ===========\n";

    for (const auto &[gid, stats] : groups_)
    {
        std::shared_lock<std::shared_mutex> lock_group(stats.mtx);

        out << "-------------------------------------\n";
        out << "Group ID: " << gid << "\n";
        out << "Total Flows Count: " << stats.total_flows_count << "\n";
        out << "Total Processed Flows Count: " << stats.total_processed_flows_count << "\n";
        out << "Total Packets Count: " << stats.total_packets_count << "\n";

        out << std::fixed << std::setprecision(4);

        // // Safe access to average window size
        // double avg_win = stats.average_window_size.count(1) ? stats.average_window_size.at(1) : 0.0;
        // out << "Average Window Size: " << avg_win << "\n";

        // Compute group-wide average packet rate
        long double sum_rate = 0;
        int rate_count = 0;
        for (const auto &[mac, rate] : stats.packet_rate_device)
        {
            sum_rate += rate;
            rate_count++;
        }

        double group_avg_rate = (rate_count > 0) ? static_cast<double>(sum_rate / rate_count) : 0.0;
        out << "Average Packet Rate (group): " << group_avg_rate << " pkts/s\n";

        // Packet rate per device
        out << "Packet Rate Per Device:\n";
        for (const auto &[mac, rate] : stats.packet_rate_device)
        {
            out << "  [" << mac << "] : " << rate << " pkts/s\n";
        }

        // Flow rate per device
        out << "Flow Rate Per Device:\n";
        for (const auto &[mac, flow_rate] : stats.flow_rate_device)
        {
            out << "  [" << mac << "] : " << flow_rate << " flows/s\n";
        }

        // Packet count per device (merged from shards)
        out << "Packet Count Per Device:\n";
        auto counts = stats.get_packet_counts();
        for (const auto &[mac, count] : counts)
        {
            out << "  [" << mac << "] : " << count << " pkts\n";
        }

        // Processed flows per device
        out << "Processed Flows Per Device:\n";
        for (const auto &[mac, flow_count] : stats.processed_flows_device)
        {
            out << "  [" << mac << "] : " << flow_count << " flows\n";
        }
    }

    out << "=====================================\n";

    // Monitored devices
    {
        std::shared_lock<std::shared_mutex> general_lock(general_mtx);
        out << "Monitored Devices (" << monitored_devices.size() << "):\n";
        for (const auto &dev : monitored_devices)
        {
            out << "  - " << dev.name << ", mac: " << dev.mac << " ip: " << dev.ip << "\n";
        }
    }

    if (print)
    {
        std::cout << out.str();
    }

    return out.str();
}

void State::GroupStats::update_last_packet_info(std::string_view mac, uint64_t timestamp, int current_count)
{
    std::unique_lock<std::shared_mutex> lock(mtx); // Group-level protection

    last_packet_timestamps[std::string(mac)] = timestamp;
    last_packet_counts[std::string(mac)] = current_count;
}
void State::update_last_packet_info(int16_t group_id, std::string_view mac, uint64_t timestamp, int current_count)
{
    GroupStats &group = get_or_create_group(group_id); // This already handles locking internally
    group.update_last_packet_info(mac, timestamp, current_count);
}

std::vector<int16_t> State::get_all_group_ids() const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    std::vector<int16_t> keys;
    keys.reserve(groups_.size());
    for (const auto &[group_id, _] : groups_)
    {
        keys.push_back(group_id);
    }
    return keys;
}

int State::GroupStats::get_shard_index(std::string_view mac) const
{
    return static_cast<int>(std::hash<std::string_view>{}(mac) % NUM_SHARDS);
}

void State::GroupStats::increment_packet_count(std::string_view mac, int increment_by)
{
    int shard = get_shard_index(mac);
    std::unique_lock<std::shared_mutex> lock(shard_mutexes[shard]);
    packet_count_shards[shard][std::string(mac)] += increment_by;
}

std::unordered_map<std::string, int> State::GroupStats::get_packet_counts() const
{
    std::unordered_map<std::string, int> result;
    for (int i = 0; i < NUM_SHARDS; ++i)
    {
        std::shared_lock<std::shared_mutex> lock(shard_mutexes[i]);
        result.insert(packet_count_shards[i].begin(),
                      packet_count_shards[i].end());
    }
    return result;
}

// ----------------------------------------
// Packet Rate History Implementation
// ----------------------------------------

void State::GroupStats::add_rate_history_entry(std::string_view mac, long double rate, uint64_t timestamp, uint64_t packet_count)
{
    std::unique_lock<std::shared_mutex> lock(mtx);

    std::string mac_str(mac);

    // Initialize history vector if first time seeing this device
    if (rate_history_device.find(mac_str) == rate_history_device.end())
    {
        rate_history_device[mac_str].reserve(MAX_HISTORY_ENTRIES);
        history_write_index[mac_str] = 0;
    }

    auto &history = rate_history_device[mac_str];
    auto &write_idx = history_write_index[mac_str];

    RateHistoryEntry entry = {timestamp, rate, packet_count};

    // Use circular buffer approach
    if (history.size() < MAX_HISTORY_ENTRIES)
    {
        history.push_back(entry);
    }
    else
    {
        history[write_idx] = entry;
        write_idx = (write_idx + 1) % MAX_HISTORY_ENTRIES;
    }
}

void State::GroupStats::update_group_rate_history(uint64_t timestamp)
{
    std::unique_lock<std::shared_mutex> lock(mtx);

    // Calculate current group average rate
    long double total_rate = 0;
    uint64_t total_packets = 0;
    int device_count = 0;

    for (const auto &[mac, rate] : packet_rate_device)
    {
        total_rate += rate;
        device_count++;

        // Get packet count for this device
        auto packet_counts = get_packet_counts();
        auto it = packet_counts.find(mac);
        if (it != packet_counts.end())
        {
            total_packets += it->second;
        }
    }

    long double avg_rate = device_count > 0 ? total_rate / device_count : 0.0;

    RateHistoryEntry entry = {timestamp, avg_rate, total_packets};

    // Initialize group history if needed
    if (group_rate_history.capacity() < MAX_HISTORY_ENTRIES)
    {
        group_rate_history.reserve(MAX_HISTORY_ENTRIES);
    }

    // Use circular buffer for group history
    if (group_rate_history.size() < MAX_HISTORY_ENTRIES)
    {
        group_rate_history.push_back(entry);
    }
    else
    {
        group_rate_history[group_history_write_index] = entry;
        group_history_write_index = (group_history_write_index + 1) % MAX_HISTORY_ENTRIES;
    }
}

std::vector<State::GroupStats::RateHistoryEntry> State::GroupStats::get_rate_history(std::string_view mac, size_t max_entries) const
{
    std::shared_lock<std::shared_mutex> lock(mtx);

    std::string mac_str(mac);
    auto it = rate_history_device.find(mac_str);
    if (it == rate_history_device.end())
    {
        return {};
    }

    const auto &history = it->second;
    if (history.empty())
    {
        return {};
    }

    // Return entries in chronological order
    std::vector<RateHistoryEntry> result;
    result.reserve(std::min(max_entries, history.size()));

    // If buffer is not full, return from beginning
    if (history.size() < MAX_HISTORY_ENTRIES)
    {
        size_t start = history.size() > max_entries ? history.size() - max_entries : 0;
        for (size_t i = start; i < history.size(); ++i)
        {
            result.push_back(history[i]);
        }
    }
    else
    {
        // Buffer is full, need to handle circular nature
        auto write_it = history_write_index.find(mac_str);
        size_t write_idx = write_it != history_write_index.end() ? write_it->second : 0;

        size_t entries_to_return = std::min(max_entries, history.size());
        size_t start_idx = (write_idx + MAX_HISTORY_ENTRIES - entries_to_return) % MAX_HISTORY_ENTRIES;

        for (size_t i = 0; i < entries_to_return; ++i)
        {
            size_t idx = (start_idx + i) % MAX_HISTORY_ENTRIES;
            result.push_back(history[idx]);
        }
    }

    return result;
}

std::vector<State::GroupStats::RateHistoryEntry> State::GroupStats::get_recent_rate_history(std::string_view mac, uint64_t time_window_us) const
{
    auto all_history = get_rate_history(mac);
    if (all_history.empty())
    {
        return {};
    }

    uint64_t cutoff_time = all_history.back().timestamp - time_window_us;

    std::vector<RateHistoryEntry> recent;
    for (const auto &entry : all_history)
    {
        if (entry.timestamp >= cutoff_time)
        {
            recent.push_back(entry);
        }
    }

    return recent;
}

std::vector<State::GroupStats::RateHistoryEntry> State::GroupStats::get_group_rate_history(size_t max_entries) const
{
    std::shared_lock<std::shared_mutex> lock(mtx);

    if (group_rate_history.empty())
    {
        return {};
    }

    std::vector<RateHistoryEntry> result;
    result.reserve(std::min(max_entries, group_rate_history.size()));

    // If buffer is not full, return from beginning
    if (group_rate_history.size() < MAX_HISTORY_ENTRIES)
    {
        size_t start = group_rate_history.size() > max_entries ? group_rate_history.size() - max_entries : 0;
        for (size_t i = start; i < group_rate_history.size(); ++i)
        {
            result.push_back(group_rate_history[i]);
        }
    }
    else
    {
        // Buffer is full, handle circular nature
        size_t entries_to_return = std::min(max_entries, group_rate_history.size());
        size_t start_idx = (group_history_write_index + MAX_HISTORY_ENTRIES - entries_to_return) % MAX_HISTORY_ENTRIES;

        for (size_t i = 0; i < entries_to_return; ++i)
        {
            size_t idx = (start_idx + i) % MAX_HISTORY_ENTRIES;
            result.push_back(group_rate_history[idx]);
        }
    }

    return result;
}

State::GroupStats::RateStatistics State::GroupStats::calculate_rate_statistics(std::string_view mac, uint64_t time_window_us) const
{
    auto history = get_recent_rate_history(mac, time_window_us);

    RateStatistics stats = {0.0, std::numeric_limits<long double>::max(),
                            std::numeric_limits<long double>::lowest(), 0.0, 0, 0};

    if (history.empty())
    {
        stats.min_rate = 0.0;
        stats.max_rate = 0.0;
        return stats;
    }

    stats.sample_count = history.size();
    stats.time_span_us = history.back().timestamp - history.front().timestamp;

    // Calculate mean
    long double sum = 0.0;
    for (const auto &entry : history)
    {
        sum += entry.rate;
        stats.min_rate = std::min(stats.min_rate, entry.rate);
        stats.max_rate = std::max(stats.max_rate, entry.rate);
    }
    stats.avg_rate = sum / history.size();

    // Calculate standard deviation
    long double variance_sum = 0.0;
    for (const auto &entry : history)
    {
        long double diff = entry.rate - stats.avg_rate;
        variance_sum += diff * diff;
    }
    stats.std_deviation = std::sqrt(variance_sum / history.size());

    return stats;
}

State::GroupStats::RateStatistics State::GroupStats::calculate_group_rate_statistics(uint64_t time_window_us) const
{
    auto history = get_group_rate_history();

    RateStatistics stats = {0.0, std::numeric_limits<long double>::max(),
                            std::numeric_limits<long double>::lowest(), 0.0, 0, 0};

    if (history.empty())
    {
        stats.min_rate = 0.0;
        stats.max_rate = 0.0;
        return stats;
    }

    // Filter by time window
    uint64_t cutoff_time = history.back().timestamp - time_window_us;
    std::vector<RateHistoryEntry> recent;
    for (const auto &entry : history)
    {
        if (entry.timestamp >= cutoff_time)
        {
            recent.push_back(entry);
        }
    }

    if (recent.empty())
    {
        stats.min_rate = 0.0;
        stats.max_rate = 0.0;
        return stats;
    }

    stats.sample_count = recent.size();
    stats.time_span_us = recent.back().timestamp - recent.front().timestamp;

    // Calculate statistics
    long double sum = 0.0;
    for (const auto &entry : recent)
    {
        sum += entry.rate;
        stats.min_rate = std::min(stats.min_rate, entry.rate);
        stats.max_rate = std::max(stats.max_rate, entry.rate);
    }
    stats.avg_rate = sum / recent.size();

    // Calculate standard deviation
    long double variance_sum = 0.0;
    for (const auto &entry : recent)
    {
        long double diff = entry.rate - stats.avg_rate;
        variance_sum += diff * diff;
    }
    stats.std_deviation = std::sqrt(variance_sum / recent.size());

    return stats;
}

State::State() = default;
State::~State() = default;

State::GroupStats &State::get_or_create_group(int16_t group_id)
{
    std::unique_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(group_id);
    if (it == groups_.end())
    {
        // Construct GroupStats in-place without copying/moving
        auto [new_it, inserted] = groups_.try_emplace(group_id);
        return new_it->second;
    }
    return it->second;
}

void State::set_total_packets_count(int16_t g, unsigned long long int new_count)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);
    S.total_packets_count = new_count;
}

void State::set_total_flows_count(int16_t g, int16_t new_count)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);
    S.total_flows_count = new_count;
}

void State::set_average_window_size(int16_t g, int new_window_size)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);

    double count = S.average_window_size[0];
    double old_avg = S.average_window_size[1];

    double new_avg = (old_avg * count + new_window_size) / (count + 1);

    S.average_window_size[0] = count + 1;
    S.average_window_size[1] = new_avg;
}

void State::set_avg_packet_rate(int16_t g, double /*unused*/)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);

    long double sum = 0;
    int count = 0;

    for (const auto &[mac, rate] : S.packet_rate_device)
    {
        sum += rate;
        count++;
    }

    if (count > 0)
        S.avg_packet_rate[1] = static_cast<double>(sum / count);
    else
        S.avg_packet_rate[1] = 0;

    S.avg_packet_rate[0] = count; // how many devices were averaged
}

void State::set_packet_rate_device(int16_t g, std::string_view mac, long double new_rate)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);
    S.packet_rate_device[std::string(mac)] = new_rate;
}

void State::set_monitored_devices(const std::vector<Device> &new_devices)
{
    std::unique_lock<std::shared_mutex> lock(general_mtx);
    monitored_devices = new_devices;
}

void State::set_packet_count_per_device(int16_t g, const std::unordered_map<std::string, int> &new_counts)
{
    GroupStats &S = get_or_create_group(g);

    // Lock all shard mutexes in order to ensure atomic operation
    std::vector<std::unique_lock<std::shared_mutex>> shard_locks;
    for (int i = 0; i < GroupStats::NUM_SHARDS; ++i)
    {
        shard_locks.emplace_back(S.shard_mutexes[i]);
    }

    // Clear all shards
    for (auto &shard_map : S.packet_count_shards)
    {
        shard_map.clear();
    }

    // Re-insert data into appropriate shards
    for (const auto &[mac, cnt] : new_counts)
    {
        int shard = S.get_shard_index(mac);
        S.packet_count_shards[shard][mac] = cnt;
    }

    // Locks automatically released when shard_locks goes out of scope
}

std::optional<long double> State::get_packet_rate(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    const GroupStats &S = it->second;
    std::shared_lock<std::shared_mutex> group_lock(S.mtx);
    auto rate_it = S.avg_packet_rate.find(1);
    if (rate_it != S.avg_packet_rate.end())
        return rate_it->second;
    return std::nullopt;
}

std::optional<unsigned long long int> State::get_total_packets_count(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    const GroupStats &S = it->second;
    std::shared_lock<std::shared_mutex> group_lock(S.mtx);
    return S.total_packets_count;
}

std::optional<unsigned long long int> State::get_total_flows_count(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    const GroupStats &S = it->second;
    std::shared_lock<std::shared_mutex> group_lock(S.mtx);
    return S.total_flows_count;
}

std::optional<double> State::get_average_window_size(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    const GroupStats &S = it->second;
    std::shared_lock<std::shared_mutex> group_lock(S.mtx);
    auto window_it = S.average_window_size.find(1);
    if (window_it != S.average_window_size.end())
        return window_it->second;
    return std::nullopt;
}

std::optional<long double> State::get_packet_rate_device(int16_t g, std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    const GroupStats &S = it->second;
    std::shared_lock<std::shared_mutex> group_lock(S.mtx);
    std::string mac_str(mac);
    auto dit = S.packet_rate_device.find(mac_str);
    if (dit != S.packet_rate_device.end())
        return dit->second;
    return std::nullopt;
}

std::vector<Device> State::get_monitored_devices() const
{
    std::shared_lock<std::shared_mutex> lock(general_mtx);

    return monitored_devices;
}

std::optional<std::unordered_map<std::string, int>> State::get_packet_count_per_device(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
        return std::nullopt;
    return it->second.get_packet_counts();
}

void State::increment_flow_count_group(int16_t g, int increment_by)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);
    S.total_flows_count += increment_by;
}

void State::increment_packet_count_device(int16_t g, std::string_view mac, int increment_by)
{
    GroupStats &S = get_or_create_group(g);
    S.increment_packet_count(mac, increment_by);
}

bool State::check_if_dev_monitored(std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(general_mtx);

    for (auto &dev : monitored_devices)
    {
        if (dev.mac == mac)
        {
            return true;
        }
    }
    return false;
}

void State::print_numeric(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        LOG_WARNING("State", "Group " + std::to_string(g) + " not found");
        return;
    }
    const GroupStats &S = it->second;
    std::shared_lock<std::shared_mutex> group_lock(S.mtx);

    // Safe access to map values with default fallback
    auto window_it = S.average_window_size.find(1);
    double avg_window = (window_it != S.average_window_size.end()) ? window_it->second : 0.0;

    auto rate_it = S.avg_packet_rate.find(1);
    double avg_rate = (rate_it != S.avg_packet_rate.end()) ? rate_it->second : 0.0;

    LOG_INFO("State", "Group " + std::to_string(g) + " stats - " +
                          "Flows: " + std::to_string(S.total_flows_count) +
                          ", Processed Flows: " + std::to_string(S.total_processed_flows_count) +
                          ", Packets: " + std::to_string(S.total_packets_count) +
                          ", Avg Window: " + std::to_string(avg_window) +
                          ", Packet Rate: " + std::to_string(avg_rate));
}

// ! ############################################################################################################
// ! ############################################################################################################

//  ! PacketQueue methods implementations
// ! ############################################################################################################
// ! ############################################################################################################

void PacketQueue::push(Packet packet)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (queue_.size() >= max_size_)
        queue_.pop();
    queue_.push(std::move(packet));

    lock.unlock();
    cv_.notify_one();
}

Packet PacketQueue::pop()
{
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]
             { return !queue_.empty(); });
    Packet packet = std::move(queue_.front());
    queue_.pop();
    return packet;
}

bool PacketQueue::try_pop(Packet &packet, int timeout_ms)
{
    std::unique_lock<std::mutex> lock(mutex_);

    if (queue_.empty())
    {
        auto result = cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this]
                                   { return !queue_.empty() || !running; });

        if (!result)
        {
            return false;
        }
    }

    if (!running && queue_.empty())
    {
        return false;
    }

    if (!queue_.empty())
    {
        packet = queue_.front();
        queue_.pop();
        return true;
    }

    return false;
}

int PacketQueue::get_size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

void PacketQueue::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::queue<Packet> empty;
    std::swap(queue_, empty);
}

// ! ############################################################################################################
// ! ############################################################################################################

//  ! FlowPacketsQueue methods implementations
// ! ############################################################################################################
// ! ############################################################################################################

bool FlowPacketsQueue::try_pop(std::vector<Packet> &FlowPackets, int timeout_ms)
{
    std::unique_lock<std::mutex> lock(mutex_);

    if (queue_.empty())
    {
        auto result = cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this]
                                   { return !queue_.empty() || !running; });

        if (!result)
        {
            return false;
        }
    }

    if (!running && queue_.empty())
    {
        return false;
    }

    if (!queue_.empty())
    {
        FlowPackets = queue_.front();
        queue_.pop();
        return true;
    }

    return false;
}

// ? FlowQueue methods
void FlowPacketsQueue::push(std::vector<Packet> packets)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (queue_.size() >= max_size_)
        queue_.pop();
    queue_.push(std::move(packets));
    lock.unlock();
    cv_.notify_one();
}

std::vector<Packet> FlowPacketsQueue::pop()
{
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]
             { return !queue_.empty(); });
    std::vector<Packet> packets = std::move(queue_.front());
    queue_.pop();
    return packets;
}

void FlowPacketsQueue::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::queue<std::vector<Packet>> empty;
    std::swap(queue_, empty);
}

int FlowPacketsQueue::get_size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

// ! ############################################################################################################
// ! ############################################################################################################

//  ! FlowFeaturesQueue methods implementations
// ! ############################################################################################################
// ! ############################################################################################################

bool FlowFeaturesQueue::try_pop(FlowFeatures &flow_features, int timeout_ms)
{
    std::unique_lock<std::mutex> lock(mutex_);

    if (queue_.empty())
    {
        auto result = cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this]
                                   { return !queue_.empty() || !running; });

        if (!result)
        {
            return false;
        }
    }

    if (!running && queue_.empty())
    {
        return false;
    }

    if (!queue_.empty())
    {
        flow_features = queue_.front();
        queue_.pop();
        return true;
    }

    return false;
}

void FlowFeaturesQueue::push(FlowFeatures flow_features)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (queue_.size() >= max_size_)
        queue_.pop();
    queue_.push(std::move(flow_features));
    lock.unlock();
    cv_.notify_one();
}

FlowFeatures FlowFeaturesQueue::pop()
{
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]
             { return !queue_.empty(); });
    FlowFeatures features = std::move(queue_.front());
    queue_.pop();
    return features;
}

void FlowFeaturesQueue::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::queue<FlowFeatures> empty;
    std::swap(queue_, empty);
}

int FlowFeaturesQueue::get_size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

// ! ############################################################################################################
// ! ############################################################################################################

namespace std
{
    size_t hash<FlowKey>::operator()(const FlowKey &key) const
    {
        size_t h1 = hash<uint32_t>()(key.src_ip);
        size_t h2 = hash<uint32_t>()(key.dst_ip);
        size_t h3 = hash<uint16_t>()(key.src_port);
        size_t h4 = hash<uint16_t>()(key.dst_port);
        size_t h5 = hash<uint8_t>()(key.protocol);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
}

uint16_t rate_based_sizing(std::string mac, long double rate)
{
    // Target window size should capture approximately aggregation_T seconds worth of packets
    double target_duration = aggregation_T;
    uint size = static_cast<uint16_t>(std::ceil(rate * target_duration));

    // Apply reasonable bounds
    if (size < min_aggregation_window_size)
    {
        size = min_aggregation_window_size;
    }
    else if (size > max_aggregation_window_size)
    {
        size = max_aggregation_window_size;
    }

    return size;
}

std::string trim(const std::string &str)
{
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string arp_lookup(const std::string &mac, const std::string &interface)
{
    // ? this function depends on the local arp table to match a mac address to the attributed IP address
    // ? since there are multiple network interfaces
    // ? this function should also match the selected interface to get the correct IP

    std::ifstream arp_file("/proc/net/arp");

    std::string line;
    std::getline(arp_file, line); // * Skip header
    while (std::getline(arp_file, line))
    {
        std::istringstream iss(line);
        std::string ip, type, flags, hw_addr, mask, device;
        iss >> ip >> type >> flags >> hw_addr >> mask >> device;

        // std::cout << debug << "comparing: " << trim(hw_addr) << " to " << trim(mac) << " and " << trim(device) << " to " << interface << reset << "\n";

        if (trim(hw_addr) == trim(mac) && trim(device) == interface)
        {
            return ip;
        }
    }

    return "";
}

std::string get_ip_from_mac(const std::string &mac, const std::string &interface, bool &looked)
{

    std::string ipv4 = arp_lookup(mac, interface);

    if (ipv4 != "")
    {
        return ipv4;
    }

    // TODO:
    /*
        ! host discovery using IP Sweep
    */

    // ? if this code is reached, it means the given mac address is not present in the local arp table, donc ro7 dir ping sweep that will update the arp table with new addresses

    if (!looked)
    {
        IP_sweep(interface);

        looked = true;

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        cleanARPTable();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    ipv4 = arp_lookup(mac, interface);

    if (ipv4 == "")
    {
        LOG_WARNING("ARP", "No IP found for MAC " + mac);
    }

    return ipv4;
}

bool ping_host(const std::string &ip, const std::string &interface)
{

    //  ? ping a single IP
    std::string command;
#ifdef _WIN32
    command = "ping -n 1 -w 500 -S " + interface + " " + ip + " > nul 2>&1";
#else
    command = "ping -c 1 -W 1 -I " + interface + " " + ip + " > /dev/null 2>&1";
#endif
    // std::cout << debug << "\tpinging: " << command << reset << "\n";
    return system(command.c_str()) == 0;
}

void cleanARPTable()
{
#ifdef _WIN32
    std::string command = "netsh interface ip delete arpcache > nul 2>&1";
    if (system(command.c_str()) == 0)
    {
        LOG_INFO("ARP", "ARP cache cleared successfully on Windows");
    }
    else
    {
        LOG_ERROR("ARP", "Failed to clear ARP cache on Windows");
    }
#else
    std::vector<std::string> nud_states = {"incomplete", "failed", "noarp", "permanent"};
    bool any_success = false;

    for (const auto &state : nud_states)
    {
        std::string command = "sudo ip neigh flush nud " + state + " > /dev/null 2>&1";
        if (system(command.c_str()) == 0)
        {
            any_success = true;
            LOG_DEBUG("ARP", "Flushed " + state + " ARP entries successfully");
        }
        else
        {
            LOG_DEBUG("ARP", "No " + state + " ARP entries to flush or insufficient privileges");
        }
    }

    if (any_success)
    {
        LOG_INFO("ARP", "ARP table cleanup completed");
    }
    else
    {
        LOG_ERROR("ARP", "Failed to flush any ARP entries (ensure sudo privileges)");
    }
#endif
}

void IP_sweep(const std::string &interface)
{
    LOG_INFO("IPSweep", "Starting IP Sweep on interface: " + interface);

    try
    {
        struct in_addr broadcast_addr, network_addr;

        // Get interface IP and netmask
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            throw std::runtime_error("Failed to open socket for IP sweep");
        }

        // Use RAII to ensure socket is closed
        auto sock_guard = std::unique_ptr<int, std::function<void(int *)>>(
            &sock, [](int *s)
            { if (*s >= 0) close(*s); });

        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, interface.c_str(), IF_NAMESIZE - 1);

        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        {
            throw std::runtime_error("Failed to retrieve IP address for " + interface);
        }

        in_addr_t ipv4_bin_big_endian = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);

        if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
        {
            throw std::runtime_error("Failed to retrieve network mask for " + interface);
        }

        in_addr_t mask_bin_big_endian = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);

        broadcast_addr.s_addr = ipv4_bin_big_endian | ~mask_bin_big_endian;
        network_addr.s_addr = ipv4_bin_big_endian & mask_bin_big_endian;
        // broadcast_addr.s_addr = htonl(ipv4_bin_big_endian | ~mask_bin_big_endian);
        // network_addr.s_addr = htonl(ipv4_bin_big_endian & mask_bin_big_endian);

        // Create temporary structs with proper byte order for display only
        struct in_addr network_display, broadcast_display;
        network_display.s_addr = htonl(network_addr.s_addr);
        broadcast_display.s_addr = htonl(broadcast_addr.s_addr);

        LOG_INFO("IPSweep", "Scanning network: " + std::string(inet_ntoa(network_display)) +
                                " broadcast: " + std::string(inet_ntoa(broadcast_display)));

        // Collect IP addresses to scan
        std::vector<std::string> ip_list;
        for (in_addr_t current_ip = network_addr.s_addr + 1; current_ip < broadcast_addr.s_addr; current_ip++)
        {
            struct in_addr addr;
            addr.s_addr = htonl(current_ip); // Convert back to network byte order
            ip_list.push_back(inet_ntoa(addr));
        }

        // Set a reasonable maximum number of threads
        const size_t MAX_THREADS = 50;
        const size_t thread_count = std::min(ip_list.size(), MAX_THREADS);
        std::vector<std::thread> sweep_threads;

        // Divide work among threads
        size_t ips_per_thread = (ip_list.size() + thread_count - 1) / thread_count;

        for (size_t t = 0; t < thread_count; t++)
        {
            size_t start_idx = t * ips_per_thread;
            size_t end_idx = std::min((t + 1) * ips_per_thread, ip_list.size());

            if (start_idx < ip_list.size())
            {
                sweep_threads.emplace_back(
                    [&ip_list, start_idx, end_idx, &interface]()
                    {
                        for (size_t i = start_idx; i < end_idx; i++)
                        {
                            ping_host(ip_list[i], interface);
                        }
                    });
            }
        }

        // Join all threads
        for (auto &t : sweep_threads)
        {
            t.join();
        }

        LOG_INFO("IPSweep", "IP Sweep completed for " + std::to_string(ip_list.size()) + " addresses");
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("IPSweep", "IP sweep error: " + std::string(e.what()));
    }
}

std::vector<std::string> group_devices(const std::string &json_file, int &K, const std::string &interface, State &state)
{
    //  ? read json file
    std::ifstream file(json_file);

    if (!file.is_open())
        throw std::runtime_error("Failed to open " + json_file);

    json devices_json;
    file >> devices_json;

    std::vector<Device> devices;

    // ? this variable will hold the index of the last group
    K = 0;

    // ? to make sure that an IP Sweep is done only once if needed
    bool looked = false;

    // ? save monitored devices

    for (const auto &d : devices_json)
    {
        Device dev;
        dev.mac = d["mac"].get<std::string>();
        dev.name = d["name"].get<std::string>();
        dev.group = d["group"].get<int>();

        // ? use the mac address of the device to get it's current IP address.
        dev.ip = get_ip_from_mac(dev.mac, interface, looked);
        if (dev.ip.empty())
        {
            continue;
        }

        // monitor_list.insert({dev.mac, dev});
        devices.push_back(dev);
        // std::cout << debug << "adding device: " << dev.name << " to monitoring list" << reset << "\n";
        K = std::max(K, dev.group + 1);
    }

    // ? update the global state
    state.set_monitored_devices(devices);

    groups.resize(K);
    for (const auto &dev : devices)
    {
        // const Device &dev = pair.second;
        groups[dev.group].push_back(dev);
        state.increment_flow_count_group(dev.group, 0);
    }

    // ? the groups are represented by filters with the IP addresses to capture
    // ? the following will create  vector with all filters
    std::vector<std::string> group_filters(K);
    for (int i = 0; i < K; i++)
    {
        for (size_t j = 0; j < groups[i].size(); j++)
        {
            group_filters[i] += "src host " + groups[i][j].ip + " or dst host " + groups[i][j].ip;
            if (j < groups[i].size() - 1)
                group_filters[i] += " or ";
        }
        if (group_filters[i].empty())
            group_filters[i] = "src host 0.0.0.0";
    }

    return group_filters;
}

FlowKey normalize_flow_key(uint8_t protocol, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    if (src_ip > dst_ip)
    {
        std::swap(src_ip, dst_ip);
    }
    return {protocol, src_ip, dst_ip, src_port, dst_port};
}

void rate_calculation_thread(int group_id, State &state)
{
    LOG_THREAD_INFO("RateCalc-" + std::to_string(group_id), "Rate", "Rate calculation thread started");

    std::map<std::string, uint64_t> last_counts;
    std::map<std::string, uint64_t> last_times;

    while (running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1)); // run every second

        // Get all current packet counts and timestamps from State
        auto current_counts_opt = state.get_packet_count_per_device(group_id);
        if (!current_counts_opt.has_value())
        {
            continue; // Skip if group doesn't exist
        }
        auto &current_counts = current_counts_opt.value();

        for (const auto &[mac, current_count] : current_counts)
        {
            auto now_ts_opt = state.get_last_packet_time(group_id, mac);
            if (!now_ts_opt.has_value())
            {
                LOG_THREAD_DEBUG("RateCalc-" + std::to_string(group_id), "Rate",
                                 "No timestamp available for MAC: " + mac);
                continue; // Skip if no timestamp available for this MAC
            }
            uint64_t now_ts = now_ts_opt.value();
            LOG_THREAD_DEBUG("RateCalc-" + std::to_string(group_id), "Rate",
                             "Processing MAC: " + mac + " count: " + std::to_string(current_count) +
                                 " timestamp: " + std::to_string(now_ts));

            if (last_counts.find(mac) != last_counts.end())
            {
                uint64_t delta_count = current_count - last_counts[mac];
                uint64_t delta_time = now_ts - last_times[mac]; // microseconds

                long double rate = (delta_time > 0)
                                       ? (delta_count / (delta_time / 1e6)) // packets per second
                                       : 0;

                LOG_THREAD_DEBUG("RateCalc-" + std::to_string(group_id), "Rate",
                                 "Calculated rate for " + mac + ": " + std::to_string(rate) +
                                     " pps (delta_count=" + std::to_string(delta_count) +
                                     ", delta_time=" + std::to_string(delta_time) + "µs)");

                state.set_packet_rate_device(group_id, mac, rate);
                state.set_avg_packet_rate(group_id, rate);

                // Add to rate history
                state.add_device_rate_history(group_id, mac, rate, now_ts, current_count);
            }
            else
            {
                LOG_THREAD_DEBUG("RateCalc-" + std::to_string(group_id), "Rate",
                                 "First time seeing MAC: " + mac + " - initializing counters");
            }

            last_counts[mac] = current_count;
            last_times[mac] = now_ts;
        }

        // Update group-level rate history every cycle
        uint64_t current_time = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
        state.update_group_rate_history(group_id, current_time);
    }

    LOG_THREAD_WARNING("RateCalc-" + std::to_string(group_id), "Rate", "Rate calculation thread exiting");
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    try
    {
        if (header->len > 14)
        {
            LOG_DEBUG("PacketHandler", "Packet received! Length: " + std::to_string(header->len));

            packet_handler_args &args = *reinterpret_cast<packet_handler_args *>(user);
            int group_id = args.group_id;
            State &state = args.state;

            std::string pcap_filepath = "./traffic/capture/group_" + std::to_string(group_id) + "/capture/";
            // _grp-" + std::to_string(group_id) + "_time_" + std::to_string(std::time(nullptr)) + ".pcap";
            Packet pkt;
            pkt.data.resize(header->len);
            std::copy(packet, packet + PACKET_OFFSET, pkt.data.begin());

            pkt.timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000ULL + header->ts.tv_usec;

            // Extract MACs
            const u_char *eth_src = packet + 6;
            const u_char *eth_dst = packet + 0;

            auto mac_to_string = [](const u_char *mac) -> std::string
            {
                std::ostringstream oss;
                for (int i = 0; i < 6; ++i)
                {
                    if (i > 0)
                        oss << ":";
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
                }
                return oss.str();
            };

            std::string smac = mac_to_string(eth_src);
            std::string dmac = mac_to_string(eth_dst);

            // Check if either MAC is monitored
            std::string monitored_mac;
            if (state.check_if_dev_monitored(smac))
                monitored_mac = smac;
            else if (state.check_if_dev_monitored(dmac))
                monitored_mac = dmac;
            else
            {
                LOG_DEBUG("PacketHandler", "Packet discarded - MACs not monitored: " + smac + " / " + dmac);
                return; // not relevant, skip this packet
            }

            LOG_DEBUG("PacketHandler", "Processing packet for monitored MAC: " + monitored_mac);

            // Update counters
            auto current_packet_count = state.get_total_packets_count(group_id);
            state.set_total_packets_count(group_id, current_packet_count.value_or(0) + 1);
            state.increment_packet_count_device(group_id, monitored_mac, 1);

            auto packet_counts = state.get_packet_count_per_device(group_id);
            int count_now = 0;
            if (packet_counts.has_value())
            {
                auto it = packet_counts->find(std::string(monitored_mac));
                if (it != packet_counts->end())
                {
                    count_now = it->second;
                }
            }

            state.update_last_packet_info(group_id, monitored_mac, pkt.timestamp, count_now);

            packets_queues[group_id].push(pkt);
            save_packet_to_pcap(args.group_id, args.handle, header, packet, pcap_filepath);
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("PacketHandler", "Packet handler error: " + std::string(e.what()));
    }
}

void capture_thread(int group_id, const std::string &device, const std::string &filter_exp, State &state)
{
    LOG_THREAD_INFO("Capture-" + std::to_string(group_id), "Capture", "Packet capture thread started");
    try
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, packet_capture_timeout, errbuf);
        if (!handle)
            throw std::runtime_error("Group " + std::to_string(group_id) + ": Failed to open device: " + errbuf);

        struct bpf_program filter;
        if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
            throw std::runtime_error("Group " + std::to_string(group_id) + ": Failed to compile filter: " + pcap_geterr(handle));
        }
        if (pcap_setfilter(handle, &filter) == -1)
        {
            throw std::runtime_error("Group " + std::to_string(group_id) + ": Failed to set filter: " + pcap_geterr(handle));
        }

        packet_handler_args args(group_id, state, handle);

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        LOG_THREAD_INFO("Capture-" + std::to_string(group_id), "Capture",
                        "Capture started with filter: " + filter_exp);

        LOG_THREAD_DEBUG("Capture-" + std::to_string(group_id), "Capture",
                         "Starting pcap_loop for packet processing");

        // Use pcap_dispatch instead of pcap_loop for better control
        int packet_count;
        while (running)
        {
            packet_count = pcap_dispatch(handle, 100, packet_handler, reinterpret_cast<u_char *>(&args));
            if (packet_count == -1)
            {
                LOG_THREAD_ERROR("Capture-" + std::to_string(group_id), "Capture",
                                 "pcap_dispatch error: " + std::string(pcap_geterr(handle)));
                break;
            }
            if (packet_count == 0)
            {
                // No packets captured, brief sleep to prevent busy waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            else
            {
                LOG_THREAD_DEBUG("Capture-" + std::to_string(group_id), "Capture",
                                 "Dispatched " + std::to_string(packet_count) + " packets");
            }
        }

        pcap_close(handle);
    }
    catch (const std::exception &e)
    {
        LOG_THREAD_ERROR("Capture-" + std::to_string(group_id), "Capture",
                         "Capture thread error: " + std::string(e.what()));
        running = false;
    }

    LOG_THREAD_WARNING("Capture-" + std::to_string(group_id), "Capture", "Packet capture thread exiting");
}
inline uint64_t now_us()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool extract_flow_key_from_packet(const Packet &packet, FlowKey &flow_key)
{
    const std::vector<uint8_t> &data = packet.data;

    // Minimum packet size check (Ethernet header = 14 bytes)
    if (data.size() < 14)
    {
        return false;
    }

    // Extract Ethernet type
    uint16_t ethernet_type = (data[12] << 8) | data[13];

    // Only process IPv4 packets for now
    if (ethernet_type != 0x0800)
    {
        return false;
    }

    // Ensure we have minimum IP header
    const size_t ip_header_start = 14;
    if (data.size() < ip_header_start + 20)
    {
        return false;
    }

    // Extract IP header fields
    uint8_t ip_header_length = (data[ip_header_start] & 0x0F) * 4;
    uint8_t protocol = data[ip_header_start + 9];

    // Extract IP addresses (network byte order)
    uint32_t src_ip = (data[ip_header_start + 12] << 24) |
                      (data[ip_header_start + 13] << 16) |
                      (data[ip_header_start + 14] << 8) |
                      data[ip_header_start + 15];

    uint32_t dst_ip = (data[ip_header_start + 16] << 24) |
                      (data[ip_header_start + 17] << 16) |
                      (data[ip_header_start + 18] << 8) |
                      data[ip_header_start + 19];

    uint16_t src_port = 0, dst_port = 0;

    // Extract ports for TCP/UDP
    size_t transport_header_start = ip_header_start + ip_header_length;
    if (protocol == 6 || protocol == 17)
    { // TCP or UDP
        if (data.size() >= transport_header_start + 4)
        {
            src_port = (data[transport_header_start] << 8) | data[transport_header_start + 1];
            dst_port = (data[transport_header_start + 2] << 8) | data[transport_header_start + 3];
        }
    }

    // Create normalized bidirectional flow key
    flow_key = normalize_flow_key(protocol, src_ip, dst_ip, src_port, dst_port);
    return true;
}

void flow_aggregation_thread(int group_id, State &state)
{
    LOG_THREAD_INFO("FlowAggregation-" + std::to_string(group_id), "Flow", "Flow aggregation thread started");

    PacketQueue &current_queue = packets_queues[group_id];
    std::vector<Device> &devices_in_group = groups[group_id];

    // Per-flow packet storage using 5-tuple keys
    std::map<FlowKey, std::vector<Packet>> flow_packets;
    std::map<FlowKey, uint64_t> flow_start_time;
    std::map<FlowKey, uint64_t> flow_last_activity;
    std::map<FlowKey, size_t> flow_last_pushed_count; // Track last pushed packet count per flow

    // legacy code for device tracking
    // ===================================================
    // Initialize empty queues for all monitored devices
    // for (const auto &dev : devices_in_group)
    // {
    //     device_packets[dev.mac] = {};
    //     last_packet_time[dev.mac] = 0;
    // }
    // ===================================================

    // Time tracking
    const uint64_t check_interval = static_cast<uint64_t>(aggregation_T * 1'000'000); // µs
    uint64_t last_aggregation_check = now_us();

    while (running)
    {
        uint64_t current_time = now_us();

        // Try to pop packet
        Packet packet;
        if (current_queue.try_pop(packet, 100))
        {
            std::vector<uint8_t> &data = packet.data;
            char smac_buf[mac_buf_size], dmac_buf[mac_buf_size];

            std::snprintf(dmac_buf, sizeof(dmac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                          data[0], data[1], data[2], data[3], data[4], data[5]);
            std::snprintf(smac_buf, sizeof(smac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                          data[6], data[7], data[8], data[9], data[10], data[11]);

            std::string smac = smac_buf;
            std::string dmac = dmac_buf;

            bool smac_monitored = state.check_if_dev_monitored(smac);
            bool dmac_monitored = state.check_if_dev_monitored(dmac);

            // Add after MAC extraction:
            FlowKey flow_key;
            if (extract_flow_key_from_packet(packet, flow_key))
            {
                // Group packet by flow key instead of MAC
                flow_packets[flow_key].push_back(packet);
                if (flow_start_time.find(flow_key) == flow_start_time.end())
                {
                    flow_start_time[flow_key] = packet.timestamp;
                }
                flow_last_activity[flow_key] = packet.timestamp;
            }
        }

        // Check for flow completion periodically
        if (current_time - last_aggregation_check >= check_interval)
        {
            for (auto it = flow_packets.begin(); it != flow_packets.end();)
            {
                auto &[flow_key, packets] = *it;
                if (!packets.empty())
                {
                    // Check if flow is complete
                    if (is_flow_complete(flow_key, packets, current_time, flow_start_time, flow_last_activity))
                    {
                        // Only push complete flows for feature extraction
                        flows_queues[group_id].push(packets);

                        // Update statistics
                        state.set_total_processed_flows_count(group_id, state.get_total_processed_flows_count(group_id).value_or(0) + 1);
                        state.increment_flow_count_group(group_id, 1);

                        // Extract MACs from the first packet for device tracking
                        const auto &first_packet = packets[0];
                        const std::vector<uint8_t> &data = first_packet.data;

                        char smac_buf[mac_buf_size];
                        std::snprintf(smac_buf, sizeof(smac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                                      data[6], data[7], data[8], data[9], data[10], data[11]);
                        std::string smac = smac_buf;

                        char dmac_buf[mac_buf_size];
                        std::snprintf(dmac_buf, sizeof(dmac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                                      data[0], data[1], data[2], data[3], data[4], data[5]);
                        std::string dmac = dmac_buf;

                        bool smac_monitored = state.check_if_dev_monitored(smac);
                        bool dmac_monitored = state.check_if_dev_monitored(dmac);

                        // Update per-device processed flows tracking for monitored devices
                        if (smac_monitored)
                        {
                            state.increment_processed_flows_device(group_id, smac, 1);
                        }
                        if (dmac_monitored)
                        {
                            state.increment_processed_flows_device(group_id, dmac, 1);
                        }

                        // Clean up completed flow
                        flow_start_time.erase(flow_key);
                        flow_last_activity.erase(flow_key);
                        flow_last_pushed_count.erase(flow_key);
                        it = flow_packets.erase(it); // Safe erase and advance
                    }
                    else
                    {
                        ++it;
                    }
                }
                else
                {
                    ++it;
                }
            }
            last_aggregation_check = current_time;
        }
    }

    LOG_THREAD_WARNING("FlowAggregation-" + std::to_string(group_id), "Flow", "Flow aggregation thread exiting");
}

void feature_extraction_thread(int group_id, State &state)
{
    LOG_THREAD_INFO("FeatureExtract-" + std::to_string(group_id), "Features", "Feature extraction thread started");
    try
    {

        FlowFeaturesQueue &features_queue = features_queues[group_id];

        // Use a directory accessible to the regular user
        std::string output_dir = "./output";
        std::string csv_path = output_dir + "/features_group_" + std::to_string(group_id) + ".csv";

        // Ensure output directory exists
        if (!std::filesystem::exists(output_dir))
        {
            std::filesystem::create_directory(output_dir);
            // Make directory accessible to all users
            std::filesystem::permissions(output_dir,
                                         std::filesystem::perms::owner_all |
                                             std::filesystem::perms::group_all |
                                             std::filesystem::perms::others_all);
        }

        // Open file once to write header if needed
        {
            std::ofstream header_check(csv_path, std::ios::app);
            if (!header_check.is_open())
            {
                throw std::runtime_error("Failed to open CSV file for group " + std::to_string(group_id) + " at " + csv_path);
            }

            // Make file accessible to all users
            std::filesystem::permissions(csv_path,
                                         std::filesystem::perms::owner_all |
                                             std::filesystem::perms::group_all |
                                             std::filesystem::perms::others_all);

            // Write CSV header if file is empty
            header_check.seekp(0, std::ios::end);
            if (header_check.tellp() == 0)
            {
                header_check
                    << "Covariance,"
                       "AVG,"
                       "IAT,"
                       "Srate,"
                       "fin_count,fin_flag_number,"
                       "syn_count,syn_flag_number,"
                       "rst_count,rst_flag_number,"
                       "psh_count,psh_flag_number,"
                       "ack_count,ack_flag_number,"
                       "ece_count,ece_flag_number,"
                       "cwr_count,cwr_flag_number,"
                       "HTTP,HTTPS,SMTP,TCP,UDP,ICMP,LLC\n";
            }
            header_check.close();
        }

        FlowPacketsQueue &current_queue = flows_queues[group_id];
        int processed_flows = 0;

        while (running)
        {
            std::vector<Packet> flow_packets;

            // Try to get packets from the queue with a timeout to prevent busy waiting
            if (current_queue.try_pop(flow_packets, 100))
            {
                if (flow_packets.size() > 1)
                {
                    char mac_buffer_check[mac_buf_size];
                    std::string mac_check;
                    // Extract MAC addresses
                    // ? checking the source of the first packet to determine the source of the current flow
                    std::snprintf(mac_buffer_check, sizeof(mac_buffer_check), "%02x:%02x:%02x:%02x:%02x:%02x",
                                  flow_packets.front().data[6], flow_packets.front().data[7], flow_packets.front().data[8],
                                  flow_packets.front().data[9], flow_packets.front().data[10], flow_packets.front().data[11]);

                    mac_check = mac_buffer_check;

                    if (!state.check_if_dev_monitored(mac_check))
                    {
                        std::snprintf(mac_buffer_check, sizeof(mac_buffer_check), "%02x:%02x:%02x:%02x:%02x:%02x",
                                      flow_packets.front().data[0], flow_packets.front().data[1], flow_packets.front().data[2],
                                      flow_packets.front().data[3], flow_packets.front().data[4], flow_packets.front().data[5]);

                        mac_check = mac_buffer_check;
                        if (!state.check_if_dev_monitored(mac_check))
                            return;
                    }

                    // Open the file for each batch of writing to avoid keeping it open continuously
                    std::ofstream csv_file(csv_path, std::ios::app);
                    if (!csv_file.is_open())
                    {
                        throw std::runtime_error("Failed to open CSV file for group " + std::to_string(group_id) + " at " + csv_path);
                    }

                    FlowFeatures flow_features;

                    // Debug: Log that a flow is being processed
                    // std::cout << debug << "Group " << group_id << ": Processing flow with " << flow_packets.size() << " packets." << reset << "\n";

                    flow_features.Number = flow_packets.size();

                    double duration_seconds = (flow_packets.back().timestamp - flow_packets.front().timestamp) / 1e6;
                    flow_features.Duration = duration_seconds > 0 ? duration_seconds : epsilon; // Prevent division by zero
                    flow_features.Rate = flow_features.Number / flow_features.Duration;

                    char source_mac_buffer[mac_buf_size];
                    std::string source_mac;
                    // Extract MAC addresses
                    // ? checking the source of the first packet to determine the source of the current flow
                    std::snprintf(source_mac_buffer, sizeof(source_mac_buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
                                  flow_packets.front().data[6], flow_packets.front().data[7], flow_packets.front().data[8],
                                  flow_packets.front().data[9], flow_packets.front().data[10], flow_packets.front().data[11]);

                    source_mac = source_mac_buffer;

                    int src_count = 0, total_pkts_length = 0;

                    int fin = 0;
                    int syn = 0;
                    int rst = 0;
                    int psh = 0;
                    int ack = 0;
                    int ece = 0;
                    int cwr = 0;

                    int http_count = 0, https_count = 0, tcp_count = 0, udp_count = 0, smtp_count = 0, icmp_count = 0, llc_count = 0;

                    double iat_sum = 0.0;
                    double sum_length_iat = 0.0;

                    int64_t previous_timestamp = -1;

                    double sum_lenghts_sq = 0;

                    for (auto &pkt : flow_packets)
                    {
                        // Validate packet size
                        if (pkt.data.size() < 14)
                        { // Minimum Ethernet header size
                            continue;
                        }

                        if (previous_timestamp < 0)
                        {
                            previous_timestamp = pkt.timestamp;
                        }
                        else
                        {
                            // Calculate inter-arrival time in seconds
                            double current_iat = (pkt.timestamp - previous_timestamp) / 1e6;
                            iat_sum += current_iat;
                            sum_length_iat += pkt.data.size() * current_iat;
                            previous_timestamp = pkt.timestamp;
                        }

                        // Ensure we have enough bytes for the Ethernet type
                        if (pkt.data.size() >= 14)
                        {
                            uint16_t ethernet_type = (pkt.data[12] << 8) | pkt.data[13];

                            // Extract MAC addresses
                            char mac_buf[mac_buf_size];
                            std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                                          pkt.data[6], pkt.data[7], pkt.data[8], pkt.data[9], pkt.data[10], pkt.data[11]);

                            std::string src_mac = mac_buf;

                            if (src_mac == source_mac)
                                src_count++;

                            total_pkts_length += pkt.data.size();
                            sum_lenghts_sq += pkt.data.size() * pkt.data.size();

                            if (ethernet_type < 0x0600)
                            { // LLC frame
                                llc_count++;
                            }
                            else
                            {
                                switch (ethernet_type)
                                {
                                case 0x0800: //? IPv4 packet
                                {
                                    // Ensure we have enough bytes for the IP header
                                    if (pkt.data.size() < ip_begin + 1)
                                        break;

                                    // uint8_t ip_version = pkt.data[ip_begin] >> 4;
                                    uint8_t header_len = (pkt.data[ip_begin] & 0x0F) * 4;

                                    // Validate header length
                                    if (header_len < 20 || pkt.data.size() < ip_begin + header_len)
                                        break;

                                    // Ensure we have enough bytes for the protocol field
                                    if (pkt.data.size() <= protocol_offset)
                                        break;

                                    uint8_t protocol = pkt.data[protocol_offset];

                                    switch (protocol)
                                    {
                                    case 6: // TCP
                                    {
                                        tcp_count++;

                                        size_t tcp_begin = ip_begin + header_len;

                                        // Ensure we have enough bytes for the TCP flags
                                        if (pkt.data.size() <= tcp_begin + 13)
                                            break;

                                        uint8_t flags = pkt.data[tcp_begin + 13];

                                        fin += (flags & 0x01) ? 1 : 0;
                                        syn += (flags & 0x02) ? 1 : 0;
                                        rst += (flags & 0x04) ? 1 : 0;
                                        psh += (flags & 0x08) ? 1 : 0;
                                        ack += (flags & 0x10) ? 1 : 0;
                                        ece += (flags & 0x40) ? 1 : 0;
                                        cwr += (flags & 0x80) ? 1 : 0;

                                        // Ensure we have enough bytes for the port fields
                                        if (pkt.data.size() <= tcp_begin + 3)
                                            break;

                                        uint16_t src_port = (pkt.data[tcp_begin] << 8) | pkt.data[tcp_begin + 1];
                                        uint16_t dst_port = (pkt.data[tcp_begin + 2] << 8) | pkt.data[tcp_begin + 3];

                                        if (src_port == 80 || dst_port == 80)
                                            http_count++;
                                        if (src_port == 25 || dst_port == 25)
                                            smtp_count++;
                                        if (src_port == 443 || dst_port == 443)
                                            https_count++;

                                        break;
                                    }

                                    case 17: // UDP
                                    {
                                        udp_count++;
                                        break;
                                    }

                                    case 1: // ICMP
                                    {
                                        icmp_count++;
                                        break;
                                    }
                                    default:
                                        break;
                                    }

                                    break;
                                }

                                default:
                                    break;
                                }
                            }
                        }
                    }

                    // Avoid division by zero for flows with only one packet
                    if (flow_features.Number <= 1)
                    {
                        flow_features.Covariance = 0.0;
                        flow_features.IAT = 0.0;
                    }
                    else
                    {
                        double sum_lengths_excl0 = total_pkts_length - flow_packets.front().data.size();
                        double avg_len = flow_features.Number > 1 ? sum_lengths_excl0 / (flow_features.Number - 1) : 0;
                        double avg_iat = flow_features.Number > 1 ? iat_sum / (flow_features.Number - 1) : 0;

                        flow_features.Covariance = flow_features.Number > 1 ? (sum_length_iat / (flow_features.Number - 1)) - (avg_len * avg_iat) : 0;
                        flow_features.IAT = flow_features.Number > 1 ? iat_sum / (flow_features.Number - 1) : 0;
                    }

                    flow_features.AVG = flow_features.Number > 0 ? total_pkts_length / flow_features.Number : 0;
                    flow_features.Srate = flow_features.Number > 0 ? static_cast<double>(src_count) / flow_features.Number : 0;

                    // Calculate flag percentages with safeguards against division by zero
                    double total_packets = flow_features.Number > 0 ? flow_features.Number : epsilon;

                    flow_features.fin_count = fin;
                    flow_features.fin_flag_number = (fin * 100.0) / total_packets;

                    flow_features.syn_count = syn;
                    flow_features.syn_flag_number = (syn * 100.0) / total_packets;

                    flow_features.rst_count = rst;
                    flow_features.rst_flag_number = (rst * 100.0) / total_packets;

                    flow_features.psh_count = psh;
                    flow_features.psh_flag_number = (psh * 100.0) / total_packets;

                    flow_features.ack_count = ack;
                    flow_features.ack_flag_number = (ack * 100.0) / total_packets;

                    flow_features.ece_count = ece;
                    flow_features.ece_flag_number = (ece * 100.0) / total_packets;

                    flow_features.cwr_count = cwr;
                    flow_features.cwr_flag_number = (cwr * 100.0) / total_packets;

                    flow_features.HTTP = total_packets > 0 ? http_count / total_packets : 0;
                    flow_features.HTTPS = total_packets > 0 ? https_count / total_packets : 0;
                    flow_features.SMTP = total_packets > 0 ? smtp_count / total_packets : 0;
                    flow_features.TCP = total_packets > 0 ? tcp_count / total_packets : 0;
                    flow_features.UDP = total_packets > 0 ? udp_count / total_packets : 0;
                    flow_features.ICMP = total_packets > 0 ? icmp_count / total_packets : 0;
                    flow_features.LLC = total_packets > 0 ? llc_count / total_packets : 0;

                    // pushing features to the features queue
                    features_queue.push(flow_features);
                    // Set precision for floating-point output
                    csv_file << std::fixed << std::setprecision(6);

                    csv_file
                        << flow_features.Covariance << ','
                        << flow_features.AVG << ','
                        << flow_features.IAT << ','
                        << flow_features.Srate << ','

                        << flow_features.fin_count << ','
                        << flow_features.fin_flag_number << ','
                        << flow_features.syn_count << ','
                        << flow_features.syn_flag_number << ','
                        << flow_features.rst_count << ','
                        << flow_features.rst_flag_number << ','
                        << flow_features.psh_count << ','
                        << flow_features.psh_flag_number << ','
                        << flow_features.ack_count << ','
                        << flow_features.ack_flag_number << ','
                        << flow_features.ece_count << ','
                        << flow_features.ece_flag_number << ','
                        << flow_features.cwr_count << ','
                        << flow_features.cwr_flag_number << ','

                        << flow_features.HTTP << ','
                        << flow_features.HTTPS << ','
                        << flow_features.SMTP << ','
                        << flow_features.TCP << ','
                        << flow_features.UDP << ','
                        << flow_features.ICMP << ','
                        << flow_features.LLC
                        << '\n';

                    csv_file.flush();
                    csv_file.close(); //  close the file after writing

                    processed_flows++;

                    std::cout << flow_features.Covariance << ','
                              << flow_features.AVG << ','
                              << flow_features.IAT << ','
                              << flow_features.Srate << ','

                              << flow_features.fin_count << ','
                              << flow_features.fin_flag_number << ','
                              << flow_features.syn_count << ','
                              << flow_features.syn_flag_number << ','
                              << flow_features.rst_count << ','
                              << flow_features.rst_flag_number << ','
                              << flow_features.psh_count << ','
                              << flow_features.psh_flag_number << ','
                              << flow_features.ack_count << ','
                              << flow_features.ack_flag_number << ','
                              << flow_features.ece_count << ','
                              << flow_features.ece_flag_number << ','
                              << flow_features.cwr_count << ','
                              << flow_features.cwr_flag_number << ','

                              << flow_features.HTTP << ','
                              << flow_features.HTTPS << ','
                              << flow_features.SMTP << ','
                              << flow_features.TCP << ','
                              << flow_features.UDP << ','
                              << flow_features.ICMP << ','
                              << flow_features.LLC << std::endl;

                    LOG_THREAD_INFO("FeatureExtract-" + std::to_string(group_id), "Features",
                                    "Processed flow with " + std::to_string(flow_features.Number) +
                                        " packets (Total flows: " + std::to_string(processed_flows) + ")");
                }
            }
            else
            {
                // If no data is available, sleep a little to prevent CPU overuse
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    catch (const std::exception &e)
    {
        LOG_THREAD_ERROR("FeatureExtract-" + std::to_string(group_id), "Features",
                         "Feature extraction error: " + std::string(e.what()));
    }

    LOG_THREAD_WARNING("FeatureExtract-" + std::to_string(group_id), "Features",
                       "Feature extraction thread exiting");
}
/*
 ? protocol problem was not a problem, I was capturing arp packets by mistake
 ? and those packets have different structure than ipv4, therefor the offsets were not correct
 ? packet count was a due to the fact that flows were identified by a key containing the src and dst ip
 ? solved by normalizing the flow key, using the smaller ip as the source
 ? silence time problem: the ckeck was done only when a new packet arrives, solved by changing the logic
*/

void inference_thread(int number_of_groups, State &state)
{
    LOG_THREAD_INFO("Inference", "Inference", "Inference thread started");

    // Get API endpoint from environment variable (loaded from .env file in main)
    const char *api_endpoint_env = std::getenv("INFERENCE_API_URL");
    if (!api_endpoint_env)
    {
        LOG_THREAD_ERROR("Inference", "Inference", "API_ENDPOINT environment variable not set");
        return;
    }
    std::string api_endpoint(api_endpoint_env);

    // Initialize curl
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        LOG_THREAD_ERROR("Inference", "Inference", "Failed to initialize curl");
        return;
    }

    // Send inference reauest
    try
    {
        FlowFeatures features;
        while (running)
        {
            bool any_pop = false;
            for (int group_id = 0; group_id < number_of_groups; group_id++)
            {
                if (features_queues[group_id].try_pop(features, 0))
                {
                    any_pop = true;

                    // Get device information from the current group
                    std::string device_ip;
                    std::string device_name = "unknown";
                    std::string device_mac;

                    // Since we can't directly extract IP from FlowFeatures, we need to find
                    // the device from the group. For production, we'll use the first device
                    // in the current group as a representative, or implement a better mapping.

                    if (group_id < groups.size() && !groups[group_id].empty())
                    {
                        // Get the first active device from this group
                        for (const auto &device : groups[group_id])
                        {
                            if (!device.ip.empty() && !device.name.empty())
                            {
                                device_ip = device.ip;
                                device_name = device.name;
                                device_mac = device.mac;
                                break;
                            }
                        }
                    }

                    // Fallback: use monitored devices if group lookup fails
                    if (device_name == "unknown")
                    {
                        auto monitored_devices = state.get_monitored_devices();
                        if (!monitored_devices.empty())
                        {
                            // Find a device from the current group
                            for (const auto &device : monitored_devices)
                            {
                                if (device.group == group_id)
                                {
                                    device_ip = device.ip;
                                    device_name = device.name;
                                    device_mac = device.mac;
                                    break;
                                }
                            }

                            // If still not found, use the first available device
                            if (device_name == "unknown" && !monitored_devices.empty())
                            {
                                device_ip = monitored_devices[0].ip;
                                device_name = monitored_devices[0].name;
                                device_mac = monitored_devices[0].mac;
                            }
                        }
                    }

                    // Generate device name from group if still unknown
                    if (device_name == "unknown")
                    {
                        device_name = "group_" + std::to_string(group_id) + "_device";
                        device_ip = "0.0.0.0"; // Placeholder
                    }

                    // Create JSON payload with all actual feature values
                    json json_payload = {
                        {"device", device_ip},
                        {"device_name", device_name},
                        {"device_mac", device_mac},
                        {"group_id", group_id},
                        {"features", {{"ARP", features.ARP}, {"AVG", features.AVG}, {"Covariance", features.Covariance}, {"DHCP", features.DHCP}, {"DNS", features.DNS}, {"Duration", features.Duration}, {"HTTP", features.HTTP}, {"HTTPS", features.HTTPS}, {"Header_Length", features.Header_Length}, {"IAT", features.IAT}, {"ICMP", features.ICMP}, {"IGMP", features.IGMP}, {"IPv", features.IPv}, {"IRC", features.IRC}, {"LLC", features.LLC}, {"Magnitue", features.Magnitue}, {"Max", features.Max}, {"Min", features.Min}, {"Number", features.Number}, {"Protocol_Type", features.Protocol_Type}, {"Radius", features.Radius}, {"Rate", features.Rate}, {"SMTP", features.SMTP}, {"SSH", features.SSH}, {"Srate", features.Srate}, {"Std", features.Std}, {"TCP", features.TCP}, {"Telnet", features.Telnet}, {"Tot_size", features.Tot_size}, {"Tot_sum", features.Tot_sum}, {"UDP", features.UDP}, {"Variance", features.Variance}, {"Weight", features.Weight}, {"ack_count", features.ack_count}, {"ack_flag_number", features.ack_flag_number}, {"byte_count", features.byte_count}, {"cwr_count", features.cwr_count}, {"cwr_flag_number", features.cwr_flag_number}, {"ece_count", features.ece_count}, {"ece_flag_number", features.ece_flag_number}, {"fin_count", features.fin_count}, {"fin_flag_number", features.fin_flag_number}, {"is_arp", features.is_arp ? 1.0 : 0.0}, {"is_ipv", features.is_ipv ? 1.0 : 0.0}, {"is_llc", features.is_llc ? 1.0 : 0.0}, {"psh_count", features.psh_count}, {"psh_flag_number", features.psh_flag_number}, {"rst_count", features.rst_count}, {"rst_flag_number", features.rst_flag_number}, {"syn_count", features.syn_count}, {"syn_flag_number", features.syn_flag_number}}}};

                    std::string json_string = json_payload.dump();

                    // Configure curl for HTTP POST
                    curl_easy_setopt(curl, CURLOPT_URL, api_endpoint.c_str());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string.c_str());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_string.length());
                    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
                    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
                    curl_easy_setopt(curl, CURLOPT_USERAGENT, "IoMT-IDS/1.0");
                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // For testing
                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // For testing

                    // Set headers
                    struct curl_slist *headers = nullptr;
                    headers = curl_slist_append(headers, "Content-Type: application/json");
                    headers = curl_slist_append(headers, "Accept: application/json");
                    headers = curl_slist_append(headers, "Source: 0");
                    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                    // Perform the request
                    CURLcode res = curl_easy_perform(curl);

                    if (res != CURLE_OK)
                    {
                        LOG_THREAD_ERROR("Inference", "Inference",
                                         "Failed to send features to API: " + std::string(curl_easy_strerror(res)));
                    }
                    else
                    {
                        long response_code;
                        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                        if (response_code >= 400)
                        {
                            LOG_THREAD_ERROR("Inference", "Inference",
                                             "API returned error code: " + std::to_string(response_code));
                        }
                        else
                        {
                            LOG_THREAD_DEBUG("Inference", "Inference",
                                             "Successfully sent features for device: " + device_name + " (" + device_ip + ")");
                        }
                    }

                    curl_slist_free_all(headers);
                }
            }

            if (!any_pop)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    catch (const std::exception &e)
    {
        LOG_THREAD_ERROR("Inference", "Inference", "Inference thread error: " + std::string(e.what()));
    }

    curl_easy_cleanup(curl);
    LOG_THREAD_WARNING("Inference", "Inference", "Inference thread exiting");
}

void create_shm(const std::string &shm_name, const std::string &filename)
{
    // Try to open (or create) the shared memory
    int fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR, 0666);
    if (fd == -1)
    {
        perror("shm_open");
        exit(1);
    }

    // Check if the shared memory already has the correct size
    struct stat shm_stat;
    if (fstat(fd, &shm_stat) == -1)
    {
        perror("fstat");
        close(fd);
        exit(1);
    }

    if (shm_stat.st_size != SHM_SIZE)
    {
        // Only resize if the size is incorrect
        if (ftruncate(fd, SHM_SIZE) == -1)
        {
            perror("ftruncate");
            close(fd);
            exit(1);
        }
    }

    fchmod(fd, 0666); // Set permissions to allow read/write for all users

    close(fd);

    // Save the name to a file (one per line)
    std::ofstream ofs(filename, std::ios::trunc);
    if (!ofs)
    {
        std::cerr << "Failed to open output file: " << filename << std::endl;
        running = false;
    }

    ofs << shm_name << "\n";
    ofs.close();
}

// void write_to_shm(const std::string &shm_name, const FeaturesSHMWrapper &payload)
// {
//     int fd = shm_open(shm_name.c_str(), O_RDWR, 0666);
//     if (fd == -1)
//     {
//         perror("shm_open (write)");
//         exit(1);
//     }

//     void *ptr = mmap(nullptr, SHM_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
//     if (ptr == MAP_FAILED)
//     {
//         perror("mmap");
//         close(fd);
//         exit(1);
//     }

//     std::memcpy(ptr, &payload, sizeof(FeaturesSHMWrapper));
//     munmap(ptr, SHM_SIZE);
//     close(fd);
// }

void logger_thread(State &state)
{
    LOG_THREAD_INFO("Logger", "Logger", "Logger thread started");

    std::string output_dir = "./resources";
    std::filesystem::create_directories(output_dir);
    std::string filename = output_dir + "/global_log.log";
    double refresh_rate = 0.1; // seconds

    try
    {
        // Launch xterm to live-monitor the log file
        std::string command = "xterm -e 'while true; do clear; cat " + filename + "; sleep " + std::to_string(refresh_rate) + "; done' &";
        int result = system(command.c_str());
        if (result != 0)
        {
            LOG_THREAD_WARNING("Logger", "Logger",
                               "Failed to launch xterm (error: " + std::string(strerror(errno)) +
                                   "), continuing with file logging only");
        }

        while (running)
        { // Generate the current snapshot of system state
            std::string details = state.get_all_details(false);
            LOG_THREAD_DEBUG("Logger", "Logger", "Generated log length: " + std::to_string(details.length()));
            LOG_THREAD_DEBUG("Logger", "Logger", "Groups: " + std::to_string(state.groups_.size()) + " | Monitored devices: " + std::to_string(state.monitored_devices.size()));

            // Open, write, and close log file in one step
            std::ofstream outfile(filename, std::ios::trunc);
            state.dashboard_live_stats(); // Send live stats to the dashboard
            if (!outfile)
            {
                LOG_THREAD_ERROR("Logger", "Logger", "Unable to open " + filename + " for writing");
            }
            else
            {
                outfile << details;
                outfile.close();
            }

            LOG_THREAD_DEBUG("Logger", "Logger", "Loop iteration done. Running: " + std::string(running ? "true" : "false"));

            // Sleep between updates
            std::this_thread::sleep_for(std::chrono::milliseconds(2000)); // two seconds
        }
    }
    catch (const std::exception &e)
    {
        LOG_THREAD_ERROR("Logger", "Logger", "Logger thread exception: " + std::string(e.what()));
    }
    catch (...)
    {
        LOG_THREAD_FATAL("Logger", "Logger", "Logger thread encountered an unknown fatal error!");
    }

    LOG_THREAD_WARNING("Logger", "Logger", "Logger thread exiting");
}

// Utility: Load .env and set environment variables
void load_env_file(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        LOG_WARNING("Environment", "Could not open " + filename);
        return;
    }

    std::string line;
    while (std::getline(file, line))
    {
        // Skip empty lines or comments
        if (line.empty() || line[0] == '#')
            continue;

        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value))
        {
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            // Set the environment variable
            setenv(key.c_str(), value.c_str(), 1); // overwrite = true
        }
    }

    file.close();
}

void State::dashboard_live_stats() const
{
    const char *url = std::getenv("DASHBOARD_URL");
    if (!url)
    {
        LOG_ERROR("Dashboard", "DASHBOARD_URL environment variable not set");
        return;
    }

    // std::cout << info << "dashboard Url: " << url << "." << reset << std::endl;

    json stats = get_stats_as_json();
    std::string json_str = stats.dump();

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        LOG_ERROR("Dashboard", "Failed to initialize CURL");
        return;
    }

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_str.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        LOG_ERROR("Dashboard", "CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

// ----------------------------------------
// State Class Rate History Wrapper Methods
// ----------------------------------------

void State::add_device_rate_history(int16_t g, std::string_view mac, long double rate, uint64_t timestamp, uint64_t packet_count)
{
    GroupStats &S = get_or_create_group(g);
    S.add_rate_history_entry(mac, rate, timestamp, packet_count);
}

void State::update_group_rate_history(int16_t g, uint64_t timestamp)
{
    GroupStats &S = get_or_create_group(g);
    S.update_group_rate_history(timestamp);
}

std::vector<State::GroupStats::RateHistoryEntry> State::get_device_rate_history(int16_t g, std::string_view mac, size_t max_entries) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return {};
    }
    return it->second.get_rate_history(mac, max_entries);
}

std::vector<State::GroupStats::RateHistoryEntry> State::get_recent_device_rate_history(int16_t g, std::string_view mac, uint64_t time_window_us) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return {};
    }
    return it->second.get_recent_rate_history(mac, time_window_us);
}

std::vector<State::GroupStats::RateHistoryEntry> State::get_group_rate_history(int16_t g, size_t max_entries) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return {};
    }
    return it->second.get_group_rate_history(max_entries);
}

std::optional<State::GroupStats::RateStatistics> State::get_device_rate_statistics(int16_t g, std::string_view mac, uint64_t time_window_us) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return std::nullopt;
    }
    return it->second.calculate_rate_statistics(mac, time_window_us);
}

std::optional<State::GroupStats::RateStatistics> State::get_group_rate_statistics(int16_t g, uint64_t time_window_us) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return std::nullopt;
    }
    return it->second.calculate_group_rate_statistics(time_window_us);
}

void State::print_rate_history_summary(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        LOG_WARNING("State", "Group " + std::to_string(g) + " not found for rate history summary");
        return;
    }

    const GroupStats &stats = it->second;
    std::shared_lock<std::shared_mutex> group_lock(stats.mtx);

    LOG_INFO("RateHistory", "=== Rate History Summary for Group " + std::to_string(g) + " ===");

    // Show device-level rate statistics (last 5 minutes)
    for (const auto &[mac, current_rate] : stats.packet_rate_device)
    {
        auto device_stats = get_device_rate_statistics(g, mac, 300000000); // 5 minutes
        if (device_stats.has_value())
        {
            LOG_INFO("RateHistory", "Device " + mac + " (last 5min): " +
                                        "avg=" + std::to_string(device_stats->avg_rate) + " pps, " +
                                        "min=" + std::to_string(device_stats->min_rate) + " pps, " +
                                        "max=" + std::to_string(device_stats->max_rate) + " pps, " +
                                        "std=" + std::to_string(device_stats->std_deviation) + " pps, " +
                                        "samples=" + std::to_string(device_stats->sample_count));

            // Show recent rate trend (last 10 entries)
            auto recent_history = get_recent_device_rate_history(g, mac, 10000000); // 10 seconds
            if (!recent_history.empty())
            {
                std::string trend = "  Recent rates: ";
                size_t show_count = std::min(size_t(10), recent_history.size());
                for (size_t i = recent_history.size() - show_count; i < recent_history.size(); ++i)
                {
                    trend += std::to_string(recent_history[i].rate).substr(0, 5) + " ";
                }
                LOG_INFO("RateHistory", trend);
            }
        }
    }

    // Show group-level statistics
    auto group_stats = get_group_rate_statistics(g, 300000000); // 5 minutes
    if (group_stats.has_value())
    {
        LOG_INFO("RateHistory", std::string("Group average (last 5min): ") +
                                    "avg=" + std::to_string(group_stats->avg_rate) + " pps, " +
                                    "min=" + std::to_string(group_stats->min_rate) + " pps, " +
                                    "max=" + std::to_string(group_stats->max_rate) + " pps, " +
                                    "std=" + std::to_string(group_stats->std_deviation) + " pps, " +
                                    "samples=" + std::to_string(group_stats->sample_count));
    }

    LOG_INFO("RateHistory", "===============================================");
}

// ----------------------------------------
// Periodic History Saving Implementation
// ----------------------------------------

void history_saving_thread(State &state)
{
    LOG_THREAD_INFO("HistorySaver", "HistorySaver", "Periodic history saving thread started");
    LOG_INFO("HistorySaver", "Saving rate history every 60 seconds to local files");

    std::string output_dir = "./output/history";

    // Create directory if it doesn't exist
    try
    {
        std::filesystem::create_directories(output_dir);
        std::filesystem::permissions(output_dir,
                                     std::filesystem::perms::owner_all |
                                         std::filesystem::perms::group_all |
                                         std::filesystem::perms::others_all);
        LOG_INFO("HistorySaver", "History output directory created: " + output_dir);
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("HistorySaver", "Failed to create history directory: " + std::string(e.what()));
        return;
    }

    int save_counter = 0;

    while (running)
    {
        try
        {
            // Wait for 60 seconds (1 minute)
            std::this_thread::sleep_for(std::chrono::seconds(60));

            if (!running)
                break;

            save_counter++;

            // Generate timestamped filename
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::ostringstream oss;
            oss << output_dir << "/rate_history_"
                << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S")
                << "_save" << std::setfill('0') << std::setw(3) << save_counter;

            std::string base_filename = oss.str();
            save_rate_history_to_file(state, base_filename);

            LOG_THREAD_INFO("HistorySaver", "HistorySaver",
                            "Periodic save #" + std::to_string(save_counter) + " completed: " + base_filename + ".csv");
        }
        catch (const std::exception &e)
        {
            LOG_THREAD_ERROR("HistorySaver", "HistorySaver",
                             "Error during periodic save: " + std::string(e.what()));
        }
    }

    // Final save when shutting down
    try
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << output_dir << "/rate_history_final_"
            << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");

        save_rate_history_to_file(state, oss.str());
        LOG_THREAD_INFO("HistorySaver", "HistorySaver", "Final history save completed: " + oss.str() + ".csv");
    }
    catch (const std::exception &e)
    {
        LOG_THREAD_ERROR("HistorySaver", "HistorySaver",
                         "Error during final save: " + std::string(e.what()));
    }

    LOG_THREAD_WARNING("HistorySaver", "HistorySaver", "History saving thread exiting");
}

void save_rate_history_to_file(State &state, const std::string &base_filename)
{
    std::string filename = base_filename.empty() ? "rate_history_snapshot" : base_filename;
    filename += ".csv";

    std::ofstream csv_file(filename);
    if (!csv_file.is_open())
    {
        LOG_ERROR("HistorySaver", "Failed to open file for history save: " + filename);
        return;
    }

    // Write comprehensive CSV header
    csv_file << "Timestamp,UnixTimestamp_US,Group_ID,Device_MAC,Rate_PPS,Packet_Count,";
    csv_file << "Time_Since_Start_Sec,Session_ID,Save_Type\n";

    auto group_ids = state.get_all_group_ids();
    if (group_ids.empty())
    {
        csv_file.close();
        LOG_WARNING("HistorySaver", "No groups found for history save");
        return;
    }

    // Generate session ID based on current time
    auto now = std::chrono::system_clock::now();
    auto session_time = std::chrono::system_clock::to_time_t(now);
    std::string session_id = std::to_string(session_time);

    // Find the earliest timestamp across all devices to calculate relative times
    uint64_t start_time = std::numeric_limits<uint64_t>::max();
    int total_devices = 0;

    for (int16_t gid : group_ids)
    {
        auto packet_counts = state.get_packet_count_per_device(gid);
        if (!packet_counts)
            continue;

        for (const auto &[mac, count] : *packet_counts)
        {
            auto history = state.get_device_rate_history(gid, mac);
            if (!history.empty())
            {
                start_time = std::min(start_time, history.front().timestamp);
                total_devices++;
            }
        }
    }

    if (start_time == std::numeric_limits<uint64_t>::max())
    {
        csv_file.close();
        LOG_WARNING("HistorySaver", "No history data found for save");
        return;
    }

    // Write data for all groups and devices
    int exported_records = 0;

    for (int16_t gid : group_ids)
    {
        auto packet_counts = state.get_packet_count_per_device(gid);
        if (!packet_counts)
            continue;

        // Also save group-level history
        auto group_history = state.get_group_rate_history(gid);
        for (const auto &entry : group_history)
        {
            auto time_point = std::chrono::system_clock::time_point{
                std::chrono::microseconds{entry.timestamp}};
            auto time_t = std::chrono::system_clock::to_time_t(time_point);

            double seconds_since_start = (entry.timestamp - start_time) / 1000000.0;

            csv_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << ","
                     << entry.timestamp << ","
                     << gid << ","
                     << "GROUP_AVERAGE,"
                     << std::fixed << std::setprecision(6) << entry.rate << ","
                     << entry.packet_count << ","
                     << std::setprecision(3) << seconds_since_start << ","
                     << session_id << ","
                     << "PERIODIC\n";
            exported_records++;
        }

        // Save per-device history
        for (const auto &[mac, count] : *packet_counts)
        {
            auto history = state.get_device_rate_history(gid, mac);

            for (const auto &entry : history)
            {
                auto time_point = std::chrono::system_clock::time_point{
                    std::chrono::microseconds{entry.timestamp}};
                auto time_t = std::chrono::system_clock::to_time_t(time_point);

                double seconds_since_start = (entry.timestamp - start_time) / 1000000.0;

                csv_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << ","
                         << entry.timestamp << ","
                         << gid << ","
                         << mac << ","
                         << std::fixed << std::setprecision(6) << entry.rate << ","
                         << entry.packet_count << ","
                         << std::setprecision(3) << seconds_since_start << ","
                         << session_id << ","
                         << "PERIODIC\n";
                exported_records++;
            }
        }
    }

    csv_file.close();

    // Create a summary info file alongside the CSV
    std::string info_filename = base_filename + "_info.txt";
    std::ofstream info_file(info_filename);
    if (info_file.is_open())
    {
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        info_file << "Rate History Save Summary\n";
        info_file << "========================\n";
        info_file << "Save Time: " << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S") << "\n";
        info_file << "Session ID: " << session_id << "\n";
        info_file << "Total Records: " << exported_records << "\n";
        info_file << "Total Groups: " << group_ids.size() << "\n";
        info_file << "Total Devices: " << total_devices << "\n";
        info_file << "CSV File: " << filename << "\n";
        time_t start_time_t = static_cast<time_t>(start_time / 1000000); // Convert microseconds to seconds
        info_file << "Start Time: " << std::put_time(std::localtime(&start_time_t), "%Y-%m-%d %H:%M:%S") << "\n";

        // Add current statistics
        info_file << "\nCurrent Statistics:\n";
        for (int16_t gid : group_ids)
        {
            auto total_packets = state.get_total_packets_count(gid);
            auto total_flows = state.get_total_flows_count(gid);
            info_file << "Group " << gid << ": "
                      << (total_packets ? *total_packets : 0) << " packets, "
                      << (total_flows ? *total_flows : 0) << " flows\n";
        }
        info_file.close();
    }

    LOG_DEBUG("HistorySaver", "History saved: " + std::to_string(exported_records) +
                                  " records across " + std::to_string(group_ids.size()) + " groups");
}

// ----------------------------------------
// Interactive Command Interface Implementation
// ----------------------------------------

void interactive_command_thread(State &state)
{
    LOG_THREAD_INFO("Interactive", "Commands", "Interactive command interface started");

    try
    {
        // Create a named pipe for communication between the main process and the interactive terminal
        std::string pipe_path = "/tmp/iomt_ids_commands";
        std::string response_pipe_path = "/tmp/iomt_ids_responses";

        // Remove existing pipes if they exist
        unlink(pipe_path.c_str());
        unlink(response_pipe_path.c_str());

        // Create named pipes
        if (mkfifo(pipe_path.c_str(), 0666) != 0)
        {
            LOG_THREAD_ERROR("Interactive", "Commands", "Failed to create command pipe: " + std::string(strerror(errno)));
            return;
        }

        if (mkfifo(response_pipe_path.c_str(), 0666) != 0)
        {
            LOG_THREAD_ERROR("Interactive", "Commands", "Failed to create response pipe: " + std::string(strerror(errno)));
            unlink(pipe_path.c_str());
            return;
        }

        // Create the interactive script
        std::string script_path = "/tmp/iomt_ids_interactive.sh";
        std::ofstream script_file(script_path);
        script_file << "#!/bin/bash\n";
        script_file << "echo '======================================'\n";
        script_file << "echo 'IoMT-IDS Rate History Viewer Started'\n";
        script_file << "echo 'Type help for available commands'\n";
        script_file << "echo '======================================'\n";
        script_file << "while true; do\n";
        script_file << "  echo -n 'IoMT-IDS> '\n";
        script_file << "  read command\n";
        script_file << "  if [ \"$command\" = \"quit\" ] || [ \"$command\" = \"q\" ] || [ \"$command\" = \"exit\" ]; then\n";
        script_file << "    echo \"$command\" > " << pipe_path << "\n";
        script_file << "    echo 'Shutting down interactive interface...'\n";
        script_file << "    break\n";
        script_file << "  elif [ -n \"$command\" ]; then\n";
        script_file << "    echo \"$command\" > " << pipe_path << "\n";
        script_file << "    cat " << response_pipe_path << "\n";
        script_file << "  fi\n";
        script_file << "done\n";
        script_file.close();

        // Make script executable
        chmod(script_path.c_str(), 0755);

        // Launch xterm with the interactive script
        std::string terminal_command = "xterm -title 'IoMT-IDS Interactive Interface' -geometry 120x40 -e '" + script_path + "' &";
        int result = system(terminal_command.c_str());
        if (result != 0)
        {
            LOG_THREAD_WARNING("Interactive", "Commands",
                               "Failed to launch xterm (error: " + std::string(strerror(errno)) +
                                   "), falling back to console mode");
            // Fallback: run in current terminal
            interactive_console_mode(state);
            return;
        }

        LOG_THREAD_INFO("Interactive", "Commands", "Interactive terminal launched successfully");

        // Main command processing loop
        while (running)
        {
            // Open command pipe for reading (blocking)
            std::ifstream cmd_pipe(pipe_path);
            if (!cmd_pipe.is_open())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            std::string command;
            if (std::getline(cmd_pipe, command))
            {
                cmd_pipe.close();

                // Trim whitespace
                command = trim(command);

                if (command.empty())
                {
                    continue;
                }

                // Process command and generate response
                std::string response = process_interactive_command(state, command);

                // Send response back
                std::ofstream resp_pipe(response_pipe_path);
                if (resp_pipe.is_open())
                {
                    resp_pipe << response << std::endl;
                    resp_pipe.close();
                }

                // Check for quit command
                if (command == "quit" || command == "q" || command == "exit")
                {
                    LOG_INFO("Interactive", "Shutting down interactive interface...");
                    running = false;
                    break;
                }
            }
            else
            {
                cmd_pipe.close();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        // Cleanup
        unlink(pipe_path.c_str());
        unlink(response_pipe_path.c_str());
        unlink(script_path.c_str());
    }
    catch (const std::exception &e)
    {
        LOG_THREAD_ERROR("Interactive", "Commands", "Interactive command thread error: " + std::string(e.what()));
    }

    LOG_THREAD_WARNING("Interactive", "Commands", "Interactive command interface exiting");
}

// Helper function for processing commands and generating responses
std::string process_interactive_command(State &state, const std::string &command)
{
    std::ostringstream response;

    try
    {
        if (command == "help" || command == "h")
        {
            response << "\n=== IoMT-IDS Rate History Viewer Commands ===\n";
            response << "General Commands:\n";
            response << "  help, h                    - Show this help menu\n";
            response << "  quit, q, exit             - Exit the application\n\n";

            response << "Overview Commands:\n";
            response << "  overview, o               - Show group overview with current stats\n";
            response << "  summary, s                - Show rate history summary for all groups\n";
            response << "  summary <group_id>        - Show rate history summary for specific group\n\n";

            response << "Device Analysis:\n";
            response << "  device <group_id> <mac>   - Show detailed rate statistics for device\n";
            response << "  trends, t                 - Show recent rate trends (last 60 seconds)\n";
            response << "  trends <group_id>         - Show trends for specific group\n";
            response << "  trends <group_id> <sec>   - Show trends for group over <sec> seconds\n\n";

            response << "Export Commands:\n";
            response << "  export, e                 - Export rate history to CSV\n";
            response << "  export <filename>         - Export to specific filename\n\n";

            response << "Examples:\n";
            response << "  summary 0                 - Show rate history for group 0\n";
            response << "  device 0 aa:bb:cc:dd:ee:ff - Show stats for specific device\n";
            response << "  trends 0 120              - Show 2-minute trends for group 0\n";
            response << "  export rates_today.csv    - Export to custom filename\n";
            response << "=============================================\n";
        }
        else if (command == "summary" || command == "s")
        {
            auto group_ids = state.get_all_group_ids();
            for (int16_t gid : group_ids)
            {
                response << "\n=== Rate History Summary - Group " << gid << " ===\n";
                // Capture print_rate_history_summary output
                std::ostringstream summary_stream;
                auto old_buf = std::cout.rdbuf(summary_stream.rdbuf());
                state.print_rate_history_summary(gid);
                std::cout.rdbuf(old_buf);
                response << summary_stream.str();
            }
        }
        else if (command.substr(0, 8) == "summary ")
        {
            int group_id = std::stoi(command.substr(8));
            response << "\n=== Rate History Summary - Group " << group_id << " ===\n";
            std::ostringstream summary_stream;
            auto old_buf = std::cout.rdbuf(summary_stream.rdbuf());
            state.print_rate_history_summary(static_cast<int16_t>(group_id));
            std::cout.rdbuf(old_buf);
            response << summary_stream.str();
        }
        else if (command == "overview" || command == "o")
        {
            response << generate_group_overview(state);
        }
        else if (command.substr(0, 6) == "device")
        {
            std::istringstream iss(command);
            std::string cmd, group_str, mac;
            iss >> cmd >> group_str >> mac;
            if (!group_str.empty() && !mac.empty())
            {
                int group_id = std::stoi(group_str);
                response << generate_device_rate_details(state, group_id, mac);
            }
            else
            {
                response << "Usage: device <group_id> <mac_address>\n";
            }
        }
        else if (command == "trends" || command == "t")
        {
            response << generate_recent_rate_trends(state, -1, 60);
        }
        else if (command.substr(0, 7) == "trends ")
        {
            std::istringstream iss(command);
            std::string cmd, group_str, seconds_str;
            iss >> cmd >> group_str >> seconds_str;

            int group_id = -1;
            int seconds = 60;

            if (!group_str.empty())
            {
                group_id = std::stoi(group_str);
            }
            if (!seconds_str.empty())
            {
                seconds = std::stoi(seconds_str);
            }

            response << generate_recent_rate_trends(state, group_id, seconds);
        }
        else if (command == "export" || command == "e")
        {
            response << generate_export_csv(state, -1, "rate_history_export.csv");
        }
        else if (command.substr(0, 7) == "export ")
        {
            std::string filename = command.substr(7);
            response << generate_export_csv(state, -1, filename);
        }
        else
        {
            response << "Unknown command: '" << command << "'. Type 'help' for available commands.\n";
        }
    }
    catch (const std::exception &e)
    {
        response << "Command error: " << e.what() << "\n";
    }

    return response.str();
}

// Fallback console mode function
void interactive_console_mode(State &state)
{
    std::cout << "======================================\n";
    std::cout << "IoMT-IDS Rate History Viewer Started\n";
    std::cout << "Type 'help' for available commands\n";
    std::cout << "======================================\n";

    std::string command;

    while (running)
    {
        std::cout << "\nIoMT-IDS> ";
        std::cout.flush();

        if (!std::getline(std::cin, command))
        {
            break;
        }

        command = trim(command);

        if (command.empty())
        {
            continue;
        }

        if (command == "quit" || command == "q" || command == "exit")
        {
            std::cout << "Shutting down interactive interface...\n";
            running = false;
            break;
        }

        std::string response = process_interactive_command(state, command);
        std::cout << response;
    }
}

// Generate functions for different displays
std::string generate_group_overview(State &state)
{
    std::ostringstream response;
    response << "\n=== Group Overview ===\n";

    auto group_ids = state.get_all_group_ids();
    if (group_ids.empty())
    {
        response << "No groups found.\n";
        return response.str();
    }

    for (int16_t group_id : group_ids)
    {
        auto total_packets = state.get_total_packets_count(group_id);
        auto total_flows = state.get_total_flows_count(group_id);
        auto avg_window = state.get_average_window_size(group_id);

        response << "\nGroup " << group_id << ":\n";
        response << "  Total Packets: " << (total_packets ? *total_packets : 0) << "\n";
        response << "  Total Flows: " << (total_flows ? *total_flows : 0) << "\n";
        response << "  Avg Window Size: " << (avg_window ? *avg_window : 0.0) << "\n";

        auto packet_counts = state.get_packet_count_per_device(group_id);
        if (packet_counts)
        {
            response << "  Active Devices: " << packet_counts->size() << "\n";
            response << "  Device Rates:\n";

            for (const auto &[mac, count] : *packet_counts)
            {
                auto rate = state.get_packet_rate_device(group_id, mac);
                response << "    " << mac << ": "
                         << (rate ? std::to_string(*rate) : "0.0") << " pps\n";
            }
        }
    }
    response << "======================\n";
    return response.str();
}

std::string generate_device_rate_details(State &state, int group_id, const std::string &mac)
{
    std::ostringstream response;
    response << "\n=== Device Rate Details ===\n";
    response << "Group: " << group_id << "\n";
    response << "MAC: " << mac << "\n\n";

    auto current_rate = state.get_packet_rate_device(static_cast<int16_t>(group_id), mac);
    response << "Current Rate: " << (current_rate ? std::to_string(*current_rate) : "0.0") << " pps\n\n";

    std::vector<std::pair<std::string, uint64_t>> time_windows = {
        {"1 minute", 60000000},
        {"5 minutes", 300000000},
        {"15 minutes", 900000000},
        {"1 hour", 3600000000}};

    for (const auto &[window_name, window_us] : time_windows)
    {
        auto stats = state.get_device_rate_statistics(static_cast<int16_t>(group_id), mac, window_us);
        if (stats && stats->sample_count > 0)
        {
            response << "Statistics (" << window_name << "):\n";
            response << "  Average: " << std::fixed << std::setprecision(2) << stats->avg_rate << " pps\n";
            response << "  Min: " << stats->min_rate << " pps\n";
            response << "  Max: " << stats->max_rate << " pps\n";
            response << "  Std Dev: " << stats->std_deviation << " pps\n";
            response << "  Samples: " << stats->sample_count << "\n\n";
        }
        else
        {
            response << "Statistics (" << window_name << "): No data available\n\n";
        }
    }

    response << "===========================\n";
    return response.str();
}

std::string generate_recent_rate_trends(State &state, int group_id, int seconds)
{
    std::ostringstream response;
    uint64_t time_window_us = static_cast<uint64_t>(seconds) * 1000000;

    if (group_id == -1)
    {
        auto group_ids = state.get_all_group_ids();
        for (int16_t gid : group_ids)
        {
            response << "\n=== Rate Trends - Group " << gid << " (last " << seconds << " seconds) ===\n";

            auto group_stats = state.get_group_rate_statistics(gid, time_window_us);
            if (group_stats && group_stats->sample_count > 0)
            {
                response << "Group Average: " << std::fixed << std::setprecision(2)
                         << group_stats->avg_rate << " pps (±" << group_stats->std_deviation << ")\n";
                response << "Range: " << group_stats->min_rate << " - " << group_stats->max_rate << " pps\n\n";
            }

            auto packet_counts = state.get_packet_count_per_device(gid);
            if (packet_counts)
            {
                for (const auto &[mac, count] : *packet_counts)
                {
                    auto device_stats = state.get_device_rate_statistics(gid, mac, time_window_us);
                    if (device_stats && device_stats->sample_count > 0)
                    {
                        response << "Device " << mac << ": "
                                 << device_stats->avg_rate << " pps (±"
                                 << device_stats->std_deviation << ") ["
                                 << device_stats->sample_count << " samples]\n";
                    }
                }
            }
        }
    }
    else
    {
        response << "\n=== Rate Trends - Group " << group_id << " (last " << seconds << " seconds) ===\n";

        int16_t gid = static_cast<int16_t>(group_id);
        auto group_stats = state.get_group_rate_statistics(gid, time_window_us);
        if (group_stats && group_stats->sample_count > 0)
        {
            response << "Group Average: " << std::fixed << std::setprecision(2)
                     << group_stats->avg_rate << " pps (±" << group_stats->std_deviation << ")\n\n";
        }

        auto packet_counts = state.get_packet_count_per_device(gid);
        if (packet_counts)
        {
            for (const auto &[mac, count] : *packet_counts)
            {
                auto device_stats = state.get_device_rate_statistics(gid, mac, time_window_us);
                if (device_stats && device_stats->sample_count > 0)
                {
                    response << "Device " << mac << ": "
                             << device_stats->avg_rate << " pps (±"
                             << device_stats->std_deviation << ") ["
                             << device_stats->sample_count << " samples]\n";
                }
            }
        }
    }
    response << "=========================\n";
    return response.str();
}

std::string generate_export_csv(State &state, int group_id, const std::string &filename)
{
    std::ostringstream response;
    std::string output_file = filename;

    if (filename == "rate_history_export.csv")
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << "rate_history_export_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") << ".csv";
        output_file = oss.str();
    }

    std::ofstream csv_file(output_file);
    if (!csv_file.is_open())
    {
        response << "Error: Failed to open file for export: " << output_file << "\n";
        return response.str();
    }

    csv_file << "Timestamp,Group_ID,Device_MAC,Rate_PPS,Packet_Count,Time_Since_Start_Sec\n";

    auto group_ids = state.get_all_group_ids();
    uint64_t start_time = std::numeric_limits<uint64_t>::max();

    for (int16_t gid : group_ids)
    {
        if (group_id != -1 && gid != group_id)
            continue;

        auto packet_counts = state.get_packet_count_per_device(gid);
        if (!packet_counts)
            continue;

        for (const auto &[mac, count] : *packet_counts)
        {
            auto history = state.get_device_rate_history(gid, mac);
            if (!history.empty())
            {
                start_time = std::min(start_time, history.front().timestamp);
            }
        }
    }

    int exported_records = 0;
    for (int16_t gid : group_ids)
    {
        if (group_id != -1 && gid != group_id)
            continue;

        auto packet_counts = state.get_packet_count_per_device(gid);
        if (!packet_counts)
            continue;

        // Also save group-level history
        auto group_history = state.get_group_rate_history(gid);
        for (const auto &entry : group_history)
        {
            auto time_point = std::chrono::system_clock::time_point{
                std::chrono::microseconds{entry.timestamp}};
            auto time_t = std::chrono::system_clock::to_time_t(time_point);

            double seconds_since_start = (entry.timestamp - start_time) / 1000000.0;

            csv_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << ","
                     << entry.timestamp << ","
                     << gid << ","
                     << "GROUP_AVERAGE,"
                     << std::fixed << std::setprecision(6) << entry.rate << ","
                     << entry.packet_count << ","
                     << std::setprecision(3) << seconds_since_start << "\n";
            exported_records++;
        }

        // Save per-device history
        for (const auto &[mac, count] : *packet_counts)
        {
            auto history = state.get_device_rate_history(gid, mac);

            for (const auto &entry : history)
            {
                auto time_point = std::chrono::system_clock::time_point{
                    std::chrono::microseconds{entry.timestamp}};
                auto time_t = std::chrono::system_clock::to_time_t(time_point);

                double seconds_since_start = (entry.timestamp - start_time) / 1000000.0;

                csv_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << ","
                         << entry.timestamp << ","
                         << gid << ","
                         << mac << ","
                         << std::fixed << std::setprecision(6) << entry.rate << ","
                         << entry.packet_count << ","
                         << std::setprecision(3) << seconds_since_start << "\n";
                exported_records++;
            }
        }
    }

    csv_file.close();

    response << "Export completed successfully!\n";
    response << "Records exported: " << exported_records << "\n";
    response << "File: " << output_file << "\n";

    // Create a summary info file alongside the CSV
    std::string base_filename = output_file.substr(0, output_file.find_last_of('.'));
    std::string info_filename = base_filename + "_info.txt";
    std::ofstream info_file(info_filename);
    if (info_file.is_open())
    {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        auto session_time = std::chrono::system_clock::to_time_t(now);
        std::string session_id = std::to_string(session_time);

        // Count total devices
        int total_devices = 0;
        for (int16_t gid : group_ids)
        {
            if (group_id != -1 && gid != group_id)
                continue;
            auto packet_counts = state.get_packet_count_per_device(gid);
            if (packet_counts)
                total_devices += packet_counts->size();
        }

        info_file << "Rate History Export Summary\n";
        info_file << "===========================\n";
        info_file << "Export Time: " << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S") << "\n";
        info_file << "Session ID: " << session_id << "\n";
        info_file << "Total Records: " << exported_records << "\n";
        info_file << "Total Groups: " << group_ids.size() << "\n";
        info_file << "Total Devices: " << total_devices << "\n";
        info_file << "CSV File: " << output_file << "\n";
        time_t start_time_t = static_cast<time_t>(start_time / 1000000); // Convert microseconds to seconds
        info_file << "Start Time: " << std::put_time(std::localtime(&start_time_t), "%Y-%m-%d %H:%M:%S") << "\n";

        // Add current statistics
        info_file << "\nCurrent Statistics:\n";
        for (int16_t gid : group_ids)
        {
            auto total_packets = state.get_total_packets_count(gid);
            auto total_flows = state.get_total_flows_count(gid);
            info_file << "Group " << gid << ": "
                      << (total_packets ? *total_packets : 0) << " packets, "
                      << (total_flows ? *total_flows : 0) << " flows\n";
        }
        info_file.close();
    }

    LOG_DEBUG("HistorySaver", "History saved: " + std::to_string(exported_records) +
                                  " records across " + std::to_string(group_ids.size()) + " groups");

    return "done";
}

bool check_tcp_flow_completion(const std::vector<Packet> &packets)
{
    // Check for FIN or RST flags in recent packets
    if (packets.empty())
        return false;

    bool has_syn = false;
    bool has_syn_ack = false;
    bool has_ack = false;
    bool has_fin = false;
    bool has_rst = false;

    // Analyze all packets to understand the TCP flow state
    for (const auto &packet : packets)
    {
        const std::vector<uint8_t> &data = packet.data;

        // Basic packet size check (Ethernet header = 14 bytes)
        if (data.size() < 14)
            continue;

        // Check if it's IPv4
        uint16_t eth_type = (data[12] << 8) | data[13];
        if (eth_type != 0x0800)
            continue;

        // Ensure we have minimum IP + TCP headers
        if (data.size() < 34)
            continue;

        // Check if it's TCP
        uint8_t protocol = data[23];
        if (protocol != 6)
            continue; // Not TCP

        // Get IPv4 header length and ensure we have complete TCP header
        uint8_t ihl = (data[14] & 0x0F) * 4; // IPv4 header length in bytes
        if (data.size() < 14 + ihl + 20)
            continue; // Ethernet + IP + minimum TCP

        // Get TCP flags (14th byte of TCP header, offset 13 from TCP start)
        uint8_t tcp_flags = data[14 + ihl + 13];

        // Check for specific flags
        if (tcp_flags & 0x02)
            has_syn = true; // SYN flag
        if (tcp_flags & 0x10)
            has_ack = true; // ACK flag
        if (tcp_flags & 0x01)
            has_fin = true; // FIN flag
        if (tcp_flags & 0x04)
            has_rst = true; // RST flag

        // Check for SYN-ACK (both SYN and ACK flags set)
        if ((tcp_flags & 0x12) == 0x12)
            has_syn_ack = true;
    }

    // Flow is complete if:
    // 1. FIN or RST flag is present (proper termination)
    if (has_fin || has_rst)
    {
        return true;
    }

    // 2. Incomplete handshake detected (SYN flood pattern)
    // If we have SYN and SYN-ACK but no final ACK, and enough time has passed,
    // consider it a failed/incomplete connection
    if (has_syn && has_syn_ack && !has_ack && packets.size() >= 2)
    {
        // For SYN flood detection, we can be more aggressive about timing out
        // incomplete handshakes. This will be handled by the idle timeout in
        // the main completion logic, but we can flag it here too.
        uint64_t time_diff = packets.back().timestamp - packets.front().timestamp;
        if (time_diff > 5000000ULL) // 5 seconds for incomplete handshake
        {
            return true;
        }
    }

    return false;
}

bool check_icmp_flow_completion(const std::vector<Packet> &packets)
{
    // For ICMP, check if we have a request-response pair
    if (packets.size() < 2)
        return false;

    bool has_request = false;
    bool has_response = false;

    for (const auto &packet : packets)
    {
        const std::vector<uint8_t> &data = packet.data;

        // Basic packet size check
        if (data.size() < 14)
            continue;

        // Check if it's IPv4
        uint16_t eth_type = (data[12] << 8) | data[13];
        if (eth_type != 0x0800)
            continue;

        // Ensure we have IP + ICMP headers
        if (data.size() < 34)
            continue;

        // Check if it's ICMP
        uint8_t protocol = data[23];
        if (protocol != 1)
            continue; // Not ICMP

        // Get ICMP type (first byte of ICMP header)
        uint8_t ihl = (data[14] & 0x0F) * 4; // IPv4 header length
        if (data.size() < 14 + ihl + 8)
            continue; // Need ICMP header

        uint8_t icmp_type = data[14 + ihl];

        // Check for Echo Request (8) and Echo Reply (0)
        if (icmp_type == 8)
            has_request = true;
        if (icmp_type == 0)
            has_response = true;

        // Other ICMP types can also indicate completion
        // Destination Unreachable (3), Time Exceeded (11), etc.
        if (icmp_type == 3 || icmp_type == 11 || icmp_type == 12)
        {
            return true; // Error responses complete the flow
        }
    }

    // Complete if we have both request and response
    return has_request && has_response;
}

bool check_udp_flow_timeout(uint64_t current_time, uint64_t flow_start_time, uint64_t last_activity)
{
    // UDP has no connection state, rely on timeouts
    uint64_t flow_duration = current_time - flow_start_time;
    uint64_t idle_time = current_time - last_activity;

    // UDP flows timeout faster than TCP for most cases
    const uint64_t UDP_ACTIVE_TIMEOUT = 600000000ULL; // 10 minutes
    const uint64_t UDP_IDLE_TIMEOUT = 30000000ULL;    // 30 seconds

    return (flow_duration > UDP_ACTIVE_TIMEOUT || idle_time > UDP_IDLE_TIMEOUT);
}

bool is_flow_complete(const FlowKey &key, const std::vector<Packet> &packets, uint64_t current_time,
                      const std::map<FlowKey, uint64_t> &flow_start_time,
                      const std::map<FlowKey, uint64_t> &flow_last_activity)
{

    // Safety check: if flow has too many packets, force completion to prevent memory issues
    if (packets.size() > MAX_PACKETS_PER_FLOW)
    {
        return true;
    }

    // Get timing information
    auto start_it = flow_start_time.find(key);
    auto activity_it = flow_last_activity.find(key);

    if (start_it == flow_start_time.end() || activity_it == flow_last_activity.end())
    {
        // If we can't find timing info, force completion for safety
        return true;
    }

    uint64_t flow_duration = current_time - start_it->second;
    uint64_t idle_time = current_time - activity_it->second;

    // Protocol-specific completion logic
    switch (key.protocol)
    {
    case 6: // TCP
        // Check for proper TCP termination first
        if (check_tcp_flow_completion(packets))
        {
            return true;
        }
        // Fall back to timeout-based completion
        return (flow_duration > FLOW_ACTIVE_TIMEOUT || idle_time > FLOW_IDLE_TIMEOUT);

    case 17: // UDP
        // UDP has no connection state, use timeout-based completion with UDP-specific timeouts
        return check_udp_flow_timeout(current_time, start_it->second, activity_it->second);

    case 1: // ICMP
        // Check for ICMP request-response completion
        if (check_icmp_flow_completion(packets))
        {
            return true;
        }
        // ICMP flows should timeout much faster
        return (flow_duration > ICMP_ACTIVE_TIMEOUT || idle_time > ICMP_IDLE_TIMEOUT);

    default: // Other protocols (ARP, etc.)
        // For unknown protocols, use conservative timeouts
        const uint64_t OTHER_ACTIVE_TIMEOUT = 60000000ULL; // 1 minute
        const uint64_t OTHER_IDLE_TIMEOUT = 5000000ULL;    // 5 seconds
        return (flow_duration > OTHER_ACTIVE_TIMEOUT || idle_time > OTHER_IDLE_TIMEOUT);
    }
}

// Flow tracking methods for GroupStats class
void State::GroupStats::increment_processed_flows_count(std::string_view mac, int increment_by)
{
    std::unique_lock<std::shared_mutex> lock(mtx);
    processed_flows_device[std::string(mac)] += increment_by;
    total_processed_flows_count += increment_by;
}

int State::GroupStats::get_processed_flows_count(std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(mtx);
    auto it = processed_flows_device.find(std::string(mac));
    return (it != processed_flows_device.end()) ? it->second : 0;
}

std::unordered_map<std::string, int> State::GroupStats::get_processed_flows_counts() const
{
    std::shared_lock<std::shared_mutex> lock(mtx);
    return processed_flows_device;
}

void State::GroupStats::update_last_flow_info(std::string_view mac, uint64_t timestamp, int current_count)
{
    std::unique_lock<std::shared_mutex> lock(mtx);
    last_flow_timestamps[std::string(mac)] = timestamp;
    last_flow_counts[std::string(mac)] = current_count;
    last_flow_times[std::string(mac)] = timestamp;
}

std::tuple<uint64_t, uint64_t> State::GroupStats::get_last_flow_info(std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(mtx);
    auto ts_it = last_flow_timestamps.find(std::string(mac));
    auto count_it = last_flow_counts.find(std::string(mac));

    uint64_t timestamp = (ts_it != last_flow_timestamps.end()) ? ts_it->second : 0;
    uint64_t count = (count_it != last_flow_counts.end()) ? count_it->second : 0;

    return std::make_tuple(timestamp, count);
}

void State::increment_processed_flows_device(int16_t g, std::string_view mac, int increment_by)
{
    GroupStats &S = get_or_create_group(g);
    S.increment_processed_flows_count(mac, increment_by);
}

std::optional<int> State::get_processed_flows_device(int16_t g, std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return std::nullopt;
    }
    return it->second.get_processed_flows_count(mac);
}

std::optional<std::unordered_map<std::string, int>> State::get_processed_flows_per_device(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return std::nullopt;
    }
    return it->second.get_processed_flows_counts();
}

void State::update_last_flow_info(int16_t group_id, std::string_view mac, uint64_t timestamp, int current_count)
{
    GroupStats &group = get_or_create_group(group_id);
    group.update_last_flow_info(mac, timestamp, current_count);
}

std::optional<long double> State::get_flow_rate_device(int16_t g, std::string_view mac) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return std::nullopt;
    }

    std::shared_lock<std::shared_mutex> group_lock(it->second.mtx);
    auto rate_it = it->second.flow_rate_device.find(std::string(mac));
    if (rate_it != it->second.flow_rate_device.end())
    {
        return rate_it->second;
    }
    return std::nullopt;
}

void State::set_flow_rate_device(int16_t g, std::string_view mac, long double new_rate)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);
    S.flow_rate_device[std::string(mac)] = new_rate;
}

std::optional<unsigned long long int> State::get_total_processed_flows_count(int16_t g) const
{
    std::shared_lock<std::shared_mutex> lock(groups_mtx_);
    auto it = groups_.find(g);
    if (it == groups_.end())
    {
        return std::nullopt;
    }

    std::shared_lock<std::shared_mutex> group_lock(it->second.mtx);
    return it->second.total_processed_flows_count;
}

void State::set_total_processed_flows_count(int16_t g, unsigned long long int new_count)
{
    GroupStats &S = get_or_create_group(g);
    std::unique_lock<std::shared_mutex> lock(S.mtx);
    S.total_processed_flows_count = new_count;
}