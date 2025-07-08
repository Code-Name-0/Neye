// src/neye_lib.hpp
#ifndef NEYE_LIB_HPP
#define NEYE_LIB_HPP

#include <pcap/pcap.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <cstdint>
#include <thread>
#include <atomic>
#include <map>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip> // for std::setw and std::setfill
#include <numeric> // for std::accumulate
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cmath>
#include <limits>
#include <cstring>
#include <net/ethernet.h>
#include <sys/stat.h> // For fchmod
#include <unistd.h>   // For getuid
#include <filesystem> // For std::filesystem
#include <functional> // For std::hash
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstdlib>
#include <string_view>
#include <optional>
#include <shared_mutex>
#include <sys/mman.h> // for shm_open, mmap (POSIX)
#include <fcntl.h>    // O_CREAT, O_RDWR
#include <cstring>    // for strerror
#include <cerrno>     // for errno
#include <regex>
#include <curl/curl.h>
#include <cstdlib>
#include <sys/stat.h> // for mkfifo
#include <unistd.h>   // for unlink
#include <string>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include "logger.hpp"

using json = nlohmann::json;

#ifndef PACKET_OFFSET
#define PACKET_OFFSET 56 // ? offset of fields to keep in captured packets in bytes
#endif

struct Device
{
    std::string name;
    std::string mac;
    std::string ip;
    int group;
};
class State
{
public:
    // ----------------------------------------
    // Per‑group statistics container
    // ----------------------------------------
    struct GroupStats
    {
        // For rate calculation:
        std::unordered_map<std::string, uint64_t> last_packet_counts;
        std::unordered_map<std::string, uint64_t> last_packet_timestamps;

        // ----------------------------------------
        // Packet Rate History Tracking System
        // ----------------------------------------
        struct RateHistoryEntry
        {
            uint64_t timestamp;    // microseconds since epoch
            long double rate;      // packets per second
            uint64_t packet_count; // total packets at this point
        };

        // Configurable history parameters
        static constexpr size_t MAX_HISTORY_ENTRIES = 3600;      // 1 hour at 1-second intervals
        static constexpr size_t RECENT_HISTORY_SIZE = 300;       // 5 minutes for recent analysis
        static constexpr uint64_t HISTORY_INTERVAL_US = 1000000; // 1 second in microseconds

        // Per-device rate history (circular buffers)
        std::unordered_map<std::string, std::vector<RateHistoryEntry>> rate_history_device;
        std::unordered_map<std::string, size_t> history_write_index; // Current write position

        // Group-level aggregated history
        std::vector<RateHistoryEntry> group_rate_history;
        size_t group_history_write_index = 0;

        // History management methods
        void add_rate_history_entry(std::string_view mac, long double rate, uint64_t timestamp, uint64_t packet_count);
        void update_group_rate_history(uint64_t timestamp);
        std::vector<RateHistoryEntry> get_rate_history(std::string_view mac, size_t max_entries = MAX_HISTORY_ENTRIES) const;
        std::vector<RateHistoryEntry> get_recent_rate_history(std::string_view mac, uint64_t time_window_us = 300000000) const; // 5 minutes
        std::vector<RateHistoryEntry> get_group_rate_history(size_t max_entries = MAX_HISTORY_ENTRIES) const;

        // Statistical analysis methods
        struct RateStatistics
        {
            long double avg_rate;
            long double min_rate;
            long double max_rate;
            long double std_deviation;
            size_t sample_count;
            uint64_t time_span_us;
        };

        RateStatistics calculate_rate_statistics(std::string_view mac, uint64_t time_window_us = 300000000) const;
        RateStatistics calculate_group_rate_statistics(uint64_t time_window_us = 300000000) const;

        // Original members, but now per‑group:
        unsigned long long int total_flows_count;            // !
        unsigned long long int total_packets_count;          // !
        std::unordered_map<int, double> average_window_size; // ! index 0 is the count of windows (how many windows were calculated)
        std::unordered_map<int, double> avg_packet_rate;
        std::unordered_map<std::string, long double> packet_rate_device;

        // Flow tracking members (NEW)
        unsigned long long int total_processed_flows_count;             // Total flows processed
        std::unordered_map<std::string, int> processed_flows_device;    // Flows processed per device MAC
        std::unordered_map<std::string, uint64_t> last_flow_times;      // Last flow completion time per device
        std::unordered_map<std::string, long double> flow_rate_device;  // Flow completion rate per device
        std::unordered_map<std::string, uint64_t> last_flow_counts;     // Last flow count per device for rate calculation
        std::unordered_map<std::string, uint64_t> last_flow_timestamps; // Last flow timestamp per device for rate calculation

        // Sharded packet‑count map<mac, count>
        static const int NUM_SHARDS = 10;
        std::array<std::unordered_map<std::string, int>, NUM_SHARDS> packet_count_shards;
        mutable std::array<std::shared_mutex, NUM_SHARDS> shard_mutexes;

        // Mutex to protect non‑shard fields inside this group
        mutable std::shared_mutex mtx;

        // Constructor
        GroupStats();

        // Determine which shard index for a given MAC
        int get_shard_index(std::string_view mac) const;

        // Increment packet count for one MAC under shard lock
        void increment_packet_count(std::string_view mac, int increment_by);

        // Retrieve merged map<mac, count> across all shards (thread‑safe)
        std::unordered_map<std::string, int> get_packet_counts() const;

        // Update last seen values for a MAC (thread-safe)
        void update_last_packet_info(std::string_view mac, uint64_t timestamp, int current_count);

        // Fetch last values (thread-safe)
        std::tuple<uint64_t, uint64_t> get_last_packet_info(std::string_view mac) const;

        // Flow tracking methods (NEW)
        void increment_processed_flows_count(std::string_view mac, int increment_by);
        int get_processed_flows_count(std::string_view mac) const;
        std::unordered_map<std::string, int> get_processed_flows_counts() const;
        void update_last_flow_info(std::string_view mac, uint64_t timestamp, int current_count);
        std::tuple<uint64_t, uint64_t> get_last_flow_info(std::string_view mac) const;

        std::unordered_map<std::string, uint64_t> last_packet_times;
    };

    std::unordered_map<int16_t, GroupStats> groups_;

    std::vector<Device> monitored_devices; // ! set it in the group devices function
    State();
    ~State();
    void update_last_packet_info(int16_t group_id, std::string_view mac, uint64_t timestamp, int current_count);
    json get_stats_as_json() const;
    void dashboard_live_stats() const;
    std::vector<int16_t> get_all_group_ids() const;

    // ——— Per‑group setters ———

    // Set total_packets_count for group g
    void set_total_packets_count(int16_t g, unsigned long long int new_count);

    // Set total_flows_count for group g
    void set_total_flows_count(int16_t g, int16_t new_count);

    // Set average_window_size for group g
    void set_average_window_size(int16_t g, int new_window_size);

    // Set packet_rate for group g
    void set_avg_packet_rate(int16_t g, double rate);

    // Set packet_rate_device[mac] = new_rate for group g
    void set_packet_rate_device(int16_t g, std::string_view mac, long double new_rate);

    void set_monitored_devices(const std::vector<Device> &new_devices);

    // Overwrite entire packet_count_per_device map for group g
    void set_packet_count_per_device(int16_t g, const std::unordered_map<std::string, int> &new_counts);

    // ——— Per‑group getters ———

    std::optional<long double> get_packet_rate(int16_t g) const;
    std::optional<unsigned long long int> get_total_packets_count(int16_t g) const;
    std::optional<unsigned long long int> get_total_flows_count(int16_t g) const;
    std::optional<double> get_average_window_size(int16_t g) const;
    std::optional<long double> get_packet_rate_device(int16_t g, std::string_view mac) const;
    std::vector<Device> get_monitored_devices() const;
    std::optional<std::unordered_map<std::string, int>> get_packet_count_per_device(int16_t g) const;

    // ——— Rate History Methods ———

    // Add rate history entry for a specific device
    void add_device_rate_history(int16_t g, std::string_view mac, long double rate, uint64_t timestamp, uint64_t packet_count);

    // Update group-level rate history
    void update_group_rate_history(int16_t g, uint64_t timestamp);

    // Get rate history for a specific device
    std::vector<GroupStats::RateHistoryEntry> get_device_rate_history(int16_t g, std::string_view mac, size_t max_entries = 3600) const;

    // Get recent rate history (default: last 5 minutes)
    std::vector<GroupStats::RateHistoryEntry> get_recent_device_rate_history(int16_t g, std::string_view mac, uint64_t time_window_us = 300000000) const;

    // Get group rate history
    std::vector<GroupStats::RateHistoryEntry> get_group_rate_history(int16_t g, size_t max_entries = 3600) const;

    // Get statistical analysis of device rates
    std::optional<GroupStats::RateStatistics> get_device_rate_statistics(int16_t g, std::string_view mac, uint64_t time_window_us = 300000000) const;

    // Get statistical analysis of group rates
    std::optional<GroupStats::RateStatistics> get_group_rate_statistics(int16_t g, uint64_t time_window_us = 300000000) const;

    // Utility to increment packet count for a specific MAC in group g
    void increment_packet_count_device(int16_t g, std::string_view mac, int increment_by);
    void increment_flow_count_group(int16_t g, int increment_by);
    // Check if a device (by MAC) is in monitored_devices for group g
    bool check_if_dev_monitored(std::string_view mac) const;

    std::optional<std::tuple<uint64_t, uint64_t>> get_last_packet_info(int16_t g, std::string_view mac) const;
    // Print numeric summary for group g
    void print_numeric(int16_t g) const;

    std::string get_all_details(bool print) const;

    // Print rate history summary for debugging/monitoring
    void print_rate_history_summary(int16_t g) const;

    std::optional<uint64_t> get_last_packet_time(int16_t group_id, std::string_view mac) const;
    // void update_last_packet_info(int16_t group_id, const std::string &mac, uint64_t timestamp, int new_count);

    // ——— Flow Tracking Methods (NEW) ———

    // Increment processed flows for a device in a group
    void increment_processed_flows_device(int16_t g, std::string_view mac, int increment_by);

    // Get processed flows count for a device
    std::optional<int> get_processed_flows_device(int16_t g, std::string_view mac) const;

    // Get all processed flows counts for a group
    std::optional<std::unordered_map<std::string, int>> get_processed_flows_per_device(int16_t g) const;

    // Update flow completion info
    void update_last_flow_info(int16_t group_id, std::string_view mac, uint64_t timestamp, int current_count);

    // Get flow rate for a device
    std::optional<long double> get_flow_rate_device(int16_t g, std::string_view mac) const;

    // Set flow rate for a device
    void set_flow_rate_device(int16_t g, std::string_view mac, long double new_rate);

    // Get total processed flows for a group
    std::optional<unsigned long long int> get_total_processed_flows_count(int16_t g) const;

    // Set total processed flows for a group
    void set_total_processed_flows_count(int16_t g, unsigned long long int new_count);

private:
    // ----------------------------------------
    // Top‑level container of all group stats
    // ----------------------------------------

    mutable std::shared_mutex groups_mtx_;
    mutable std::shared_mutex general_mtx;

    // Helper to find or create the GroupStats for a given group_id
    GroupStats &get_or_create_group(int16_t group_id);
};

struct Packet
{
    std::vector<uint8_t> data;
    uint64_t timestamp;
};

struct packet_handler_args
{
    int group_id;
    State &state;
    pcap_t *handle;

    packet_handler_args(int gid, State &s, pcap_t *h)
        : group_id(gid), state(s), handle(h) {}
};

struct FlowKey
{
    uint8_t protocol;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;

    bool operator<(const FlowKey &other) const;
    bool operator==(const FlowKey &other) const;
};

namespace std
{
    template <>
    struct hash<FlowKey>
    {
        size_t operator()(const FlowKey &key) const;
    };
}

struct FlowFeatures
{
    bool is_arp = false;
    bool is_llc = false;
    bool is_ipv = false;
    uint64_t byte_count = 0;
    // uint64_t start_time = 0;
    // uint64_t last_seen = 0;
    // std::vector<uint32_t> packet_sizes;
    // std::vector<uint64_t> packet_times;
    // std::vector<uint32_t> header_lengths;
    uint32_t fin_count = 0;
    uint32_t syn_count = 0;
    uint32_t rst_count = 0;
    uint32_t psh_count = 0;
    uint32_t ack_count = 0;
    uint32_t ece_count = 0;
    uint32_t cwr_count = 0;

    double Header_Length = 0.0;
    double Protocol_Type;
    double Duration = 0.0;
    double Rate = 0.0;
    double Srate = 0.0;
    double fin_flag_number = 0.0;
    double syn_flag_number = 0.0;
    double rst_flag_number = 0.0;
    double psh_flag_number = 0.0;
    double ack_flag_number = 0.0;
    double ece_flag_number = 0.0;
    double cwr_flag_number = 0.0;
    double HTTP = 0.0;
    double HTTPS = 0.0;
    double DNS = 0.0;
    double MQTT = 0.0;
    double Telnet = 0.0;
    double SMTP = 0.0;
    double SSH = 0.0;
    double IRC = 0.0;
    double TCP = 0.0;
    double UDP = 0.0;
    double DHCP = 0.0;
    double ARP = 0.0;
    double ICMP = 0.0;
    double IGMP = 0.0;
    double IPv = 0.0;
    double LLC = 0.0;
    double Tot_sum = 0.0;
    double Min = 0.0;
    double Max = 0.0;
    double AVG = 0.0;
    double Std = 0.0;
    double Tot_size = 0.0;
    double IAT = 0.0;
    double IAT_Std = 0.0;
    uint32_t Number = 0;
    double Magnitue = 0.0;
    double Radius = 0.0;
    double Covariance = 0.0;
    double Variance = 0.0;
    double Weight = 0.0;
};

class FlowFeaturesQueue
{
private:
    std::queue<FlowFeatures> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    size_t max_size_ = 10000;

public:
    void push(FlowFeatures flow_features);
    FlowFeatures pop();
    bool try_pop(FlowFeatures &flow_features, int timeout_ms);
    void clear();
    int get_size();
};

class FlowPacketsQueue
{
private:
    std::queue<std::vector<Packet>> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    size_t max_size_ = 10000;

public:
    void push(std::vector<Packet> packet);
    std::vector<Packet> pop();
    bool try_pop(std::vector<Packet> &FlowPackets, int timeout_ms);
    void clear();
    int get_size();
};

struct FeaturesSHMWrapper
{
    volatile uint8_t writing;
    volatile uint8_t consumed;
    FlowFeatures features;
};

class PacketQueue
{
private:
    std::queue<Packet> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    size_t max_size_ = 10000;

public:
    void push(Packet packet);
    Packet pop();
    bool try_pop(Packet &packet, int timeout_ms);
    void clear();
    int get_size();
};

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

std::string trim(const std::string &str);

FlowKey normalize_flow_key(uint8_t protocol, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

void capture_thread(int group_id, const std::string &device, const std::string &filter_exp, State &state);

void feature_extraction_thread(int group_id, State &state);

std::string arp_lookup(const std::string &mac, const std::string &interface);

std::string get_ip_from_mac(const std::string &mac, const std::string &interface, bool &looked);

std::vector<std::string> group_devices(const std::string &json_file, int &K, const std::string &interface, State &global_state);

void IP_sweep(const std::string &interface);

void cleanARPTable();

void logger_thread(State &state);

// ——— Interactive Command Interface ———
void interactive_command_thread(State &state);
void display_help_menu();
void display_rate_history_summary(State &state, int group_id = -1);
void display_device_rate_details(State &state, int group_id, const std::string &mac);
void display_recent_rate_trends(State &state, int group_id = -1, int seconds = 60);
void export_rate_history_csv(State &state, int group_id = -1, const std::string &filename = "rate_history_export.csv");
void display_group_overview(State &state);

// ——— Periodic History Saving ———
void history_saving_thread(State &state);
void save_rate_history_to_file(State &state, const std::string &base_filename = "");

// ——— Interactive Helper Functions ———
std::string process_interactive_command(State &state, const std::string &command);
void interactive_console_mode(State &state);
std::string generate_group_overview(State &state);
std::string generate_device_rate_details(State &state, int group_id, const std::string &mac);
std::string generate_recent_rate_trends(State &state, int group_id = -1, int seconds = 60);
std::string generate_export_csv(State &state, int group_id = -1, const std::string &filename = "rate_history_export.csv");

bool ping_host(const std::string &ip, const std::string &interface);
void rate_calculation_thread(int group_id, State &state);
void flow_aggregation_thread(int group_id, State &state);
void inference_thread(int number_of_groups, State &state);

void create_shm(const std::string &shm_names, const std::string &filename);
// void write_to_shm(const std::string &shm_name, const FeaturesSHMWrapper &payload);
uint16_t rate_based_sizing(std::string, long double rate);

extern std::map<int, PacketQueue> packets_queues;
extern std::map<int, FlowPacketsQueue> flows_queues;
extern std::map<int, FlowFeaturesQueue> features_queues;
extern size_t SHM_SIZE;

extern std::vector<std::vector<Device>> groups;
extern State global_state;

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
void load_env_file(const std::string &filename);

bool is_flow_complete(const FlowKey &key, const std::vector<Packet> &packets, uint64_t current_time,
                      const std::map<FlowKey, uint64_t> &flow_start_time,
                      const std::map<FlowKey, uint64_t> &flow_last_activity);
#endif