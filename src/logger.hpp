#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <sstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <mutex>

// Log levels
enum class LogLevel
{
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    FATAL = 4
};

// Structured Logger Class
class Logger
{
private:
    static LogLevel current_level_;
    static std::mutex log_mutex_;
    static bool colors_enabled_;
    static bool timestamps_enabled_;

    static std::string get_timestamp();
    static std::string get_level_string(LogLevel level);
    static std::string get_thread_info(const std::string &thread_name = "");

public:
    static void set_level(LogLevel level);
    static void enable_colors(bool enabled);
    static void enable_timestamps(bool enabled);

    static void log(LogLevel level, const std::string &message,
                    const std::string &thread_name = "",
                    const std::string &component = "");

    // Convenience methods
    static void debug(const std::string &message, const std::string &thread_name = "", const std::string &component = "");
    static void info(const std::string &message, const std::string &thread_name = "", const std::string &component = "");
    static void warning(const std::string &message, const std::string &thread_name = "", const std::string &component = "");
    static void error(const std::string &message, const std::string &thread_name = "", const std::string &component = "");
    static void fatal(const std::string &message, const std::string &thread_name = "", const std::string &component = "");
};

// Thread-safe stream-like logging
class LogStream
{
private:
    LogLevel level_;
    std::string thread_name_;
    std::string component_;
    std::ostringstream stream_;

public:
    LogStream(LogLevel level, const std::string &thread_name = "", const std::string &component = "")
        : level_(level), thread_name_(thread_name), component_(component) {}

    template <typename T>
    LogStream &operator<<(const T &value)
    {
        stream_ << value;
        return *this;
    }

    ~LogStream()
    {
        Logger::log(level_, stream_.str(), thread_name_, component_);
    }
};

// Macros for easy logging with automatic thread naming
#define LOG_DEBUG(component, message) Logger::debug(message, "", component)
#define LOG_INFO(component, message) Logger::info(message, "", component)
#define LOG_WARNING(component, message) Logger::warning(message, "", component)
#define LOG_ERROR(component, message) Logger::error(message, "", component)
#define LOG_FATAL(component, message) Logger::fatal(message, "", component)

// Thread-specific logging macros
#define LOG_THREAD_DEBUG(thread, component, message) Logger::debug(message, thread, component)
#define LOG_THREAD_INFO(thread, component, message) Logger::info(message, thread, component)
#define LOG_THREAD_WARNING(thread, component, message) Logger::warning(message, thread, component)
#define LOG_THREAD_ERROR(thread, component, message) Logger::error(message, thread, component)
#define LOG_THREAD_FATAL(thread, component, message) Logger::fatal(message, thread, component)

// Stream-style logging
#define LOG_STREAM_DEBUG(component) LogStream(LogLevel::DEBUG, "", component)
#define LOG_STREAM_INFO(component) LogStream(LogLevel::INFO, "", component)
#define LOG_STREAM_WARNING(component) LogStream(LogLevel::WARNING, "", component)
#define LOG_STREAM_ERROR(component) LogStream(LogLevel::ERROR, "", component)

#endif // LOGGER_HPP